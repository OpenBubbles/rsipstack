use super::custom_tcp::CustomTcpConnection;
use super::stream::StreamConnection;
use super::tls::{TlsConfig, TlsConnection};
use super::websocket::WebSocketConnection;
use super::{connection::TransportSender, sip_addr::SipAddr, tcp::TcpConnection, SipConnection};
use crate::resolver::SipResolver;
use crate::sip::{Host, HostWithPort, Transport};
use crate::transaction::key::TransactionKey;
use crate::transport::connection::TransportReceiver;
use crate::{transport::TransportEvent, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::select;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Default of [`TransportLayer::large_message_threshold`]: RFC 3261 §18.1.1 sends a request
/// larger than 1300 bytes (path MTU unknown) over a congestion-controlled transport.
pub const DEFAULT_LARGE_MESSAGE_THRESHOLD: usize = 1300;

/// Opens the TCP streams [`TransportLayer::reliable_connection_for`] needs, through whatever
/// network stack the caller uses (an ePDG tunnel's, say). Blocking: it is called on tokio's
/// blocking pool, and it bounds its own connect time. Closures
/// `Fn(SocketAddr) -> io::Result<Box<dyn TcpStreamLike>>` implement it.
pub trait StreamConnector: Send + Sync {
    fn connect(&self, remote: SocketAddr) -> std::io::Result<Box<dyn epdg::TcpStreamLike>>;
}

impl<F> StreamConnector for F
where
    F: Fn(SocketAddr) -> std::io::Result<Box<dyn epdg::TcpStreamLike>> + Send + Sync,
{
    fn connect(&self, remote: SocketAddr) -> std::io::Result<Box<dyn epdg::TcpStreamLike>> {
        (self)(remote)
    }
}

#[async_trait]
pub trait DomainResolver: Send + Sync {
    async fn resolve(&self, target: &SipAddr) -> Result<SipAddr>;
}

#[async_trait]
pub trait TransportWhitelist: Send + Sync {
    /// Return true to accept the packet/connection for the given peer IP.
    async fn allow(&self, ip: IpAddr) -> bool;
}

#[async_trait]
impl<F, Fut> TransportWhitelist for F
where
    F: Send + Sync + Fn(IpAddr) -> Fut,
    Fut: std::future::Future<Output = bool> + Send,
{
    async fn allow(&self, ip: IpAddr) -> bool {
        (self)(ip).await
    }
}

pub(crate) type TransportWhitelistRef = Arc<dyn TransportWhitelist>;
pub struct DefaultDomainResolver {
    resolver: SipResolver,
}

impl DefaultDomainResolver {
    pub fn new() -> Self {
        Self {
            resolver: SipResolver::default(),
        }
    }

    pub async fn resolve_with_lookup(&self, target: &SipAddr) -> Result<SipAddr> {
        let domain = match &target.addr.host {
            Host::Domain(domain) => domain,
            _ => {
                return Err(crate::Error::DnsResolutionError(target.addr.to_string()));
            }
        };

        // RFC 5626: .invalid domains are placeholders for temporary contacts
        // and must not be resolved via DNS
        if domain.0 == "invalid" || domain.0.ends_with(".invalid") {
            return Err(crate::Error::DnsResolutionError(format!(
                "cannot resolve .invalid domain: {}",
                domain
            )));
        }

        // Use new SipResolver
        let secure = matches!(
            target.r#type,
            Some(Transport::Tls) | Some(Transport::Wss) | Some(Transport::TlsSctp)
        );

        let addrs = self
            .resolver
            .lookup(domain, target.addr.port, target.r#type, secure)
            .await
            .map_err(|e| crate::Error::DnsResolutionError(format!("{}: {}", target.addr, e)))?;

        if let Some(first) = addrs.first() {
            return Ok(SipAddr {
                r#type: Some(first.transport),
                addr: HostWithPort {
                    host: Host::IpAddr(first.addr.ip()),
                    port: Some(first.addr.port().into()),
                },
            });
        }

        Err(crate::Error::DnsResolutionError(target.addr.to_string()))
    }
}

impl Default for DefaultDomainResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DomainResolver for DefaultDomainResolver {
    async fn resolve(&self, target: &SipAddr) -> Result<SipAddr> {
        return self.resolve_with_lookup(target).await;
    }
}

pub struct TransportLayerInner {
    pub(crate) cancel_token: CancellationToken,
    listens: Arc<RwLock<Vec<SipConnection>>>, // listening transports
    connections: Arc<DashMap<SipAddr, SipConnection>>, // outbound/inbound connections
    pub(crate) transport_tx: TransportSender,
    pub(crate) transport_rx: Mutex<Option<TransportReceiver>>,
    pub domain_resolver: Box<dyn DomainResolver>,
    whitelist: RwLock<Option<TransportWhitelistRef>>,
    tls_config: RwLock<Option<TlsConfig>>,
    ws_path: RwLock<Option<String>>,
    /// See [`TransportLayer::large_message_threshold`].
    large_message_threshold: AtomicUsize,
    /// See [`TransportLayer::set_stream_connector`].
    stream_connector: RwLock<Option<Arc<dyn StreamConnector>>>,
    /// Held while [`TransportLayer::reliable_connection_for`] looks for or opens a
    /// connection, so requests that need one at the same time share it.
    stream_connecting: tokio::sync::Mutex<()>,
    /// `serve_listens` has run: listeners added from now on are served when added
    /// (see [`TransportLayer::add_listener`]). Read and written under the `listens` lock.
    serving_listens: AtomicBool,
}
pub(crate) type TransportLayerInnerRef = Arc<TransportLayerInner>;

#[derive(Clone)]
pub struct TransportLayer {
    pub outbound: Option<SipAddr>,
    pub inner: TransportLayerInnerRef,
}

impl TransportLayer {
    pub fn new_with_domain_resolver(
        cancel_token: CancellationToken,
        domain_resolver: Box<dyn DomainResolver>,
    ) -> Self {
        let (transport_tx, transport_rx) = mpsc::unbounded_channel();
        let inner = TransportLayerInner {
            cancel_token,
            listens: Arc::new(RwLock::new(Vec::new())),
            connections: Arc::new(DashMap::new()),
            transport_tx,
            transport_rx: Mutex::new(Some(transport_rx)),
            domain_resolver,
            whitelist: RwLock::new(None),
            tls_config: RwLock::new(None),
            ws_path: RwLock::new(None),
            large_message_threshold: AtomicUsize::new(DEFAULT_LARGE_MESSAGE_THRESHOLD),
            stream_connector: RwLock::new(None),
            stream_connecting: tokio::sync::Mutex::new(()),
            serving_listens: AtomicBool::new(false),
        };
        Self {
            outbound: None,
            inner: Arc::new(inner),
        }
    }

    pub fn new(cancel_token: CancellationToken) -> Self {
        let domain_resolver = Box::new(DefaultDomainResolver::default());
        Self::new_with_domain_resolver(cancel_token, domain_resolver)
    }

    /// Register a listening transport. It is served when [`serve_listens`](Self::serve_listens)
    /// runs (the endpoint does that once, when it starts serving); one added after that is
    /// listed but never served — use [`add_listener`](Self::add_listener) then.
    pub fn add_transport(&self, transport: SipConnection) {
        self.inner.add_listener(transport)
    }

    /// Register a listener (e.g. a [`CustomTcpListenerConnection`]) and serve it: at once
    /// when this transport layer is already serving its listeners (`serve_listens` has run),
    /// otherwise when `serve_listens` runs — exactly once either way. Unlike
    /// [`add_transport`](Self::add_transport), it may be called while the endpoint is running.
    ///
    /// [`CustomTcpListenerConnection`]: super::CustomTcpListenerConnection
    pub fn add_listener(&self, listener: SipConnection) {
        let serve_now = {
            let mut listens = self.inner.listens.write();
            listens.push(listener.clone());
            self.inner.serving_listens.load(Ordering::SeqCst)
        };
        if serve_now {
            let inner = self.inner.clone();
            tokio::spawn(async move {
                let addr = listener.get_addr().clone();
                if let Err(e) = TransportLayerInner::serve_listener(inner, listener).await {
                    warn!(error = ?e, %addr, "Failed to serve listener");
                }
            });
        }
    }

    /// Size in bytes above which a request that would go over an unreliable transport (UDP)
    /// goes over TCP instead (RFC 3261 §18.1.1), when a [`StreamConnector`] is set. Default
    /// [`DEFAULT_LARGE_MESSAGE_THRESHOLD`] (1300); `usize::MAX` turns the switch off.
    pub fn large_message_threshold(&self) -> usize {
        self.inner.large_message_threshold.load(Ordering::Relaxed)
    }

    /// Set [`large_message_threshold`](Self::large_message_threshold).
    pub fn set_large_message_threshold(&self, bytes: usize) {
        self.inner
            .large_message_threshold
            .store(bytes, Ordering::Relaxed);
    }

    /// Set the connector that opens TCP connections for requests above
    /// [`large_message_threshold`](Self::large_message_threshold) (see
    /// [`reliable_connection_for`](Self::reliable_connection_for)). Without one, every request
    /// goes over the connection the lookup chose, whatever its size.
    pub fn set_stream_connector<C>(&self, connector: C)
    where
        C: StreamConnector + 'static,
    {
        *self.inner.stream_connector.write() = Some(Arc::new(connector));
    }

    /// Remove the stream connector: large requests stay on UDP again.
    pub fn clear_stream_connector(&self) {
        *self.inner.stream_connector.write() = None;
    }

    /// A reliable connection to `remote`'s address (RFC 3261 §18.1.1): the connection already
    /// keyed `TCP <remote address>` if there is one (and it has not ended), otherwise a new
    /// [`CustomTcpConnection`] over a stream from the
    /// [`StreamConnector`], added to the transport layer (and so served at once). `remote`
    /// must be an IP address (port 5060 when absent); its transport is ignored. Calls for the
    /// same moment are served one at a time, so they share one new connection. Errors when
    /// no connector is set or it fails — the caller then sends over UDP after all.
    pub async fn reliable_connection_for(&self, remote: &SipAddr) -> Result<SipConnection> {
        self.inner.reliable_connection_for(remote).await
    }

    pub fn del_transport(&self, addr: &SipAddr) {
        self.inner.del_listener(addr)
    }

    pub fn add_connection(&self, connection: SipConnection) {
        self.inner.add_connection(connection);
    }

    pub fn del_connection(&self, addr: &SipAddr) {
        self.inner.del_connection(addr)
    }

    pub async fn lookup(
        &self,
        target: &SipAddr,
        key: Option<&TransactionKey>,
    ) -> Result<(SipConnection, SipAddr)> {
        self.inner.lookup(target, self.outbound.as_ref(), key).await
    }

    pub async fn serve_listens(&self) -> Result<()> {
        let listens = {
            // Under the lock `add_listener` takes, so every listener is served exactly once:
            // either it is in this snapshot or `add_listener` sees the flag and serves it.
            let listens = self.inner.listens.read();
            self.inner.serving_listens.store(true, Ordering::SeqCst);
            listens.clone()
        };
        for transport in listens {
            let addr = transport.get_addr().clone();
            match TransportLayerInner::serve_listener(self.inner.clone(), transport).await {
                Ok(()) => {}
                Err(e) => {
                    warn!(error = ?e, %addr, "Failed to serve listener");
                }
            }
        }
        Ok(())
    }

    pub fn get_addrs(&self) -> Vec<SipAddr> {
        let mut addrs: Vec<SipAddr> = self
            .inner
            .listens
            .read()
            .iter()
            .map(|t| t.get_addr().to_owned())
            .collect();
        for conn in self.inner.connections.iter() {
            addrs.push(conn.get_addr().clone());
        }
        addrs
    }

    /// Set an async whitelist callback invoked on incoming packets/connections.
    pub fn set_whitelist<T>(&self, whitelist: T)
    where
        T: TransportWhitelist + 'static,
    {
        self.inner.set_whitelist(Some(Arc::new(whitelist)));
    }

    /// Remove the whitelist callback.
    pub fn clear_whitelist(&self) {
        self.inner.set_whitelist(None);
    }

    /// Set the TLS configuration used for future outbound TLS connections.
    pub fn set_tls_config(&self, tls_config: TlsConfig) {
        self.inner.set_tls_config(Some(tls_config));
    }

    /// Remove the TLS configuration used for future outbound TLS connections.
    pub fn clear_tls_config(&self) {
        self.inner.set_tls_config(None);
    }

    /// Set the WebSocket path used for future outbound WebSocket connections.
    /// Defaults to `/` if not set.
    pub fn set_ws_path(&self, path: impl Into<String>) {
        self.inner.set_ws_path(Some(path.into()));
    }

    /// Remove the WebSocket path override, reverting to default `/`.
    pub fn clear_ws_path(&self) {
        self.inner.set_ws_path(None);
    }
}

impl TransportLayerInner {
    pub(super) fn set_whitelist(&self, whitelist: Option<TransportWhitelistRef>) {
        *self.whitelist.write() = whitelist;
    }

    pub(crate) async fn is_whitelisted(&self, ip: IpAddr) -> bool {
        let whitelist = self.whitelist.read().clone();
        match whitelist {
            Some(whitelist) => whitelist.allow(ip).await,
            None => true,
        }
    }

    fn set_tls_config(&self, tls_config: Option<TlsConfig>) {
        *self.tls_config.write() = tls_config;
    }

    fn tls_config(&self) -> Option<TlsConfig> {
        self.tls_config.read().clone()
    }

    fn set_ws_path(&self, path: Option<String>) {
        *self.ws_path.write() = path;
    }

    fn ws_path(&self) -> Option<String> {
        self.ws_path.read().clone()
    }

    pub fn add_listener(&self, connection: SipConnection) {
        self.listens.write().push(connection);
    }

    pub(super) fn del_listener(&self, addr: &SipAddr) {
        self.listens.write().retain(|t| t.get_addr() != addr);
    }

    pub(super) fn add_connection(&self, connection: SipConnection) {
        if let Some(remote_addr) = connection.get_remote_addr().cloned() {
            debug!(%remote_addr, "add_connection");
            self.connections.insert(remote_addr, connection.clone());
            self.serve_connection(connection);
        } else {
            warn!(addr = %connection.get_addr(), "connection has no remote address");
        }
    }

    pub(super) fn del_connection(&self, addr: &SipAddr) {
        debug!(%addr, "del_connection");
        self.connections.remove(addr);
    }

    async fn reliable_connection_for(&self, remote: &SipAddr) -> Result<SipConnection> {
        let remote_addr = remote.get_socketaddr()?;
        let key = SipAddr {
            r#type: Some(Transport::Tcp),
            addr: remote_addr.into(),
        };
        // Two large requests at once must not each open a connection: the second would
        // replace the first in `connections`, leaving it open, unlisted and never reused.
        let _connecting = self.stream_connecting.lock().await;
        // The map guard must not be held across an await.
        let existing = self.connections.get(&key).map(|entry| entry.value().clone());
        match existing {
            // Ended, but its serve loop has not got round to forgetting it yet.
            Some(SipConnection::CustomTcp(ended)) if ended.is_closed() => {
                debug!(remote = %key, connection = %ended, "the listed TCP connection has ended; opening a new one");
                self.connections.remove_if(&key, |_, current| {
                    matches!(current, SipConnection::CustomTcp(current) if current.same_connection(&ended))
                });
            }
            Some(connection) => {
                debug!(remote = %key, %connection, "reusing the TCP connection");
                return Ok(connection);
            }
            None => {}
        }
        let connector = self.stream_connector.read().clone().ok_or_else(|| {
            crate::Error::TransportLayerError("no stream connector set".to_string(), key.clone())
        })?;
        let stream = tokio::task::spawn_blocking(move || connector.connect(remote_addr))
            .await
            .map_err(|e| {
                crate::Error::TransportLayerError(
                    format!("stream connector task failed: {e}"),
                    key.clone(),
                )
            })?
            .map_err(|e| {
                crate::Error::TransportLayerError(format!("TCP connect failed: {e}"), key.clone())
            })?;
        let connection = SipConnection::CustomTcp(CustomTcpConnection::new(
            stream,
            None,
            Some(self.cancel_token.child_token()),
        ));
        if connection.get_remote_addr() != Some(&key) {
            // Keyed by the stream's peer address, so a later lookup of `key` will not find it.
            warn!(remote = %key, %connection, "the stream connector connected to a different address");
        }
        info!(remote = %key, %connection, "opened a TCP connection");
        self.add_connection(connection.clone());
        Ok(connection)
    }

    async fn lookup(
        &self,
        destination: &SipAddr,
        outbound: Option<&SipAddr>,
        key: Option<&TransactionKey>,
    ) -> Result<(SipConnection, SipAddr)> {
        let target = outbound.unwrap_or(destination);
        let tls_config = self.tls_config();

        // Capture the original domain name before DNS resolution for TLS SNI
        let original_domain = match &target.addr.host {
            Host::Domain(domain) => Some(domain.to_string()),
            _ => None,
        };

        let target = if matches!(target.addr.host, Host::Domain(_)) {
            &self.domain_resolver.resolve(target).await?
        } else {
            target
        };

        debug!(?key, src = %destination, %target, "lookup target");
        if let Some(transport) = self.connections.get(target) {
            return Ok((transport.clone(), target.clone()));
        }
        if let Some(Transport::Tcp | Transport::Tls | Transport::Ws | Transport::Wss) =
            target.r#type
        {
            let sip_connection = match target.r#type {
                Some(Transport::Tcp) => {
                    let connection =
                        TcpConnection::connect(target, Some(self.cancel_token.child_token()))
                            .await?;
                    SipConnection::Tcp(connection)
                }
                Some(Transport::Tls) => {
                    // Build effective TLS config with SNI from the original domain
                    let mut effective_config = tls_config.clone().unwrap_or_default();
                    if effective_config.sni_hostname.is_none() {
                        effective_config.sni_hostname = original_domain;
                    }
                    let connection = TlsConnection::connect(
                        target,
                        Some(&effective_config),
                        None,
                        Some(self.cancel_token.child_token()),
                    )
                    .await?;
                    SipConnection::Tls(connection)
                }
                Some(Transport::Ws | Transport::Wss) => {
                    let ws_path = self.ws_path();
                    let connection = WebSocketConnection::connect_with_path(
                        target,
                        ws_path.as_deref(),
                        Some(self.cancel_token.child_token()),
                    )
                    .await?;
                    SipConnection::WebSocket(connection)
                }
                _ => {
                    return Err(crate::Error::TransportLayerError(
                        format!("unsupported transport type: {:?}", target.r#type),
                        target.to_owned(),
                    ));
                }
            };
            self.add_connection(sip_connection.clone());
            return Ok((sip_connection, target.clone()));
        }

        let listens = self.listens.read();
        let mut first_udp = None;
        for transport in listens.iter() {
            let addr = transport.get_addr();
            if addr.r#type == Some(Transport::Udp) && first_udp.is_none() {
                first_udp = Some(transport.clone());
            }
            if addr == target {
                return Ok((transport.clone(), target.clone()));
            }
        }
        if let Some(transport) = first_udp {
            return Ok((transport, target.clone()));
        }
        Err(crate::Error::TransportLayerError(
            format!("unsupported transport type: {:?}", target.r#type),
            target.to_owned(),
        ))
    }

    pub(super) async fn serve_listener(self: Arc<Self>, transport: SipConnection) -> Result<()> {
        let sender = self.transport_tx.clone();
        match transport {
            SipConnection::Udp(transport) => {
                let transport_layer_inner = self.clone();
                tokio::spawn(async move {
                    transport
                        .serve_loop_with_whitelist(sender, Some(transport_layer_inner))
                        .await
                });
                Ok(())
            }
            SipConnection::TcpListener(connection) => connection.serve_listener(self.clone()).await,
            SipConnection::CustomTcpListener(connection) => {
                connection.serve_listener(self.clone()).await
            }
            #[cfg(feature = "rustls")]
            SipConnection::TlsListener(connection) => connection.serve_listener(self.clone()).await,
            #[cfg(feature = "websocket")]
            SipConnection::WebSocketListener(connection) => {
                connection.serve_listener(self.clone()).await
            }

            _ => {
                warn!(
                    "serve_listener: unsupported transport type: {:?}",
                    transport.get_addr()
                );
                Ok(())
            }
        }
    }

    /// Serve `transport` on a task: `TransportEvent::New`, the serve loop, then — once the
    /// loop has ended — `close()` and `TransportEvent::Closed`. A [`SipConnection::CustomTcp`]
    /// is also forgotten before `Closed` (removed from the connections, but only while the
    /// entry under its remote address is still this very connection, not a replacement), so
    /// the next large request opens a new one. Other kinds stay listed until their owner
    /// calls `del_connection`, as before.
    pub fn serve_connection(&self, transport: SipConnection) {
        let sub_token = self.cancel_token.child_token();
        let sender_clone = self.transport_tx.clone();
        let connections = self.connections.clone();
        let remote_addr = transport
            .get_remote_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "-".to_string());
        info!(addr=%transport.get_addr(), remote=%remote_addr, "serve_connection: starting serve_loop");
        tokio::spawn(async move {
            match sender_clone.send(TransportEvent::New(transport.clone())) {
                Ok(()) => {
                    info!(addr=%transport.get_addr(), remote=%remote_addr, "serve_connection: New event sent");
                }
                Err(e) => {
                    warn!(addr=%transport.get_addr(), remote=%remote_addr, error = ?e, "Error sending new connection event");
                    return;
                }
            }
            select! {
                _ = sub_token.cancelled() => { }
                result = async {
                    transport.serve_loop(sender_clone.clone()).await
                } => {
                    if let Err(e) = result {
                        warn!(addr=%transport.get_addr(), remote=%remote_addr, error = %e, "serve_loop error");
                    }
                }
            }
            info!(addr=%transport.get_addr(), remote=%remote_addr, "transport serve_loop exited");
            if let SipConnection::CustomTcp(closed) = &transport {
                let remote = closed.get_remote_addr();
                let forgotten = connections.remove_if(remote, |_, current| {
                    matches!(current, SipConnection::CustomTcp(current) if current.same_connection(closed))
                });
                if forgotten.is_some() {
                    debug!(%remote, "forgot the closed TCP connection");
                }
            }
            transport.close().await.ok();
            sender_clone.send(TransportEvent::Closed(transport)).ok();
        });
    }
}
impl Drop for TransportLayer {
    fn drop(&mut self) {
        self.inner.cancel_token.cancel();
    }
}
#[cfg(test)]
mod tests {
    use crate::resolver::SipResolver;
    use crate::sip::uri::ParamsExt;
    use crate::sip::{Host, HostWithPort, Transport};
    use crate::{
        transport::{udp::UdpConnection, SipAddr},
        Result,
    };

    #[tokio::test]
    async fn test_lookup() -> Result<()> {
        let mut tl = super::TransportLayer::new(tokio_util::sync::CancellationToken::new());

        let first_uri = SipAddr {
            r#type: Some(Transport::Udp),
            addr: HostWithPort {
                host: Host::IpAddr("127.0.0.1".parse()?),
                port: Some(5060.into()),
            },
        };
        assert!(tl.lookup(&first_uri, None).await.is_err());
        let udp_peer = UdpConnection::create_connection(
            "127.0.0.1:0".parse()?,
            None,
            Some(tl.inner.cancel_token.child_token()),
        )
        .await?;
        let udp_peer_addr = udp_peer.get_addr().to_owned();
        tl.add_transport(udp_peer.into());

        let (target, _) = tl.lookup(&first_uri, None).await?;
        assert_eq!(target.get_addr(), &udp_peer_addr);

        // test outbound
        let outbound_peer = UdpConnection::create_connection(
            "127.0.0.1:0".parse()?,
            None,
            Some(tl.inner.cancel_token.child_token()),
        )
        .await?;
        let outbound = outbound_peer.get_addr().to_owned();
        tl.add_transport(outbound_peer.into());
        tl.outbound = Some(outbound.clone());

        // must return the outbound transport
        let (target, _) = tl.lookup(&first_uri, None).await?;
        assert_eq!(target.get_addr(), &outbound);
        Ok(())
    }

    #[tokio::test]
    async fn test_sip_dns_lookup() -> Result<()> {
        let check_list = vec![
            (
                "sip:bob@127.0.0.1:5061;transport=udp",
                ("bob", "127.0.0.1", 5061, Transport::Udp),
            ),
            (
                "sip:bob@127.0.0.1:5062;transport=tcp",
                ("bob", "127.0.0.1", 5062, Transport::Tcp),
            ),
            (
                "sip:bob@localhost:5063;transport=tls",
                ("bob", "127.0.0.1", 5063, Transport::Tls),
            ),
        ];

        let resolver = SipResolver::default();

        for item in check_list {
            let uri = crate::sip::uri::Uri::try_from(item.0)?;
            let domain = match &uri.host_with_port.host {
                crate::sip::Host::Domain(d) => d.clone(),
                crate::sip::Host::IpAddr(ip) => crate::sip::Domain::from(ip.to_string()),
            };

            let secure = match uri.scheme {
                Some(crate::sip::Scheme::Sips) => true,
                _ => false,
            };

            // Extract transport from params
            let transport_param = uri.transport().map(|t| *t); // This returns Option<&Transport>

            let targets = resolver
                .lookup(&domain, uri.host_with_port.port, transport_param, secure)
                .await;

            assert!(targets.is_ok(), "Failed to resolve {}", item.0);
            let targets = targets.unwrap();
            assert!(!targets.is_empty());

            let target = &targets[0];

            assert_eq!(uri.user().unwrap(), item.1 .0);
            assert_eq!(target.transport, item.1 .3);
            assert_eq!(target.addr.ip().to_string(), item.1 .1);
            assert_eq!(target.addr.port(), item.1 .2);
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_serve_listens() -> Result<()> {
        let tl = super::TransportLayer::new(tokio_util::sync::CancellationToken::new());

        // Add a UDP connection first
        let udp_conn = UdpConnection::create_connection(
            "127.0.0.1:0".parse()?,
            None,
            Some(tl.inner.cancel_token.child_token()),
        )
        .await?;
        let addr = udp_conn.get_addr().clone();
        tl.add_transport(udp_conn.into());

        // Start serving listeners
        tl.serve_listens().await?;

        // Verify that the transport list is not empty
        let addrs = tl.get_addrs();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], addr);

        // Cancel to stop the spawned tasks
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        drop(tl);

        Ok(())
    }

    #[tokio::test]
    async fn test_resolve_invalid_domain_rejected() {
        use super::DefaultDomainResolver;

        let resolver = DefaultDomainResolver::new();

        // Test various .invalid domains
        let cases = vec![
            ("invalid", "invalid"),
            ("invalid.invalid", "invalid.invalid"),
            ("abc123.invalid", "abc123.invalid"),
        ];

        for (input, expected_in_message) in cases {
            let target = SipAddr {
                r#type: Some(Transport::Udp),
                addr: HostWithPort {
                    host: Host::Domain(input.into()),
                    port: Some(5060.into()),
                },
            };
            let result = resolver.resolve_with_lookup(&target).await;
            assert!(
                result.is_err(),
                "expected error for .invalid domain: {}",
                input
            );
            let err = result.unwrap_err();
            let err_msg = err.to_string();
            assert!(
                err_msg.contains(expected_in_message),
                "error must mention '{}', got: {}",
                expected_in_message,
                err_msg
            );
        }
    }
}

/// Custom TCP in the transport layer: listener, forgetting closed connections, and
/// RFC 3261 §18.1.1 connections on demand.
#[cfg(test)]
mod stream_tests {
    use super::*;
    use crate::sip::SipMessage;
    use crate::transport::custom_tcp::tests::{loopback, ok_for, Peer, PEER_OPTIONS, WAIT};
    use crate::transport::{CustomTcpConnection, CustomTcpListenerConnection};
    use epdg::NetStack;
    use std::io;
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;
    use tokio::time::timeout;

    fn tcp(addr: SocketAddr) -> SipAddr {
        SipAddr {
            r#type: Some(Transport::Tcp),
            addr: addr.into(),
        }
    }

    async fn next_event(rx: &mut TransportReceiver) -> TransportEvent {
        timeout(WAIT, rx.recv())
            .await
            .expect("a transport event in time")
            .expect("transport channel open")
    }

    fn listed(tl: &TransportLayer, remote: &SipAddr) -> Option<SipConnection> {
        tl.inner.connections.get(remote).map(|entry| entry.value().clone())
    }

    fn is(connection: &SipConnection, expected: &CustomTcpConnection) -> bool {
        matches!(connection, SipConnection::CustomTcp(c) if c.same_connection(expected))
    }

    /// The peer connects to our listener (added while the layer is already serving) and
    /// sends a request; it arrives on a new custom TCP connection, the response goes back
    /// on that connection (RFC 3261 §18.2.2), and when the peer hangs up the connection is
    /// forgotten before `Closed` is emitted.
    #[tokio::test]
    async fn a_listener_added_while_serving_accepts_and_the_response_rides_the_same_connection() {
        let tl = TransportLayer::new(CancellationToken::new());
        let mut events = tl.inner.transport_rx.lock().take().unwrap();
        tl.serve_listens().await.unwrap();
        let listener =
            CustomTcpListenerConnection::new(loopback().listen_tcp(0).unwrap(), None);
        let listen_addr = listener.get_addr().clone();
        assert_eq!(listen_addr.r#type, Some(Transport::Tcp));
        let listener = SipConnection::from(listener);
        assert_eq!(listener.transport(), Transport::Tcp);
        assert!(listener.get_remote_addr().is_none());
        tl.add_listener(listener);
        assert_eq!(tl.get_addrs(), vec![listen_addr.clone()]);

        let target = listen_addr.get_socketaddr().unwrap();
        let peer = tokio::task::spawn_blocking(move || {
            let mut peer = Peer::new(TcpStream::connect(target).unwrap());
            peer.write(PEER_OPTIONS.as_bytes());
            let response = peer.read_message();
            (peer, response)
        });

        let accepted = match next_event(&mut events).await {
            TransportEvent::New(SipConnection::CustomTcp(c)) => c,
            other => panic!("expected the accepted connection, got {other:?}"),
        };
        assert_eq!(StreamConnection::get_addr(&accepted), &listen_addr);
        let remote = StreamConnection::get_remote_addr(&accepted).clone();
        let request = match next_event(&mut events).await {
            TransportEvent::Incoming(SipMessage::Request(request), on, from) => {
                assert!(is(&on, &accepted), "{on}");
                assert_eq!(from, remote);
                request
            }
            other => panic!("expected the OPTIONS, got {other:?}"),
        };
        assert!(listed(&tl, &remote).is_some_and(|c| is(&c, &accepted)));

        let response = SipMessage::try_from(ok_for(&request.to_string()).as_bytes()).unwrap();
        SipConnection::CustomTcp(accepted.clone())
            .send(response, None)
            .await
            .unwrap();
        let (peer, response) = timeout(WAIT, peer).await.unwrap().unwrap();
        assert!(response.starts_with("SIP/2.0 200 OK\r\n"), "{response}");
        assert_eq!(tcp(peer.local_addr()), remote);

        drop(peer);
        match next_event(&mut events).await {
            TransportEvent::Closed(closed) => {
                assert!(is(&closed, &accepted), "{closed}");
                assert!(listed(&tl, &remote).is_none(), "forgotten before Closed");
            }
            other => panic!("expected Closed, got {other:?}"),
        }
        assert_eq!(tl.get_addrs(), vec![listen_addr], "the listener stays");
    }

    /// Only the very connection that closed is forgotten: a replacement already installed
    /// under the same remote address stays.
    #[tokio::test]
    async fn a_closed_connection_never_evicts_its_replacement() {
        let tl = TransportLayer::new(CancellationToken::new());
        let mut events = tl.inner.transport_rx.lock().take().unwrap();
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server_addr = server.local_addr().unwrap();
        let first = CustomTcpConnection::new(
            loopback().connect_tcp(server_addr, WAIT).unwrap(),
            None,
            None,
        );
        let (first_peer, _) = server.accept().unwrap();
        let second = CustomTcpConnection::new(
            loopback().connect_tcp(server_addr, WAIT).unwrap(),
            None,
            None,
        );
        let (second_peer, _) = server.accept().unwrap();
        assert_eq!(StreamConnection::get_addr(&first), &tcp(first_peer.peer_addr().unwrap()));
        let remote = tcp(server_addr);
        assert_eq!(StreamConnection::get_remote_addr(&second), &remote);

        tl.add_connection(first.clone().into());
        assert!(matches!(next_event(&mut events).await, TransportEvent::New(c) if is(&c, &first)));
        tl.add_connection(second.clone().into());
        assert!(matches!(next_event(&mut events).await, TransportEvent::New(c) if is(&c, &second)));
        assert!(listed(&tl, &remote).is_some_and(|c| is(&c, &second)));

        drop(first_peer);
        match next_event(&mut events).await {
            TransportEvent::Closed(closed) => assert!(is(&closed, &first), "{closed}"),
            other => panic!("expected Closed, got {other:?}"),
        }
        assert!(
            listed(&tl, &remote).is_some_and(|c| is(&c, &second)),
            "the replacement stays listed"
        );

        drop(second_peer);
        match next_event(&mut events).await {
            TransportEvent::Closed(closed) => assert!(is(&closed, &second), "{closed}"),
            other => panic!("expected Closed, got {other:?}"),
        }
        assert!(listed(&tl, &remote).is_none());
    }

    /// One connection per remote while it lives; once it has closed (and been forgotten)
    /// the next call opens a new one. Without a working connector it is an error, which
    /// `Transaction::send` turns into the UDP fallback.
    #[tokio::test]
    async fn reliable_connection_for_reuses_the_connection_and_reopens_once_it_closed() {
        let tl = TransportLayer::new(CancellationToken::new());
        let mut events = tl.inner.transport_rx.lock().take().unwrap();
        assert_eq!(tl.large_message_threshold(), DEFAULT_LARGE_MESSAGE_THRESHOLD);
        tl.set_large_message_threshold(900);
        assert_eq!(tl.large_message_threshold(), 900);

        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server_addr = server.local_addr().unwrap();
        // The UDP destination a large request would have gone to.
        let destination = SipAddr {
            r#type: Some(Transport::Udp),
            addr: server_addr.into(),
        };
        let e = tl.reliable_connection_for(&destination).await.unwrap_err();
        assert!(e.to_string().contains("no stream connector"), "{e}");

        let calls: Arc<Mutex<Vec<SocketAddr>>> = Arc::default();
        tl.set_stream_connector({
            let calls = calls.clone();
            move |remote: SocketAddr| {
                calls.lock().push(remote);
                loopback().connect_tcp(remote, WAIT)
            }
        });

        let first = match tl.reliable_connection_for(&destination).await.unwrap() {
            SipConnection::CustomTcp(c) => c,
            other => panic!("expected a custom TCP connection, got {other}"),
        };
        assert_eq!(StreamConnection::get_remote_addr(&first), &tcp(server_addr));
        assert!(SipConnection::from(first.clone()).is_reliable());
        assert!(matches!(next_event(&mut events).await, TransportEvent::New(c) if is(&c, &first)));
        let again = tl.reliable_connection_for(&destination).await.unwrap();
        assert!(is(&again, &first), "reused");
        assert_eq!(calls.lock().as_slice(), &[server_addr]);

        let (peer, _) = server.accept().unwrap();
        drop(peer);
        assert!(matches!(next_event(&mut events).await, TransportEvent::Closed(c) if is(&c, &first)));
        let reopened = tl.reliable_connection_for(&destination).await.unwrap();
        assert!(!is(&reopened, &first), "a new connection after the old one closed");
        assert_eq!(calls.lock().len(), 2);
        let (peer, _) = server.accept().unwrap();
        let mut peer = Peer::new(peer);

        // A connector that fails, a destination that is not an IP address, no connector.
        let unused = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let other = SipAddr::from(unused.local_addr().unwrap());
        tl.set_stream_connector(|_: SocketAddr| -> io::Result<Box<dyn epdg::TcpStreamLike>> {
            Err(io::ErrorKind::ConnectionRefused.into())
        });
        let e = tl.reliable_connection_for(&other).await.unwrap_err();
        assert!(e.to_string().contains("TCP connect failed"), "{e}");
        let by_name = SipAddr {
            r#type: Some(Transport::Udp),
            addr: HostWithPort::try_from("pcscf.example.test:5060").unwrap(),
        };
        assert!(tl.reliable_connection_for(&by_name).await.is_err());
        tl.clear_stream_connector();
        assert!(tl.reliable_connection_for(&other).await.is_err());

        // Shutting the transport layer down closes the connection: the peer reads EOF.
        drop(tl);
        timeout(WAIT, tokio::task::spawn_blocking(move || peer.expect_eof()))
            .await
            .unwrap()
            .unwrap();
    }

    /// Two requests needing a connection to the same remote at the same moment share one:
    /// the second waits for the first's connect instead of opening another, which would
    /// replace the first in `connections` and leave it open and never reused.
    #[tokio::test]
    async fn requests_for_a_connection_at_the_same_moment_share_one() {
        let tl = TransportLayer::new(CancellationToken::new());
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server_addr = server.local_addr().unwrap();
        let calls: Arc<AtomicUsize> = Arc::default();
        tl.set_stream_connector({
            let calls = calls.clone();
            move |remote: SocketAddr| {
                calls.fetch_add(1, Ordering::SeqCst);
                // Slow enough that both requests are waiting for a connection at once.
                std::thread::sleep(Duration::from_millis(200));
                loopback().connect_tcp(remote, WAIT)
            }
        });
        let destination = SipAddr {
            r#type: Some(Transport::Udp),
            addr: server_addr.into(),
        };
        let (a, b) = tokio::join!(
            tl.reliable_connection_for(&destination),
            tl.reliable_connection_for(&destination)
        );
        let (SipConnection::CustomTcp(a), SipConnection::CustomTcp(b)) = (a.unwrap(), b.unwrap())
        else {
            panic!("expected custom TCP connections");
        };
        assert!(a.same_connection(&b), "both got the same connection");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "one connect");
        assert!(listed(&tl, &tcp(server_addr)).is_some_and(|c| is(&c, &a)));
        server.accept().expect("the one connection");
        server.set_nonblocking(true).unwrap();
        let second = server.accept().map(|(_, peer)| peer);
        assert!(
            matches!(&second, Err(e) if e.kind() == io::ErrorKind::WouldBlock),
            "no second connection: {second:?}"
        );
    }

    /// A listed connection that has ended but has not been forgotten yet (its serve loop
    /// has not run since) is not handed out again: a new one replaces it.
    #[tokio::test]
    async fn an_ended_connection_still_listed_is_replaced_not_reused() {
        let tl = TransportLayer::new(CancellationToken::new());
        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server_addr = server.local_addr().unwrap();
        let ended = CustomTcpConnection::new(
            loopback().connect_tcp(server_addr, WAIT).unwrap(),
            None,
            None,
        );
        let _first_peer = server.accept().unwrap();
        assert!(!ended.is_closed());
        ended.close().await.unwrap();
        assert!(ended.is_closed());
        // Listed but never served, as if its serve loop had not noticed yet.
        tl.inner
            .connections
            .insert(tcp(server_addr), SipConnection::CustomTcp(ended.clone()));

        let calls: Arc<AtomicUsize> = Arc::default();
        tl.set_stream_connector({
            let calls = calls.clone();
            move |remote: SocketAddr| {
                calls.fetch_add(1, Ordering::SeqCst);
                loopback().connect_tcp(remote, WAIT)
            }
        });
        let destination = SipAddr {
            r#type: Some(Transport::Udp),
            addr: server_addr.into(),
        };
        let fresh = tl.reliable_connection_for(&destination).await.unwrap();
        assert!(!is(&fresh, &ended), "the ended connection is not reused");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(listed(&tl, &tcp(server_addr)).is_some_and(|c| matches!(&c, SipConnection::CustomTcp(c) if !c.same_connection(&ended))));
        let _second_peer = server.accept().unwrap();
    }

    /// A listener that never accepts anything, counting how many accept loops poll it.
    struct FakeListener {
        calls: Arc<AtomicUsize>,
        in_flight: Arc<AtomicUsize>,
        max_in_flight: Arc<AtomicUsize>,
        /// From this call on, the tunnel is dead (`NotConnected`).
        dead_from: Option<usize>,
    }

    impl FakeListener {
        fn new(dead_from: Option<usize>) -> Self {
            FakeListener {
                calls: Arc::default(),
                in_flight: Arc::default(),
                max_in_flight: Arc::default(),
                dead_from,
            }
        }
    }

    impl epdg::TcpListenerLike for FakeListener {
        fn accept_timeout(
            &self,
            timeout: Duration,
        ) -> io::Result<Option<(Box<dyn epdg::TcpStreamLike>, SocketAddr)>> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.dead_from.is_some_and(|dead| call >= dead) {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    epdg::Error::Closed("gateway stopped answering".into()),
                ));
            }
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(timeout.min(Duration::from_millis(20)));
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            Ok(None)
        }

        fn local_addr(&self) -> SocketAddr {
            "127.0.0.1:5060".parse().unwrap()
        }
    }

    /// Nothing polls the listener any more: an accept already in flight may finish, then no
    /// new one starts.
    async fn settles(calls: &AtomicUsize) -> bool {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let before = calls.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(300)).await;
        calls.load(Ordering::SeqCst) == before
    }

    /// `add_listener` before the layer serves its listeners: served by `serve_listens`;
    /// after: served at once. Either way by exactly one accept loop, which `close` ends.
    #[tokio::test]
    async fn add_listener_serves_each_listener_exactly_once() {
        let tl = TransportLayer::new(CancellationToken::new());
        let early = FakeListener::new(None);
        let (early_calls, early_max) = (early.calls.clone(), early.max_in_flight.clone());
        let early = CustomTcpListenerConnection::new(Box::new(early), None);
        tl.add_listener(early.clone().into());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(early_calls.load(Ordering::SeqCst), 0, "not served before serve_listens");

        tl.serve_listens().await.unwrap();
        let late = FakeListener::new(None);
        let (late_calls, late_max) = (late.calls.clone(), late.max_in_flight.clone());
        let late = CustomTcpListenerConnection::new(Box::new(late), None);
        tl.add_listener(late.clone().into());
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(early_calls.load(Ordering::SeqCst) > 0, "served by serve_listens");
        assert!(late_calls.load(Ordering::SeqCst) > 0, "served when added");
        assert_eq!(early_max.load(Ordering::SeqCst), 1, "one accept loop");
        assert_eq!(late_max.load(Ordering::SeqCst), 1, "one accept loop");
        assert_eq!(tl.get_addrs().len(), 2);

        early.close().await.unwrap();
        late.close().await.unwrap();
        assert!(settles(&early_calls).await, "close ends the accept loop");
        assert!(settles(&late_calls).await, "close ends the accept loop");
    }

    /// A dead tunnel (`NotConnected` from accept) ends the accept loop.
    #[tokio::test]
    async fn the_accept_loop_ends_when_the_listener_reports_not_connected() {
        let tl = TransportLayer::new(CancellationToken::new());
        tl.serve_listens().await.unwrap();
        let dying = FakeListener::new(Some(3));
        let calls = dying.calls.clone();
        tl.add_listener(CustomTcpListenerConnection::new(Box::new(dying), None).into());
        let deadline = tokio::time::Instant::now() + WAIT;
        while calls.load(Ordering::SeqCst) < 3 {
            assert!(tokio::time::Instant::now() < deadline, "accept loop never reached the dead call");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(settles(&calls).await, "no accept after NotConnected");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}
