//! A UDP SIP transport over a caller-supplied datagram socket (`epdg::UdpSocketLike`),
//! e.g. a socket living inside a userspace ePDG/IKEv2 tunnel rather than on the OS stack.
//!
//! Mirrors [`super::udp::UdpConnection`]: outgoing messages are written with `send_to`,
//! incoming datagrams are read on a blocking worker (`spawn_blocking`) and handed to the
//! transport layer as [`TransportEvent::Incoming`] with `Via` `received`/`rport` updated.
//!
//! Liveness: the socket underneath may be a tunnel that dies (the gateway stops
//! answering, the host loses every route). It reports that as
//! `io::ErrorKind::NotConnected` on both `recv_timeout` and `send_to`, carrying the
//! tunnel's dead reason in the error's `Display`.
//!
//! The **receive** path is the single exit: a `NotConnected` from `recv_timeout` ends
//! [`CustomUdpConnection::serve_loop`], and that exit is what makes
//! `TransportLayer::serve_connection` emit `TransportEvent::Closed`, which is the signal
//! upstack to re-establish the transport from scratch. A `NotConnected` from `send_to` is
//! logged and returned to the caller as a send error — it does **not** end the loop (see
//! [`CustomUdpConnection::send_error`]). It does not need to: the same tunnel death has
//! already failed the concurrent `recv_timeout`, and the tunnel wakes every blocked
//! receiver when it marks itself dead, so the close follows within one poll rather than
//! at the end of a 250 ms slice. Keeping one exit keeps `Closed` emitted exactly once.
//!
//! Every other receive error is transient: it is logged, backed off briefly and retried.
use super::{connection::TransportSender, SipAddr, SipConnection};
use crate::sip::prelude::HeadersExt;
use crate::{
    transport::{
        connection::{KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE},
        TransportEvent,
    },
    Result,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// How long one blocking receive waits before re-checking the cancellation token.
const RECV_POLL: Duration = Duration::from_millis(250);
/// Pause after a receive error that is not fatal. Without it a socket that fails
/// instantly and forever (a `spawn_blocking` pool that keeps rejecting, say) would spin
/// this loop at full speed; every such error is also logged.
const RECV_ERROR_BACKOFF: Duration = Duration::from_millis(50);

pub struct CustomUdpInner {
    pub socket: Arc<dyn epdg::UdpSocketLike>,
    pub addr: SipAddr,
}

/// SIP over an externally provided UDP socket (see module docs).
#[derive(Clone)]
pub struct CustomUdpConnection {
    remote: Option<SipAddr>,
    cancel_token: Option<CancellationToken>,
    inner: Arc<CustomUdpInner>,
}

fn udp_sip_addr(addr: SocketAddr) -> SipAddr {
    SipAddr {
        r#type: Some(crate::sip::transport::Transport::Udp),
        addr: addr.into(),
    }
}

impl CustomUdpConnection {
    /// Wrap an already-bound socket. `remote` pins the peer this connection talks to
    /// (the P-CSCF); the transport layer keys connections by it.
    pub fn new(
        socket: Box<dyn epdg::UdpSocketLike>,
        remote: Option<SocketAddr>,
        cancel_token: Option<CancellationToken>,
    ) -> Self {
        let addr = udp_sip_addr(socket.local_addr());
        let socket: Arc<dyn epdg::UdpSocketLike> = Arc::from(socket);
        let t = CustomUdpConnection {
            remote: remote.map(udp_sip_addr),
            cancel_token,
            inner: Arc::new(CustomUdpInner { socket, addr }),
        };
        debug!(local = %t, ?remote, "created custom UDP connection");
        t
    }

    /// Receive datagrams until the socket dies or the connection is cancelled.
    ///
    /// Returning (with `Ok` or `Err`) is what makes `TransportLayer::serve_connection`
    /// emit `TransportEvent::Closed` for this connection, so the loop must end promptly
    /// once the tunnel underneath is unrecoverable. The epdg tunnel signals exactly that
    /// as `io::ErrorKind::NotConnected` (`Error::Closed` → `netstack::to_io`), and the
    /// error's `Display` carries the tunnel's dead reason ("tunnel closed: …"), which is
    /// logged here — it is the only place that reason reaches the SIP layer.
    pub async fn serve_loop(&self, sender: TransportSender) -> Result<()> {
        loop {
            let socket = self.inner.socket.clone();
            let received = tokio::select! {
                _ = async {
                    if let Some(ref cancel_token) = self.cancel_token {
                        cancel_token.cancelled().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {
                    debug!(local = %self.get_addr(), "custom UDP serve_loop cancelled");
                    return Ok(());
                }
                result = tokio::task::spawn_blocking(move || socket.recv_timeout(RECV_POLL)) => {
                    match result {
                        Ok(Ok(Some(datagram))) => datagram,
                        Ok(Ok(None)) => continue,
                        Ok(Err(e)) => {
                            if e.kind() == std::io::ErrorKind::NotConnected {
                                // `e` displays the tunnel's dead reason, e.g.
                                // "tunnel closed: gateway stopped answering".
                                warn!(local = %self.get_addr(), reason = %e, "custom UDP socket closed (tunnel unrecoverable); stopping serve_loop");
                                return Ok(());
                            }
                            warn!(error = %e, "error receiving custom UDP packet");
                            tokio::time::sleep(RECV_ERROR_BACKOFF).await;
                            continue;
                        }
                        Err(e) => {
                            warn!(error = %e, "custom UDP receive task failed");
                            tokio::time::sleep(RECV_ERROR_BACKOFF).await;
                            continue;
                        }
                    }
                }
            };
            let (addr, packet) = received;
            let packet = packet.as_slice();

            match packet {
                KEEPALIVE_REQUEST => {
                    self.inner.socket.send_to(addr, KEEPALIVE_RESPONSE).ok();
                    continue;
                }
                KEEPALIVE_RESPONSE => continue,
                _ => {
                    if packet.iter().all(|&b| b.is_ascii_whitespace()) {
                        continue;
                    }
                }
            }

            let raw_message = String::from_utf8_lossy(packet);
            let msg = match crate::sip::SipMessage::try_from(packet) {
                Ok(msg) => msg,
                Err(e) => {
                    debug!(src = %addr, error = %e, raw_message = ?raw_message, "error parsing SIP message");
                    continue;
                }
            };
            let msg = match SipConnection::update_msg_received(
                msg,
                addr,
                crate::sip::transport::Transport::Udp,
            ) {
                Ok(msg) => msg,
                Err(e) => {
                    debug!(src = %addr, error = ?e, raw_message = ?raw_message, "error updating SIP via");
                    continue;
                }
            };
            let cseq = msg
                .cseq_header()
                .map(|c| c.value().to_string())
                .unwrap_or_default();
            debug!(len = packet.len(), src = %addr, dest = %self.get_addr(), cseq = %cseq, raw_message = ?raw_message, "custom udp received");

            let from = udp_sip_addr(addr);
            sender.send(TransportEvent::Incoming(
                msg,
                SipConnection::CustomUdp(Self {
                    remote: Some(from.clone()),
                    cancel_token: self.cancel_token.clone(),
                    inner: self.inner.clone(),
                }),
                from,
            ))?;
        }
    }

    pub async fn send(
        &self,
        msg: crate::sip::SipMessage,
        destination: Option<&SipAddr>,
    ) -> Result<()> {
        let destination = match destination {
            Some(addr) => addr.get_socketaddr(),
            None => SipConnection::get_destination(&msg),
        }?;
        // to_bytes() keeps binary bodies intact (RFC 3261 §7.4).
        let buf = msg.to_bytes();
        let cseq = msg
            .cseq_header()
            .map(|c| c.value().to_string())
            .unwrap_or_default();
        debug!(len = buf.len(), dest = %destination, src = %self.get_addr(), cseq = %cseq, raw_message = ?String::from_utf8_lossy(&buf), "custom udp send");
        self.inner
            .socket
            .send_to(destination, &buf)
            .map_err(|e| self.send_error(e))
    }

    pub fn send_raw(&self, buf: &[u8], destination: &SipAddr) -> Result<()> {
        self.inner
            .socket
            .send_to(destination.get_socketaddr()?, buf)
            .map_err(|e| self.send_error(e))
    }

    /// A failed send as a transport error. The `io::ErrorKind` is flattened into the
    /// message (that is the shape callers already handle), so the send path cannot itself
    /// report liveness — it only logs the reason. Nothing more is needed: the tunnel death
    /// that failed this send has already failed the concurrent `recv_timeout` (epdg
    /// `docs/DESIGN.md` §17.6 — a parked receive returns `NotConnected` at once and every
    /// later call keeps returning it), so `serve_loop` is already ending, from its one and
    /// only exit path.
    fn send_error(&self, e: std::io::Error) -> crate::Error {
        if e.kind() == std::io::ErrorKind::NotConnected {
            warn!(local = %self.get_addr(), reason = %e, "custom UDP send on a dead tunnel");
        }
        crate::Error::TransportLayerError(e.to_string(), self.get_addr().to_owned())
    }

    pub fn get_addr(&self) -> &SipAddr {
        &self.inner.addr
    }

    pub fn get_remote_addr(&self) -> Option<&SipAddr> {
        self.remote.as_ref()
    }

    pub fn cancel_token(&self) -> Option<CancellationToken> {
        self.cancel_token.clone()
    }
}

impl std::fmt::Display for CustomUdpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner.socket.local_addr())
    }
}

impl std::fmt::Debug for CustomUdpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner.addr)
    }
}

impl Drop for CustomUdpInner {
    fn drop(&mut self) {
        debug!(addr = %self.addr, "dropping custom UDP transport");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::connection::TransportEvent;
    use std::collections::VecDeque;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio::sync::mpsc::unbounded_channel;

    /// One scripted `recv_timeout` outcome.
    type RecvResult = io::Result<Option<(SocketAddr, Vec<u8>)>>;

    /// A scripted [`epdg::UdpSocketLike`]: `recv_timeout` returns the next scripted
    /// result and, once the script is exhausted, reports the tunnel gone exactly as
    /// `epdg` does after `mark_dead`. No sockets, no tunnel, no timing races.
    struct FakeSocket {
        script: Mutex<VecDeque<RecvResult>>,
        send_kind: Option<io::ErrorKind>,
        calls: Arc<AtomicUsize>,
    }

    /// The error an epdg tunnel produces for every inner socket once it is dead:
    /// `Error::Closed(reason)` mapped by `netstack::to_io` to `NotConnected`, the reason
    /// still readable through `Display`.
    fn tunnel_dead(reason: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::NotConnected,
            epdg::Error::Closed(reason.to_string()),
        )
    }

    impl FakeSocket {
        fn scripted(script: Vec<RecvResult>) -> Self {
            FakeSocket {
                script: Mutex::new(script.into()),
                send_kind: None,
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        /// Every send reports the tunnel dead; the receive script decides when the loop
        /// notices.
        fn dead_sends(script: Vec<RecvResult>) -> Self {
            FakeSocket {
                script: Mutex::new(script.into()),
                send_kind: Some(io::ErrorKind::NotConnected),
                calls: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn calls(&self) -> Arc<AtomicUsize> {
            self.calls.clone()
        }
    }

    impl epdg::UdpSocketLike for FakeSocket {
        fn send_to(&self, _dst: SocketAddr, _payload: &[u8]) -> io::Result<()> {
            match self.send_kind {
                Some(io::ErrorKind::NotConnected) => Err(tunnel_dead("gateway stopped answering")),
                Some(kind) => Err(io::Error::new(kind, "scripted send failure")),
                None => Ok(()),
            }
        }

        fn recv_timeout(&self, _timeout: Duration) -> RecvResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(next) = self.script.lock().unwrap().pop_front() {
                return next;
            }
            Err(tunnel_dead("gateway stopped answering"))
        }

        fn local_addr(&self) -> SocketAddr {
            "127.0.0.1:5060".parse().unwrap()
        }
    }

    fn connection(socket: FakeSocket) -> (CustomUdpConnection, Arc<AtomicUsize>) {
        let calls = socket.calls();
        (
            CustomUdpConnection::new(Box::new(socket), Some("127.0.0.2:5060".parse().unwrap()), None),
            calls,
        )
    }

    /// The death of the tunnel must end the loop — `Ok(())` is what makes the transport
    /// layer emit `TransportEvent::Closed` (epdg `docs/DESIGN.md` §17.6).
    #[tokio::test]
    async fn serve_loop_exits_when_the_socket_reports_not_connected() {
        let (conn, calls) = connection(FakeSocket::scripted(vec![
            Ok(None),
            Ok(None),
            Err(tunnel_dead("gateway stopped answering")),
        ]));
        let (tx, mut rx) = unbounded_channel::<TransportEvent>();
        let r = tokio::time::timeout(Duration::from_secs(2), conn.serve_loop(tx)).await;
        assert!(matches!(r, Ok(Ok(()))), "serve_loop did not exit cleanly: {r:?}");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(rx.try_recv().is_err(), "no SIP message was delivered");
    }

    /// Anything that is not `NotConnected` is transient: log, back off, keep serving.
    #[tokio::test]
    async fn serve_loop_survives_other_errors_and_exits_on_not_connected() {
        let (conn, calls) = connection(FakeSocket::scripted(vec![
            Err(io::Error::other("transient")),
            Err(io::Error::from(io::ErrorKind::WouldBlock)),
            Ok(None),
        ]));
        let (tx, _rx) = unbounded_channel::<TransportEvent>();
        let r = tokio::time::timeout(Duration::from_secs(2), conn.serve_loop(tx)).await;
        assert!(matches!(r, Ok(Ok(()))), "serve_loop did not exit cleanly: {r:?}");
        assert!(calls.load(Ordering::SeqCst) >= 4, "the loop kept serving after the transient errors");
    }

    /// A send that finds the tunnel dead reports it to its caller; ending the loop stays
    /// the receive side's job, and the same death has already failed the receive, so
    /// `TransportEvent::Closed` is still emitted from exactly one place.
    #[tokio::test]
    async fn a_send_on_a_dead_tunnel_reports_the_error_while_recv_ends_the_loop() {
        // One timeout, then the receive sees the same death the send did.
        let (conn, calls) = connection(FakeSocket::dead_sends(vec![Ok(None)]));
        let (tx, _rx) = unbounded_channel::<TransportEvent>();
        let serving = {
            let conn = conn.clone();
            tokio::spawn(async move { conn.serve_loop(tx).await })
        };
        let dest = udp_sip_addr("127.0.0.2:5060".parse().unwrap());
        let e = conn.send_raw(b"OPTIONS", &dest).unwrap_err();
        assert!(matches!(e, crate::Error::TransportLayerError(..)), "{e:?}");
        let r = tokio::time::timeout(Duration::from_secs(2), serving).await;
        assert!(matches!(r, Ok(Ok(Ok(())))), "serve_loop did not exit: {r:?}");
        assert!(calls.load(Ordering::SeqCst) >= 2, "the loop ended on the receive path");
    }

    /// The connection keeps reporting itself as plain unreliable UDP, so retransmission
    /// stays the transaction layer's job (RFC 3261 §17).
    #[test]
    fn custom_udp_is_unreliable_udp() {
        let (conn, _calls) = connection(FakeSocket::dead_sends(vec![]));
        let connection = SipConnection::from(conn);
        assert_eq!(connection.transport(), crate::sip::transport::Transport::Udp);
        assert!(!connection.is_reliable());
    }
}
