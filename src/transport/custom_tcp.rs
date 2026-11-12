//! SIP over TCP through caller-supplied stream sockets (no TLS): a connected
//! `epdg::TcpStreamLike` ([`CustomTcpConnection`]) or the streams an `epdg::TcpListenerLike`
//! accepts ([`CustomTcpListenerConnection`]), e.g. TCP inside a userspace ePDG/IKEv2 tunnel
//! rather than on the OS stack. The stream counterpart of [`super::custom_udp`].
//!
//! # Why a bridge
//!
//! Framing (Content-Length, RFC 3261 §18.3), CRLF keepalives (RFC 5626 §3.5.1) and the
//! `received`/`rport` handling of every stream transport live in [`StreamConnectionInner`],
//! which reads and writes through tokio's `AsyncRead`/`AsyncWrite`. The caller's stream is
//! synchronous and blocking, so [`CustomTcpConnection`] reuses `StreamConnectionInner`
//! unchanged and puts two dedicated threads per connection in between:
//!
//! - the reader thread (`sip-tcp-read`) loops `read` in 250 ms slices (a read timeout),
//!   so it notices the connection being closed or dropped, and hands every chunk to a tokio
//!   channel that `BridgeReader` drains. EOF closes the channel (`poll_read` returns 0
//!   bytes); a hard error — `NotConnected` from a dead tunnel, carrying the tunnel's reason in
//!   its `Display` — is delivered as that error, then EOF.
//! - the writer thread (`sip-tcp-write`) writes, in order, what `BridgeWriter::poll_write`
//!   queued (`poll_write` returns at once). The first write error is kept and returned by the
//!   next `poll_write`/`poll_flush`. `poll_shutdown` queues a marker: everything queued before
//!   it is written, then the thread shuts the stream down.
//!
//! Both threads end once the connection is closed ([`CustomTcpConnection::close`]) or its last
//! handle is dropped. A connection over which nothing has been received for `IDLE_CLOSE` (five
//! minutes) closes itself: neither smoltcp nor this bridge would otherwise ever notice a peer
//! that vanished without a word (a middlebox that forgot the flow, say), and every request
//! reused onto it would be lost.
//!
//! # One exit
//!
//! As for custom UDP, the receive path is the single exit: the serve loop ends on EOF or on a
//! read error, and that exit is what makes `TransportLayer::serve_connection` forget the
//! connection and emit `TransportEvent::Closed` — exactly once. A write error is returned to
//! whoever sends next; the writer thread also shuts the stream down, so the reader sees EOF
//! and the connection ends through that same exit instead of lingering half-dead in the
//! transport layer, where it would keep being reused.
//!
//! # Transport selection (RFC 3261 §18.1.1, §18.2.2, §9.1)
//!
//! A request that would go over UDP but is larger than
//! `TransportLayer::large_message_threshold` (1300 bytes by default) goes over TCP to the
//! same remote: `Transaction::send` asks `TransportLayer::reliable_connection_for`, which
//! reuses a connection to that address or opens one through the caller's `StreamConnector`
//! and wraps it here (one call at a time, so requests at the same moment share it). If that
//! fails the request goes over UDP after all (§18.1.1). Either way the top `Via` names the
//! transport the request actually leaves on. A request bound to a connection that has ended
//! since ([`CustomTcpConnection::is_closed`]) — an authentication retry, a CANCEL — goes over
//! a new one to the same remote. A CANCEL rides the connection its INVITE went out on,
//! whatever the dialog's route set (§9.1). Requests the peer sends over TCP arrive through a
//! [`CustomTcpListenerConnection`]; their responses go back over the connection they arrived
//! on (§18.2.2), which the server transaction keeps. Not done: if that connection closes
//! before the response is sent, §18.2.2's fresh connection to the Via's `received` / sent-by
//! is not opened (the send fails), and `TransportLayer::lookup` of a TCP- or TLS-typed target
//! still dials an OS socket, not the `StreamConnector`.
use super::{
    connection::TransportSender,
    stream::{StreamConnection, StreamConnectionInner},
    transport_layer::TransportLayerInnerRef,
    SipAddr, SipConnection,
};
use crate::sip::{transport::Transport, SipMessage};
use crate::Result;
use parking_lot::Mutex;
use std::{
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
    thread,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// How long one blocking read, write or accept waits before checking again whether the
/// connection (or listener) has been closed.
const IO_POLL: Duration = Duration::from_millis(250);
/// Pause after an accept error that is not fatal (see [`super::custom_udp`]'s receive loop).
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
/// Size of the reader thread's buffer; one `read` hands at most this much to the serve loop.
const READ_BUFFER: usize = 16 * 1024;
/// A connection over which nothing has been received for this long is closed (how long an
/// unused connection stays open is the implementation's choice, RFC 3261 §18). Longer than
/// any silence a transaction can see on it — Timer B (32 s), Timer C (180 s) between an
/// INVITE's provisional and final responses — and shorter than the idle timeouts after which
/// middleboxes forget a flow without a word. Nothing else would notice such a flow: smoltcp
/// never gives up retransmitting, so every request reused onto it would be lost for good.
const IDLE_CLOSE: Duration = Duration::from_secs(300);

type CustomTcpInner = StreamConnectionInner<BridgeReader, BridgeWriter>;

fn tcp_sip_addr(addr: SocketAddr) -> SipAddr {
    SipAddr {
        r#type: Some(Transport::Tcp),
        addr: addr.into(),
    }
}

/// What a connection's handles and its two threads share.
#[derive(Default)]
struct Shared {
    /// Set once the connection is closed or its last handle dropped: the reader stops at its
    /// next read slice, the writer gives up on a write the peer does not take.
    stop: AtomicBool,
    /// Set when the reader thread has ended (EOF, a read error, a stop) — before the serve
    /// loop can see the end of its stream: nothing more will arrive on this connection.
    read_ended: AtomicBool,
    /// The writer thread's first error (kind and message; `io::Error` is not `Clone`).
    write_error: Mutex<Option<(io::ErrorKind, String)>>,
}

impl Shared {
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// The connection can no longer carry a request and its response.
    fn finished(&self) -> bool {
        self.stopped() || self.read_ended.load(Ordering::SeqCst) || self.write_error.lock().is_some()
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    fn record_write_error(&self, e: &io::Error) {
        let mut slot = self.write_error.lock();
        if slot.is_none() {
            *slot = Some((e.kind(), e.to_string()));
        }
    }

    fn write_error(&self) -> Option<io::Error> {
        self.write_error
            .lock()
            .as_ref()
            .map(|(kind, message)| io::Error::new(*kind, message.clone()))
    }
}

/// The error for a write after the connection was shut down or its writer thread ended.
fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "custom TCP connection is closed")
}

/// A read or write timeout (one [`IO_POLL`] slice elapsed) or an interrupted call: try again.
fn is_retry(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

/// `AsyncRead` half of the bridge: the chunks the reader thread read (see module docs).
struct BridgeReader {
    chunks: UnboundedReceiver<io::Result<Vec<u8>>>,
    /// The chunk being handed out and how much of it already was.
    pending: Vec<u8>,
    offset: usize,
}

impl AsyncRead for BridgeReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.offset >= this.pending.len() {
            match this.chunks.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                // The reader thread is gone: EOF (after any error it delivered).
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(Some(Ok(chunk))) => {
                    this.pending = chunk;
                    this.offset = 0;
                }
            }
        }
        let n = (this.pending.len() - this.offset).min(buf.remaining());
        buf.put_slice(&this.pending[this.offset..this.offset + n]);
        this.offset += n;
        Poll::Ready(Ok(()))
    }
}

enum WriteCommand {
    Data(Vec<u8>),
    /// Shut the stream down once everything queued before this is written.
    Shutdown,
}

/// `AsyncWrite` half of the bridge: queues for the writer thread (see module docs).
struct BridgeWriter {
    commands: UnboundedSender<WriteCommand>,
    shared: Arc<Shared>,
    shut_down: bool,
}

impl AsyncWrite for BridgeWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(e) = self.shared.write_error() {
            return Poll::Ready(Err(e));
        }
        if self.shut_down {
            return Poll::Ready(Err(closed_error()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.commands.send(WriteCommand::Data(buf.to_vec())) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(closed_error())),
        }
    }

    /// Bytes are handed to the writer thread, not awaited: this only reports an earlier
    /// write error.
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(match self.shared.write_error() {
            Some(e) => Err(e),
            None => Ok(()),
        })
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shut_down {
            self.shut_down = true;
            // A writer thread that has already ended has nothing left to shut down.
            let _ = self.commands.send(WriteCommand::Shutdown);
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for BridgeWriter {
    /// The writer lives as long as the connection's inner state, i.e. until its last handle
    /// is dropped: stop both threads.
    fn drop(&mut self) {
        self.shared.stop();
    }
}

/// Start the two bridge threads for `stream` (see module docs); the reader closes the
/// connection once nothing has been received for `idle_close`.
fn start_bridge(
    stream: &Arc<dyn epdg::TcpStreamLike>,
    shared: &Arc<Shared>,
    idle_close: Duration,
) -> (BridgeReader, BridgeWriter) {
    let peer = stream.peer_addr();
    let (chunk_tx, chunk_rx) = unbounded_channel();
    let (command_tx, command_rx) = unbounded_channel();

    // Kept until the spawn result is known: a reader that cannot start reports why through
    // the channel, so the serve loop ends with that error (the one exit).
    let failure_tx = chunk_tx.clone();
    let reader = {
        let (stream, shared) = (stream.clone(), shared.clone());
        thread::Builder::new()
            .name("sip-tcp-read".into())
            .spawn(move || {
                read_loop(&*stream, &chunk_tx, &shared, idle_close);
                // Before `chunk_tx` drops: whoever sees the serve loop end sees this too.
                shared.read_ended.store(true, Ordering::SeqCst);
            })
    };
    if let Err(e) = reader {
        warn!(%peer, error = %e, "cannot start the custom TCP reader thread; the connection ends");
        shared.read_ended.store(true, Ordering::SeqCst);
        let _ = failure_tx.send(Err(e));
    }
    drop(failure_tx);

    let writer = {
        let (stream, shared) = (stream.clone(), shared.clone());
        thread::Builder::new()
            .name("sip-tcp-write".into())
            .spawn(move || write_loop(&*stream, command_rx, &shared))
    };
    if let Err(e) = writer {
        warn!(%peer, error = %e, "cannot start the custom TCP writer thread; the connection ends");
        shared.record_write_error(&e);
        // Nothing can be sent: end the connection through the reader's EOF.
        let _ = stream.shutdown();
    }

    (
        BridgeReader {
            chunks: chunk_rx,
            pending: Vec::new(),
            offset: 0,
        },
        BridgeWriter {
            commands: command_tx,
            shared: shared.clone(),
            shut_down: false,
        },
    )
}

/// The reader thread: `read` in [`IO_POLL`] slices until EOF, a hard error, the connection
/// being stopped, the serve loop no longer listening, or nothing received for `idle_close`
/// (then it shuts the stream down: the serve loop sees EOF, the one exit).
fn read_loop(
    stream: &dyn epdg::TcpStreamLike,
    chunks: &UnboundedSender<io::Result<Vec<u8>>>,
    shared: &Shared,
    idle_close: Duration,
) {
    let peer = stream.peer_addr();
    if let Err(e) = stream.set_read_timeout(Some(IO_POLL)) {
        debug!(%peer, error = %e, "custom TCP reader cannot set its read timeout");
        shared.read_ended.store(true, Ordering::SeqCst);
        let _ = chunks.send(Err(e));
        return;
    }
    let mut buf = vec![0u8; READ_BUFFER];
    let mut last_received = Instant::now();
    loop {
        if shared.stopped() || chunks.is_closed() {
            debug!(%peer, "custom TCP reader stopped");
            return;
        }
        match stream.read(&mut buf) {
            Ok(0) => {
                debug!(%peer, "custom TCP stream reached EOF");
                return;
            }
            Ok(n) => {
                last_received = Instant::now();
                if chunks.send(Ok(buf[..n].to_vec())).is_err() {
                    return;
                }
            }
            Err(e) if is_retry(&e) => {
                if last_received.elapsed() >= idle_close {
                    debug!(%peer, ?idle_close, "nothing received on the custom TCP connection for that long; closing it");
                    shared.read_ended.store(true, Ordering::SeqCst);
                    if let Err(e) = stream.shutdown() {
                        debug!(%peer, error = %e, "custom TCP shutdown failed");
                    }
                    return;
                }
            }
            Err(e) => {
                // A dead tunnel says NotConnected and carries its reason; the serve loop logs it.
                debug!(%peer, error = %e, "custom TCP read failed");
                shared.read_ended.store(true, Ordering::SeqCst);
                let _ = chunks.send(Err(e));
                return;
            }
        }
    }
}

/// The writer thread: write what is queued, in order, until a shutdown marker, a write
/// error, or the connection being dropped.
fn write_loop(
    stream: &dyn epdg::TcpStreamLike,
    mut commands: UnboundedReceiver<WriteCommand>,
    shared: &Shared,
) {
    let peer = stream.peer_addr();
    if let Err(e) = stream.set_write_timeout(Some(IO_POLL)) {
        warn!(%peer, error = %e, "custom TCP writer cannot set its write timeout; shutting the connection down");
        shared.record_write_error(&e);
        let _ = stream.shutdown();
        return;
    }
    while let Some(command) = commands.blocking_recv() {
        match command {
            WriteCommand::Data(data) => {
                if let Err(e) = write_all(stream, &data, shared) {
                    warn!(%peer, error = %e, "custom TCP write failed; shutting the connection down");
                    shared.record_write_error(&e);
                    // The reader sees EOF and the serve loop ends: the one exit.
                    let _ = stream.shutdown();
                    return;
                }
            }
            WriteCommand::Shutdown => {
                if let Err(e) = stream.shutdown() {
                    debug!(%peer, error = %e, "custom TCP shutdown failed");
                }
                debug!(%peer, "custom TCP stream shut down");
                return;
            }
        }
    }
    debug!(%peer, "custom TCP writer stopped (connection dropped)");
}

/// Write all of `buf` in [`IO_POLL`] slices. A slice in which the peer took nothing is
/// retried, unless the connection has been stopped meanwhile (then the peer is not reading
/// and nobody is waiting for it any more).
fn write_all(stream: &dyn epdg::TcpStreamLike, mut buf: &[u8], shared: &Shared) -> io::Result<()> {
    while !buf.is_empty() {
        match stream.write(buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "the stream accepted no bytes",
                ))
            }
            Ok(n) => buf = &buf[n..],
            Err(e) if is_retry(&e) => {
                if shared.stopped() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "connection closed while the peer was not reading",
                    ));
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// SIP over a caller-supplied TCP stream (see module docs). Reliable, transport TCP.
#[derive(Clone)]
pub struct CustomTcpConnection {
    inner: Arc<CustomTcpInner>,
    stream: Arc<dyn epdg::TcpStreamLike>,
    shared: Arc<Shared>,
    cancel_token: Option<CancellationToken>,
}

impl CustomTcpConnection {
    /// Wrap a connected stream and start its two bridge threads. `local` is the address the
    /// connection reports as its own (a listener passes its address); `None` = the stream's
    /// local address. The remote address is the stream's peer; the transport layer keys the
    /// connection by it. `cancel_token` ends the serve loop when cancelled. The connection
    /// closes itself once nothing has been received on it for five minutes.
    pub fn new(
        stream: Box<dyn epdg::TcpStreamLike>,
        local: Option<SipAddr>,
        cancel_token: Option<CancellationToken>,
    ) -> Self {
        Self::with_idle_close(stream, local, cancel_token, IDLE_CLOSE)
    }

    /// [`new`](Self::new) with another idle limit than [`IDLE_CLOSE`].
    pub(crate) fn with_idle_close(
        stream: Box<dyn epdg::TcpStreamLike>,
        local: Option<SipAddr>,
        cancel_token: Option<CancellationToken>,
        idle_close: Duration,
    ) -> Self {
        let stream: Arc<dyn epdg::TcpStreamLike> = Arc::from(stream);
        let local = local.unwrap_or_else(|| tcp_sip_addr(stream.local_addr()));
        let remote = tcp_sip_addr(stream.peer_addr());
        let shared = Arc::new(Shared::default());
        let (reader, writer) = start_bridge(&stream, &shared, idle_close);
        let connection = CustomTcpConnection {
            inner: Arc::new(StreamConnectionInner::new(local, remote, reader, writer)),
            stream,
            shared,
            cancel_token,
        };
        debug!(connection = %connection, local = %connection.inner.local_addr, "created custom TCP connection");
        connection
    }

    pub fn cancel_token(&self) -> Option<CancellationToken> {
        self.cancel_token.clone()
    }

    /// Whether `other` is a handle to this same connection (not merely one between the same
    /// addresses).
    pub fn same_connection(&self, other: &CustomTcpConnection) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Whether the connection has ended — closed, its stream at EOF or failed, or a write
    /// failed — so a request sent on it now would be lost: one bound to it goes over a new
    /// connection instead (`Transaction::send`, `TransportLayer::reliable_connection_for`).
    /// Set before the serve loop ends, and so before the transport layer forgets it.
    pub fn is_closed(&self) -> bool {
        self.shared.finished()
    }
}

#[async_trait::async_trait]
impl StreamConnection for CustomTcpConnection {
    fn get_addr(&self) -> &SipAddr {
        &self.inner.local_addr
    }

    fn get_remote_addr(&self) -> &SipAddr {
        &self.inner.remote_addr
    }

    async fn send_message(&self, msg: SipMessage) -> Result<()> {
        self.inner.send_message(msg).await
    }

    /// Raw bytes on the stream, e.g. a CRLF keepalive (RFC 5626 §3.5.1).
    async fn send_raw(&self, data: &[u8]) -> Result<()> {
        self.inner.send_raw(data).await
    }

    /// Frame and deliver incoming messages until EOF, a read error or cancellation. The
    /// return is what makes `TransportLayer::serve_connection` emit `TransportEvent::Closed`.
    async fn serve_loop(&self, sender: TransportSender) -> Result<()> {
        let serving = self
            .inner
            .serve_loop(sender, SipConnection::CustomTcp(self.clone()));
        match &self.cancel_token {
            Some(token) => tokio::select! {
                _ = token.cancelled() => {
                    debug!(connection = %self, "custom TCP serve_loop cancelled");
                    Ok(())
                }
                result = serving => result,
            },
            None => serving.await,
        }
    }

    /// Shut the stream down once everything already queued is written, and stop both threads.
    async fn close(&self) -> Result<()> {
        let result = self.inner.close().await;
        self.shared.stop();
        result
    }
}

impl fmt::Display for CustomTcpConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} -> {}",
            self.stream.local_addr(),
            self.stream.peer_addr()
        )
    }
}

impl fmt::Debug for CustomTcpConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Accepts SIP-over-TCP connections on a caller-supplied listener (e.g. inside an ePDG
/// tunnel); every accepted stream becomes a [`CustomTcpConnection`] in the transport layer.
#[derive(Clone)]
pub struct CustomTcpListenerConnection {
    listener: Arc<dyn epdg::TcpListenerLike>,
    addr: SipAddr,
    cancel_token: Option<CancellationToken>,
    /// Ends the accept loop: cancelled by [`close`](Self::close), and with `cancel_token`.
    stop: CancellationToken,
}

impl CustomTcpListenerConnection {
    /// Wrap a bound listener. Its address (typed TCP) is what the transport layer lists for
    /// it. Cancelling `cancel_token` ends the accept loop (connections already accepted stay
    /// up, as with an OS listener).
    pub fn new(
        listener: Box<dyn epdg::TcpListenerLike>,
        cancel_token: Option<CancellationToken>,
    ) -> Self {
        let addr = tcp_sip_addr(listener.local_addr());
        let stop = cancel_token
            .as_ref()
            .map(CancellationToken::child_token)
            .unwrap_or_default();
        let listener = CustomTcpListenerConnection {
            listener: Arc::from(listener),
            addr,
            cancel_token,
            stop,
        };
        debug!(addr = %listener.addr, "created custom TCP listener");
        listener
    }

    /// Spawn the accept loop: `accept_timeout` in 250 ms slices on the blocking pool
    /// until the listener is closed, its token or the transport layer is cancelled, or the
    /// listener reports `NotConnected` (a dead tunnel). Each accepted peer passes the
    /// transport layer's whitelist and is added as a [`CustomTcpConnection`] (served at once).
    pub async fn serve_listener(&self, transport_layer_inner: TransportLayerInnerRef) -> Result<()> {
        let listener = self.listener.clone();
        let local = self.addr.clone();
        let stop = self.stop.clone();
        tokio::spawn(async move {
            let layer_token = transport_layer_inner.cancel_token.clone();
            loop {
                // Checked before the next accept is started, not only while one is waiting:
                // nothing is accepted once the listener has been closed.
                if stop.is_cancelled() || layer_token.is_cancelled() {
                    debug!(%local, "custom TCP listener stopped");
                    return;
                }
                let accepting = listener.clone();
                let accept =
                    tokio::task::spawn_blocking(move || accepting.accept_timeout(IO_POLL));
                let accepted = tokio::select! {
                    _ = stop.cancelled() => {
                        debug!(%local, "custom TCP listener closed");
                        return;
                    }
                    _ = layer_token.cancelled() => {
                        debug!(%local, "transport layer cancelled; custom TCP listener stops");
                        return;
                    }
                    result = accept => result,
                };
                let (stream, peer) = match accepted {
                    Ok(Ok(Some(accepted))) => accepted,
                    Ok(Ok(None)) => continue,
                    Ok(Err(e)) if e.kind() == io::ErrorKind::NotConnected => {
                        // `e` displays the tunnel's dead reason.
                        warn!(%local, reason = %e, "custom TCP listener closed (tunnel unrecoverable); stopping accept loop");
                        return;
                    }
                    Ok(Err(e)) => {
                        warn!(%local, error = %e, "error accepting custom TCP connection");
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                        continue;
                    }
                    Err(e) => {
                        warn!(%local, error = %e, "custom TCP accept task failed");
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                        continue;
                    }
                };
                if !transport_layer_inner.is_whitelisted(peer.ip()).await {
                    debug!(%local, %peer, "custom TCP connection rejected by whitelist");
                    continue;
                }
                let connection = CustomTcpConnection::new(
                    stream,
                    Some(local.clone()),
                    Some(layer_token.child_token()),
                );
                debug!(%local, %peer, "accepted custom TCP connection");
                transport_layer_inner.add_connection(SipConnection::CustomTcp(connection));
            }
        });
        Ok(())
    }

    pub fn get_addr(&self) -> &SipAddr {
        &self.addr
    }

    pub fn cancel_token(&self) -> Option<CancellationToken> {
        self.cancel_token.clone()
    }

    /// Stop accepting. Connections already accepted are not affected.
    pub async fn close(&self) -> Result<()> {
        self.stop.cancel();
        Ok(())
    }
}

impl fmt::Display for CustomTcpListenerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.listener.local_addr())
    }
}

impl fmt::Debug for CustomTcpListenerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sip::{
        prelude::{HeadersExt, ToTypedHeader},
        StatusCode,
    };
    use crate::transport::{
        connection::{KEEPALIVE_REQUEST, KEEPALIVE_RESPONSE},
        TransportEvent,
    };
    use epdg::NetStack;
    use std::collections::VecDeque;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
    use tokio::sync::mpsc::unbounded_channel;
    use tokio::time::timeout;

    pub(crate) const WAIT: Duration = Duration::from_secs(5);

    /// The OS stack pinned to loopback: real `TcpStreamLike` / `TcpListenerLike` values,
    /// standing in for the tunnel's.
    pub(crate) fn loopback() -> epdg::StdNetStack {
        epdg::StdNetStack::with_bind_addr(IpAddr::V4(Ipv4Addr::LOCALHOST))
    }

    /// The far end of a connection: a plain std socket, used from blocking code
    /// (`spawn_blocking`), framing SIP by Content-Length.
    pub(crate) struct Peer {
        stream: TcpStream,
        buf: Vec<u8>,
    }

    impl Peer {
        pub(crate) fn new(stream: TcpStream) -> Self {
            stream.set_read_timeout(Some(WAIT)).unwrap();
            Peer {
                stream,
                buf: Vec::new(),
            }
        }

        pub(crate) fn local_addr(&self) -> SocketAddr {
            self.stream.local_addr().unwrap()
        }

        fn fill(&mut self) -> usize {
            let mut chunk = [0u8; 4096];
            let n = self.stream.read(&mut chunk).expect("peer read");
            self.buf.extend_from_slice(&chunk[..n]);
            n
        }

        /// The next SIP message, head and body.
        pub(crate) fn read_message(&mut self) -> String {
            loop {
                if let Some(end) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&self.buf[..end]).to_string();
                    let total = end + 4 + content_length(&head);
                    if self.buf.len() >= total {
                        let message: Vec<u8> = self.buf.drain(..total).collect();
                        return String::from_utf8(message).expect("UTF-8 SIP message");
                    }
                }
                assert!(self.fill() > 0, "EOF before a complete message");
            }
        }

        pub(crate) fn read_exact(&mut self, n: usize) -> Vec<u8> {
            while self.buf.len() < n {
                assert!(self.fill() > 0, "EOF before {n} bytes");
            }
            self.buf.drain(..n).collect()
        }

        /// Wait for our side to close the stream.
        pub(crate) fn expect_eof(&mut self) {
            assert!(self.buf.is_empty(), "unread bytes before EOF");
            assert_eq!(self.fill(), 0, "expected EOF");
        }

        pub(crate) fn write(&mut self, bytes: &[u8]) {
            self.stream.write_all(bytes).unwrap();
        }
    }

    fn content_length(head: &str) -> usize {
        head.lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                let name = name.trim();
                (name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("l"))
                    .then(|| value.trim().parse().unwrap_or(0))
            })
            .unwrap_or(0)
    }

    /// The value of the first `name` header in `message`.
    pub(crate) fn header<'a>(message: &'a str, name: &str) -> Option<&'a str> {
        message.lines().find_map(|line| {
            let (n, value) = line.split_once(':')?;
            n.trim().eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    /// A 200 OK echoing `request`'s transaction headers.
    pub(crate) fn ok_for(request: &str) -> String {
        let mut reply = String::from("SIP/2.0 200 OK\r\n");
        for line in request.lines().skip(1) {
            let name = line.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
            if ["via", "from", "to", "call-id", "cseq"].contains(&name.as_str()) {
                reply.push_str(line);
                reply.push_str("\r\n");
            }
        }
        reply.push_str("Content-Length: 0\r\n\r\n");
        reply
    }

    fn register(from: SocketAddr) -> SipMessage {
        let raw = format!(
            "REGISTER sip:ims.example.test SIP/2.0\r\n\
             Via: SIP/2.0/TCP {from};branch=z9hG4bK-custom-tcp;rport\r\n\
             From: <sip:alice@ims.example.test>;tag=a1\r\n\
             To: <sip:alice@ims.example.test>\r\n\
             Call-ID: custom-tcp-register\r\n\
             CSeq: 1 REGISTER\r\n\
             Content-Length: 0\r\n\r\n"
        );
        SipMessage::try_from(raw.as_bytes()).unwrap()
    }

    /// A request from the peer whose Via names an address other than the one it comes from.
    pub(crate) const PEER_OPTIONS: &str = "OPTIONS sip:alice@ims.example.test SIP/2.0\r\n\
        Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK-peer;rport\r\n\
        From: <sip:pcscf@ims.example.test>;tag=p1\r\n\
        To: <sip:alice@ims.example.test>\r\n\
        Call-ID: custom-tcp-options\r\n\
        CSeq: 7 OPTIONS\r\n\
        Content-Length: 0\r\n\r\n";

    /// Our side through the loopback stack, the far end a std socket.
    fn connected_pair() -> (Box<dyn epdg::TcpStreamLike>, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let ours = loopback()
            .connect_tcp(listener.local_addr().unwrap(), WAIT)
            .unwrap();
        let (peer, _) = listener.accept().unwrap();
        (ours, peer)
    }

    async fn next_event(rx: &mut UnboundedReceiver<TransportEvent>) -> TransportEvent {
        timeout(WAIT, rx.recv())
            .await
            .expect("a transport event in time")
            .expect("transport channel open")
    }

    /// A REGISTER goes out framed on the stream; the peer's answer and its own request come
    /// back as `Incoming` on this connection, the request's Via updated as for TCP.
    #[tokio::test]
    async fn round_trip_frames_messages_and_marks_the_via_received() {
        let (ours, peer_stream) = connected_pair();
        let peer_addr = peer_stream.local_addr().unwrap();
        let conn = CustomTcpConnection::new(ours, None, None);
        let our_addr = conn.stream.local_addr();
        assert_eq!(conn.get_addr(), &tcp_sip_addr(our_addr));
        assert_eq!(conn.get_remote_addr(), &tcp_sip_addr(peer_addr));
        let connection = SipConnection::from(conn.clone());
        assert_eq!(connection.transport(), Transport::Tcp);
        assert!(connection.is_reliable());
        assert!(!conn.is_closed());
        assert_eq!(connection.get_remote_addr(), Some(&tcp_sip_addr(peer_addr)));

        let (tx, mut rx) = unbounded_channel();
        let serving = {
            let conn = conn.clone();
            tokio::spawn(async move { conn.serve_loop(tx).await })
        };
        let peer = tokio::task::spawn_blocking(move || {
            let mut peer = Peer::new(peer_stream);
            let register = peer.read_message();
            peer.write(ok_for(&register).as_bytes());
            peer.write(PEER_OPTIONS.as_bytes());
            (peer, register)
        });
        connection.send(register(our_addr), None).await.unwrap();
        let (peer, register) = timeout(WAIT, peer).await.unwrap().unwrap();
        assert!(register.starts_with("REGISTER sip:ims.example.test SIP/2.0\r\n"), "{register}");
        assert_eq!(header(&register, "CSeq"), Some("1 REGISTER"));

        match next_event(&mut rx).await {
            TransportEvent::Incoming(SipMessage::Response(response), SipConnection::CustomTcp(on), from) => {
                assert_eq!(response.status_code, StatusCode::OK);
                assert!(on.same_connection(&conn), "delivered with this connection");
                assert_eq!(from, tcp_sip_addr(peer_addr));
            }
            other => panic!("expected the 200 OK, got {other:?}"),
        }
        match next_event(&mut rx).await {
            TransportEvent::Incoming(SipMessage::Request(request), SipConnection::CustomTcp(on), _) => {
                assert!(on.same_connection(&conn));
                let via = request.via_header().unwrap().typed().unwrap();
                assert_eq!(via.transport, Transport::Tcp);
                assert_eq!(via.received().unwrap().unwrap(), IpAddr::V4(Ipv4Addr::LOCALHOST));
                assert_eq!(via.rport(), Some(Some(peer_addr.port())));
            }
            other => panic!("expected the peer's OPTIONS, got {other:?}"),
        }

        // The peer hangs up: EOF ends the serve loop, and the connection says it has ended
        // by the time the serve loop does (before anyone could forget it).
        drop(peer);
        let ended = timeout(WAIT, serving).await;
        assert!(matches!(ended, Ok(Ok(Ok(())))), "serve_loop did not end on EOF: {ended:?}");
        assert!(conn.is_closed());
    }

    /// A CRLFCRLF ping is answered with CRLF (RFC 5626 §3.5.1); `send_raw` carries our own.
    #[tokio::test]
    async fn a_crlf_keepalive_is_answered_and_send_raw_reaches_the_peer() {
        let (ours, peer_stream) = connected_pair();
        let conn = CustomTcpConnection::new(ours, None, None);
        let (tx, mut rx) = unbounded_channel();
        let _serving = {
            let conn = conn.clone();
            tokio::spawn(async move { conn.serve_loop(tx).await })
        };
        let peer = tokio::task::spawn_blocking(move || {
            let mut peer = Peer::new(peer_stream);
            peer.write(KEEPALIVE_REQUEST);
            let pong = peer.read_exact(KEEPALIVE_RESPONSE.len());
            let ping = peer.read_exact(KEEPALIVE_REQUEST.len());
            (pong, ping)
        });
        // Our own ping, queued behind the pong only once the pong has gone out.
        tokio::time::sleep(Duration::from_millis(100)).await;
        conn.send_raw(KEEPALIVE_REQUEST).await.unwrap();
        let (pong, ping) = timeout(WAIT, peer).await.unwrap().unwrap();
        assert_eq!(pong, KEEPALIVE_RESPONSE);
        assert_eq!(ping, KEEPALIVE_REQUEST);
        assert!(rx.try_recv().is_err(), "keepalives are not SIP messages");
    }

    /// The tunnel's verdict for every inner socket once it is dead (see custom_udp tests).
    fn tunnel_dead(reason: &str) -> io::Error {
        io::Error::new(
            io::ErrorKind::NotConnected,
            epdg::Error::Closed(reason.to_string()),
        )
    }

    /// A scripted [`epdg::TcpStreamLike`]: `read` returns the scripted results, then idles a
    /// short slice per call (`WouldBlock`) until the stream is shut down (EOF). Writes are
    /// recorded or fail as configured. Records shutdowns and its own drop.
    struct FakeStream {
        reads: Mutex<VecDeque<io::Result<Vec<u8>>>>,
        write_fails: bool,
        written: Arc<Mutex<Vec<u8>>>,
        /// How much had been written when `shutdown` was called.
        shut_down_after: Arc<Mutex<Option<usize>>>,
        dropped: Arc<AtomicBool>,
    }

    impl FakeStream {
        fn new(reads: Vec<io::Result<Vec<u8>>>, write_fails: bool) -> Self {
            FakeStream {
                reads: Mutex::new(reads.into()),
                write_fails,
                written: Arc::default(),
                shut_down_after: Arc::default(),
                dropped: Arc::default(),
            }
        }
    }

    impl epdg::TcpStreamLike for FakeStream {
        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            if let Some(next) = self.reads.lock().pop_front() {
                return next.map(|data| {
                    buf[..data.len()].copy_from_slice(&data);
                    data.len()
                });
            }
            if self.shut_down_after.lock().is_some() {
                return Ok(0);
            }
            thread::sleep(Duration::from_millis(10));
            Err(io::ErrorKind::WouldBlock.into())
        }

        fn write(&self, buf: &[u8]) -> io::Result<usize> {
            if self.write_fails {
                return Err(tunnel_dead("gateway stopped answering"));
            }
            self.written.lock().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_nodelay(&self, _: bool) -> io::Result<()> {
            Ok(())
        }

        fn local_addr(&self) -> SocketAddr {
            "127.0.0.1:5060".parse().unwrap()
        }

        fn peer_addr(&self) -> SocketAddr {
            "127.0.0.2:5060".parse().unwrap()
        }

        fn shutdown(&self) -> io::Result<()> {
            let written = self.written.lock().len();
            self.shut_down_after.lock().get_or_insert(written);
            Ok(())
        }
    }

    impl Drop for FakeStream {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    async fn eventually(what: &str, condition: impl Fn() -> bool) {
        let deadline = tokio::time::Instant::now() + WAIT;
        while !condition() {
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// What came before the tunnel died is delivered; the death (`NotConnected`) then ends
    /// the serve loop — the one exit that makes the transport layer emit `Closed`.
    #[tokio::test]
    async fn a_dead_tunnel_ends_the_serve_loop_after_delivering_what_came_before() {
        let stream = FakeStream::new(
            vec![
                Ok(PEER_OPTIONS.as_bytes().to_vec()),
                Err(tunnel_dead("gateway stopped answering")),
            ],
            false,
        );
        let conn = CustomTcpConnection::new(Box::new(stream), None, None);
        let (tx, mut rx) = unbounded_channel();
        let ended = timeout(WAIT, conn.serve_loop(tx)).await;
        assert!(matches!(ended, Ok(Ok(()))), "serve_loop did not end: {ended:?}");
        assert!(matches!(
            rx.try_recv(),
            Ok(TransportEvent::Incoming(SipMessage::Request(_), SipConnection::CustomTcp(_), _))
        ));
        assert!(rx.try_recv().is_err(), "nothing after the death");
    }

    /// A write that fails is reported to the next sender (with the tunnel's reason), and the
    /// writer shuts the stream down so the serve loop ends through its one exit.
    #[tokio::test]
    async fn a_write_error_reaches_the_next_sender_and_ends_the_connection() {
        let stream = FakeStream::new(vec![], true);
        let shut_down = stream.shut_down_after.clone();
        let conn = CustomTcpConnection::new(Box::new(stream), None, None);
        let (tx, _rx) = unbounded_channel();
        let serving = {
            let conn = conn.clone();
            tokio::spawn(async move { conn.serve_loop(tx).await })
        };
        let recorded = |result: Result<()>| match result {
            Err(crate::Error::IoError(e)) => {
                assert_eq!(e.kind(), io::ErrorKind::NotConnected);
                assert!(e.to_string().contains("gateway stopped answering"), "{e}");
            }
            other => panic!("expected the recorded write error, got {other:?}"),
        };
        // Queued, so normally `Ok`; its flush already reports the error when the writer
        // thread was quicker.
        if let Err(e) = conn.send_raw(b"OPTIONS").await {
            recorded(Err(e));
        }
        let ended = timeout(WAIT, serving).await;
        assert!(matches!(ended, Ok(Ok(Ok(())))), "serve_loop did not end: {ended:?}");
        assert!(shut_down.lock().is_some(), "the writer shut the stream down");
        assert!(conn.is_closed());
        recorded(conn.send_raw(b"OPTIONS").await);
    }

    /// `close` writes what is already queued, then shuts the stream down; both threads end
    /// (the stream is released) once the last handle is gone.
    #[tokio::test]
    async fn close_flushes_then_shuts_down_and_the_threads_end() {
        let stream = FakeStream::new(vec![], false);
        let (written, shut_down, dropped) = (
            stream.written.clone(),
            stream.shut_down_after.clone(),
            stream.dropped.clone(),
        );
        let conn = CustomTcpConnection::new(Box::new(stream), None, None);
        conn.send_raw(b"first ").await.unwrap();
        conn.send_raw(b"second").await.unwrap();
        assert!(!conn.is_closed());
        conn.close().await.unwrap();
        assert!(conn.is_closed());
        eventually("the shutdown", || shut_down.lock().is_some()).await;
        assert_eq!(written.lock().as_slice(), b"first second");
        assert_eq!(*shut_down.lock(), Some(12), "shut down after both writes");
        let e = conn.send_raw(b"late").await.unwrap_err();
        assert!(matches!(&e, crate::Error::IoError(e) if e.kind() == io::ErrorKind::BrokenPipe), "{e:?}");
        drop(conn);
        eventually("both threads to end", || dropped.load(Ordering::SeqCst)).await;
    }

    /// Dropping every handle of a connection that was never served or closed stops both
    /// threads too.
    #[tokio::test]
    async fn the_threads_end_when_the_connection_is_dropped() {
        let stream = FakeStream::new(vec![], false);
        let dropped = stream.dropped.clone();
        let conn = CustomTcpConnection::new(Box::new(stream), None, None);
        let clone = conn.clone();
        drop(conn);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!dropped.load(Ordering::SeqCst), "a handle is still alive");
        drop(clone);
        eventually("both threads to end", || dropped.load(Ordering::SeqCst)).await;
    }

    /// A connection over which nothing arrives for the idle limit closes itself — the serve
    /// loop ends (so the transport layer forgets it) and the peer reads EOF — instead of being
    /// reused for ever after its peer vanished. Anything received, a CRLF keepalive included,
    /// keeps it open.
    #[tokio::test]
    async fn a_connection_nothing_arrives_on_closes_after_the_idle_limit() {
        let (ours, peer_stream) = connected_pair();
        let conn = CustomTcpConnection::with_idle_close(ours, None, None, Duration::from_millis(500));
        let (tx, _rx) = unbounded_channel();
        let serving = {
            let conn = conn.clone();
            tokio::spawn(async move { conn.serve_loop(tx).await })
        };
        // A ping every 100 ms for 1.2 s, well past the limit.
        let peer = tokio::task::spawn_blocking(move || {
            let mut peer = Peer::new(peer_stream);
            for _ in 0..12 {
                peer.write(KEEPALIVE_REQUEST);
                assert_eq!(peer.read_exact(KEEPALIVE_RESPONSE.len()), KEEPALIVE_RESPONSE);
                std::thread::sleep(Duration::from_millis(100));
            }
            peer
        });
        let mut peer = timeout(WAIT, peer).await.unwrap().unwrap();
        assert!(!conn.is_closed(), "what arrives keeps the connection open");
        // Then silence.
        let ended = timeout(WAIT, serving).await;
        assert!(matches!(ended, Ok(Ok(Ok(())))), "serve_loop did not end: {ended:?}");
        assert!(conn.is_closed());
        timeout(WAIT, tokio::task::spawn_blocking(move || peer.expect_eof()))
            .await
            .unwrap()
            .unwrap();
    }

    /// A cancelled token ends the serve loop like custom UDP's.
    #[tokio::test]
    async fn the_cancel_token_ends_the_serve_loop() {
        let token = CancellationToken::new();
        let conn = CustomTcpConnection::new(
            Box::new(FakeStream::new(vec![], false)),
            Some(tcp_sip_addr("127.0.0.1:5060".parse().unwrap())),
            Some(token.clone()),
        );
        let (tx, _rx) = unbounded_channel();
        let serving = {
            let conn = conn.clone();
            tokio::spawn(async move { conn.serve_loop(tx).await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        token.cancel();
        let ended = timeout(WAIT, serving).await;
        assert!(matches!(ended, Ok(Ok(Ok(())))), "serve_loop did not end: {ended:?}");
    }
}
