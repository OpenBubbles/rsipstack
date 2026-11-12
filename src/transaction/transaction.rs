use super::endpoint::EndpointInnerRef;
use super::key::TransactionKey;
use super::{SipConnection, TransactionState, TransactionTimer, TransactionType};
use crate::dialog::DialogId;
use crate::sip::{
    ContentLength, HasHeaders, Header, HeadersExt, Method, Request, Response, SipMessage,
    StatusCode, StatusCodeKind, Transport,
};
use crate::transaction::key::TransactionRole;
use crate::transaction::{make_tag, INITIAL_RSEQ};
use crate::transport::SipAddr;
use crate::{Error, Result};
use std::collections::VecDeque;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tracing::{debug, trace, warn};

pub type TransactionEventReceiver = UnboundedReceiver<TransactionEvent>;
pub type TransactionEventSender = UnboundedSender<TransactionEvent>;

/// SIP Transaction Events
///
/// `TransactionEvent` represents the various events that can occur during
/// a SIP transaction's lifecycle. These events drive the transaction state machine
/// and coordinate between the transaction layer and transaction users.
///
/// # Events
///
/// * `Received` - A SIP message was received for this transaction
/// * `Timer` - A transaction timer has fired
/// * `Respond` - Request to send a response (server transactions only)
/// * `Terminate` - Request to terminate the transaction
///
/// # Examples
///
/// ```rust,no_run
/// use rsipstack::transaction::transaction::TransactionEvent;
/// use rsipstack::sip::SipMessage;
///
/// # fn handle_event(event: TransactionEvent) {
/// match event {
///     TransactionEvent::Received(msg, conn) => {
///         // Process received SIP message
///     },
///     TransactionEvent::Timer(timer) => {
///         // Handle timer expiration
///     },
///     TransactionEvent::Respond(response) => {
///         // Send response
///     },
///     TransactionEvent::Terminate(key) => {
///         // Clean up transaction
///     }
/// }
/// # }
/// ```
pub enum TransactionEvent {
    Received(SipMessage, Option<SipConnection>),
    Timer(TransactionTimer),
    Respond(Response),
    Terminate(TransactionKey),
}

/// Create a no-op TU sender (drops all messages).
///
/// Useful for restoring dialogs after restart when a real transaction-user channel
/// is not available yet.
pub fn transaction_event_sender_noop() -> TransactionEventSender {
    let (tx, mut rx) = unbounded_channel::<TransactionEvent>();
    tokio::spawn(async move {
        while let Some(_ev) = rx.recv().await {
            // drop
        }
    });
    tx
}
/// SIP Transaction
///
/// `Transaction` implements the SIP transaction layer as defined in RFC 3261.
/// A transaction consists of a client transaction (sends requests) or server
/// transaction (receives requests) that handles the reliable delivery of SIP
/// messages and manages retransmissions and timeouts.
///
/// # Key Features
///
/// * Automatic retransmission handling
/// * Timer management per RFC 3261
/// * State machine implementation
/// * Reliable message delivery
/// * Connection management
///
/// # Transaction Types
///
/// * `ClientInvite` - Client INVITE transaction
/// * `ClientNonInvite` - Client non-INVITE transaction
/// * `ServerInvite` - Server INVITE transaction
/// * `ServerNonInvite` - Server non-INVITE transaction
///
/// # State Machine
///
/// Transactions follow the state machines defined in RFC 3261:
/// * Calling → Trying → Proceeding → Completed → Terminated
/// * Additional states for INVITE transactions: Confirmed
///
/// # Examples
///
/// ```rust,no_run
/// use rsipstack::transaction::{
///     transaction::Transaction,
///     key::{TransactionKey, TransactionRole}
/// };
/// use rsipstack::sip::SipMessage;
///
/// # async fn example() -> rsipstack::Result<()> {
/// # let endpoint_inner = todo!();
/// # let connection = None;
/// // Create a mock request
/// let request = rsipstack::sip::Request {
///     method: rsipstack::sip::Method::Register,
///     uri: rsipstack::sip::Uri::try_from("sip:example.com")?,
///     headers: vec![
///         rsipstack::sip::Header::Via("SIP/2.0/UDP example.com:5060;branch=z9hG4bKnashds".into()),
///         rsipstack::sip::Header::CSeq("1 REGISTER".into()),
///         rsipstack::sip::Header::From("Alice <sip:alice@example.com>;tag=1928301774".into()),
///         rsipstack::sip::Header::CallId("a84b4c76e66710@pc33.atlanta.com".into()),
///     ].into(),
///     version: rsipstack::sip::Version::V2,
///     body: Default::default(),
/// };
/// let key = TransactionKey::from_request(&request, TransactionRole::Client)?;
///
/// // Create a client transaction
/// let mut transaction = Transaction::new_client(
///     key,
///     request,
///     endpoint_inner,
///     connection
/// );
///
/// // Send the request
/// transaction.send().await?;
///
/// // Receive responses
/// while let Some(message) = transaction.receive().await {
///     match message {
///         SipMessage::Response(response) => {
///             // Handle response
///         },
///         _ => {}
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Timer Handling
///
/// The transaction automatically manages SIP timers:
/// * Timer A: Retransmission timer for unreliable transports
/// * Timer B: Transaction timeout timer
/// * Timer D: Wait time for response retransmissions
/// * Timer E: Non-INVITE retransmission timer
/// * Timer F: Non-INVITE transaction timeout
/// * Timer G: INVITE response retransmission timer
/// * Timer K: Wait time for ACK
///
/// # Reliable Provisional Responses (RFC 3262)
///
/// A server INVITE transaction natively handles reliable provisional
/// responses. A `101`-`199` response handed to [`Transaction::respond`] that
/// carries `Require: 100rel` is sent reliably: the transaction assigns an
/// `RSeq` starting at [`INITIAL_RSEQ`] (1) and incrementing by one (a supplied
/// RSeq is honoured only for the first reliable provisional response of the
/// transaction; afterwards the transaction's own counter wins), retransmits it
/// on unreliable transports with an interval starting at T1 and doubling, runs
/// a 64*T1 PRACK timeout on every transport, serializes reliable provisionals
/// (a second one is queued until the first is PRACKed), and holds a 2xx while
/// an unacknowledged reliable provisional carried a body. A matching PRACK is
/// fed to the transaction as `TransactionEvent::Received` (the dialog layer
/// does this); on timeout the INVITE is rejected with `500 Server Internal
/// Error` and that response is returned from [`Transaction::receive`].
///
/// Only the initial (dialog-creating) INVITE is covered: when the INVITE's To
/// header already carries a tag (re-INVITE) the `100rel` headers are stripped
/// with a warning and the response is sent unreliably. Likewise, when the
/// INVITE advertised neither `Supported: 100rel` nor `Require: 100rel` the
/// provisional response is downgraded to an unreliable one (RFC 3262 §3 MUST
/// NOT).
pub struct Transaction {
    pub transaction_type: TransactionType,
    pub key: TransactionKey,
    pub original: Request,
    pub destination: Option<SipAddr>,
    pub state: TransactionState,
    pub endpoint_inner: EndpointInnerRef,
    pub connection: Option<SipConnection>,
    pub last_response: Option<Response>,
    pub last_ack: Option<Request>,
    pub tu_receiver: TransactionEventReceiver,
    pub tu_sender: TransactionEventSender,
    pub timer_a: Option<u64>,
    pub timer_b: Option<u64>,
    pub timer_c: Option<u64>,
    pub timer_d: Option<u64>,
    pub timer_k: Option<u64>, // server invite only
    pub timer_g: Option<u64>, // server invite only
    retransmission: bool,
    is_cleaned_up: bool,
    /// Next RSeq to assign to a reliable provisional response (RFC 3262 §3).
    /// Initialized lazily from [`INITIAL_RSEQ`] (1), or from the value the
    /// dialog layer put on the first reliable provisional response. Once set,
    /// the transaction is authoritative: a supplied RSeq that is not the
    /// expected next value is replaced (RSeq must increase by exactly one per
    /// transaction, and the stale-timer guards rely on every reliable
    /// provisional carrying a distinct RSeq).
    rel1xx_next_rseq: Option<u32>,
    /// The reliable provisional response currently on the wire and not yet
    /// acknowledged by a matching PRACK.
    rel1xx_unacked: Option<ReliableProvisional>,
    /// Responses held back while `rel1xx_unacked` is outstanding: further
    /// reliable provisional responses (RFC 3262 §3: one at a time) and a 2xx
    /// that must wait for a body-carrying provisional to be acknowledged.
    rel1xx_pending: VecDeque<Response>,
    timer_rel1xx: Option<u64>,
    timer_rel1xx_timeout: Option<u64>,
    /// To tag of the first non-100 response sent by this server INVITE
    /// transaction; reused for every later locally generated response (487
    /// after CANCEL, the RFC 3262 timeout 500) so they all belong to the same
    /// early dialog.
    local_to_tag: Option<String>,
}

/// A reliable provisional response (RFC 3262) that has been sent but not yet
/// acknowledged by a matching PRACK.
struct ReliableProvisional {
    /// The response as handed to `respond()` (before the message inspector).
    response: Response,
    rseq: u32,
    cseq: u32,
    method: Method,
    /// Whether the response carried a body. RFC 3262 §3 only requires a 2xx to
    /// be held behind provisional responses that carried a *session
    /// description*; holding behind any body is a conservative superset.
    has_body: bool,
    call_id: String,
    from_tag: Option<String>,
    to_tag: Option<String>,
}

impl ReliableProvisional {
    /// RFC 3262 §3: a matching PRACK is one within the same dialog as the
    /// response whose RAck matches the response's RSeq and CSeq.
    fn matches_prack(&self, prack: &Request) -> bool {
        let Some((rseq, cseq, method)) = prack.rack_value() else {
            return false;
        };
        if rseq != self.rseq || cseq != self.cseq || method != self.method {
            return false;
        }
        let call_id = prack.call_id_header().map(|h| h.value().to_string()).ok();
        let from_tag = prack
            .from_header()
            .ok()
            .and_then(|h| h.tag().ok().flatten())
            .map(|t| t.value().to_string());
        let to_tag = prack
            .to_header()
            .ok()
            .and_then(|h| h.tag().ok().flatten())
            .map(|t| t.value().to_string());
        call_id.as_deref() == Some(self.call_id.as_str())
            && from_tag == self.from_tag
            && to_tag == self.to_tag
    }
}

fn is_rseq_header(h: &Header) -> bool {
    match h {
        Header::RSeq(_) => true,
        Header::Other(name, _) if name.eq_ignore_ascii_case("RSeq") => true,
        _ => false,
    }
}

/// Remove every `RSeq` header (typed or untyped). Returns whether one was removed.
pub(crate) fn remove_rseq_headers(headers: &mut Vec<Header>) -> bool {
    let before = headers.len();
    headers.retain(|h| !is_rseq_header(h));
    headers.len() != before
}

/// `value` without the comma-separated `token` (case-insensitive), or `None`
/// when the token is not present. The remaining pieces are kept verbatim —
/// only the removed token and the resulting stray separator go away — so the
/// application's own spacing is preserved.
fn without_token(value: &str, token: &str) -> Option<String> {
    if !value.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)) {
        return None;
    }
    let kept: Vec<&str> = value
        .split(',')
        .filter(|t| !t.trim().eq_ignore_ascii_case(token))
        .collect();
    Some(kept.join(",").trim().to_string())
}

/// Remove `token` from every `Require` header (typed or untyped), dropping a
/// header that becomes empty. Headers are never reformatted: the remaining
/// tokens keep their original text and separators. Returns whether anything
/// was removed.
pub(crate) fn strip_require_token(headers: &mut Vec<Header>, token: &str) -> bool {
    let mut removed = false;
    let mut out = Vec::with_capacity(headers.len());
    for header in headers.drain(..) {
        let rewritten = match &header {
            Header::Require(v) => without_token(v.value(), token).map(|nv| {
                let empty = nv.is_empty();
                (empty, Header::Require(nv.into()))
            }),
            Header::Other(name, v) if name.eq_ignore_ascii_case("Require") => {
                without_token(v, token).map(|nv| {
                    let empty = nv.is_empty();
                    (empty, Header::Other(name.clone(), nv))
                })
            }
            _ => None,
        };
        match rewritten {
            Some((true, _)) => removed = true,
            Some((false, h)) => {
                removed = true;
                out.push(h);
            }
            None => out.push(header),
        }
    }
    *headers = out;
    removed
}

/// The transport a request's top `Via` must name when it goes out over `connection`, for
/// the connection kinds whose wire transport is unambiguous. `None` leaves the Via alone: a
/// channel's transport is nominal, a WebSocket connection cannot tell WS from WSS, and
/// listeners do not send.
fn via_transport_of(connection: &SipConnection) -> Option<Transport> {
    match connection {
        SipConnection::Udp(_) | SipConnection::CustomUdp(_) => Some(Transport::Udp),
        SipConnection::Tcp(_) | SipConnection::CustomTcp(_) => Some(Transport::Tcp),
        #[cfg(feature = "rustls")]
        SipConnection::Tls(_) => Some(Transport::Tls),
        _ => None,
    }
}

/// Byte range of the transport token in one `Via` value (`SIP/2.0/UDP host...`, RFC 3261
/// §20.42: after the second `/`, with optional whitespace around the slashes, up to the
/// whitespace before sent-by).
fn via_transport_span(value: &str) -> Option<(usize, usize)> {
    let (second_slash, _) = value.match_indices('/').nth(1)?;
    let rest = &value[second_slash + 1..];
    let start = second_slash + 1 + (rest.len() - rest.trim_start().len());
    let len = value[start..]
        .find(char::is_whitespace)
        .unwrap_or(value.len() - start);
    (len > 0).then_some((start, start + len))
}

/// Make the top `Via` of `msg` name `transport` — the transport the request actually
/// leaves on (RFC 3261 §18.1.1). Only that token changes: branch, sent-by and every
/// parameter keep their exact text, so the transaction still matches its responses. A Via
/// that already names `transport`, or whose transport cannot be read, is left alone.
pub(crate) fn align_via_transport(msg: &mut Request, transport: Transport) {
    let Ok(via) = msg.via_header_mut() else {
        return;
    };
    let differs = via.first_value().ok().and_then(|first| {
        let (start, end) = via_transport_span(first.value())?;
        let current: Transport = first.value()[start..end].parse().ok()?;
        Some(current != transport)
    });
    if differs != Some(true) {
        return;
    }
    let result = via.update_first_value(|first| {
        let value = first.value();
        Ok(match via_transport_span(value) {
            Some((start, end)) => crate::sip::headers::untyped::Via::new(format!(
                "{}{}{}",
                &value[..start],
                transport,
                &value[end..]
            )),
            None => first,
        })
    });
    if let Err(e) = result {
        debug!(error = %e, %transport, "cannot set the Via transport");
    }
}

/// Remove the `100rel` option tag from every `Require` header (dropping the
/// header when it becomes empty) and remove every `RSeq` header, without
/// reformatting anything else. Returns whether anything was removed.
fn strip_reliable_headers(response: &mut Response) -> bool {
    let removed_rseq = remove_rseq_headers(&mut response.headers.0);
    let removed_token = strip_require_token(&mut response.headers.0, "100rel");
    removed_rseq || removed_token
}

impl Transaction {
    fn new(
        transaction_type: TransactionType,
        key: TransactionKey,
        original: Request,
        connection: Option<SipConnection>,
        endpoint_inner: EndpointInnerRef,
    ) -> Self {
        let (tu_sender, tu_receiver) = unbounded_channel();
        let state = if matches!(
            transaction_type,
            TransactionType::ServerInvite | TransactionType::ServerNonInvite
        ) {
            TransactionState::Trying
        } else {
            TransactionState::Nothing
        };
        trace!(%key, %state, "transaction created");
        let tx = Self {
            transaction_type,
            endpoint_inner,
            connection,
            key,
            original,
            destination: None,
            state,
            last_response: None,
            last_ack: None,
            timer_a: None,
            timer_b: None,
            timer_c: None,
            timer_d: None,
            timer_k: None,
            timer_g: None,
            retransmission: true,
            tu_receiver,
            tu_sender,
            is_cleaned_up: false,
            rel1xx_next_rseq: None,
            rel1xx_unacked: None,
            rel1xx_pending: VecDeque::new(),
            timer_rel1xx: None,
            timer_rel1xx_timeout: None,
            local_to_tag: None,
        };
        tx.endpoint_inner
            .attach_transaction(&tx.key, tx.tu_sender.clone());
        tx
    }

    pub fn new_client(
        key: TransactionKey,
        original: Request,
        endpoint_inner: EndpointInnerRef,
        connection: Option<SipConnection>,
    ) -> Self {
        let tx_type = match original.method {
            Method::Invite => TransactionType::ClientInvite,
            _ => TransactionType::ClientNonInvite,
        };
        Transaction::new(tx_type, key, original, connection, endpoint_inner)
    }

    pub fn new_server(
        key: TransactionKey,
        original: Request,
        endpoint_inner: EndpointInnerRef,
        connection: Option<SipConnection>,
    ) -> Self {
        let tx_type = match original.method {
            Method::Invite | Method::Ack => TransactionType::ServerInvite,
            _ => TransactionType::ServerNonInvite,
        };
        Transaction::new(tx_type, key, original, connection, endpoint_inner)
    }
    // send client request
    pub async fn send(&mut self) -> Result<()> {
        match self.transaction_type {
            TransactionType::ClientInvite | TransactionType::ClientNonInvite => {}
            _ => {
                return Err(Error::TransactionError(
                    "send is only valid for client transactions".to_string(),
                    self.key.clone(),
                ));
            }
        }

        self.replace_ended_stream().await;

        let lookup_result = if self.connection.is_none() {
            let target_uri = self.resolve_target_uri().await?;

            Some(
                self.endpoint_inner
                    .transport_layer
                    .lookup(&target_uri, Some(&self.key))
                    .await,
            )
        } else {
            None
        };

        // Apply successful lookup result before before_send
        // so inspectors see the resolved destination address
        if let Some(Ok((connection, resolved_addr))) = &lookup_result {
            self.connection.replace(connection.clone());
            self.destination.replace(resolved_addr.clone());
        }

        // RFC 5626 flow affinity: when the request is bound to an existing
        // reliable connection (e.g. a WebSocket/WSS flow reused for in-dialog
        // requests), no transport lookup happens and `destination` would stay
        // None. Inspectors (sipflow src/dst recording) and senders need the
        // real peer address, so derive it from the flow itself instead of
        // falling back to the unresolvable Request-URI (RFC 7118 `.invalid`
        // contacts) or a wildcard listener default.
        if self.destination.is_none() {
            if let Some(connection) = self.connection.as_ref() {
                if connection.is_reliable() {
                    if let Some(remote_addr) = connection.get_remote_addr() {
                        debug!(key = %self.key, destination = %remote_addr, "destination from affinity connection");
                        self.destination.replace(remote_addr.clone());
                    }
                }
            }
        }

        // The top Via names the transport the request leaves on. One built from the
        // endpoint's first address can name another (a TCP listener listed before the UDP
        // connection actually used, say); fixed before the inspector sees the request.
        self.align_original_via();

        let content_length_header =
            Header::ContentLength(ContentLength::from(self.original.body().len() as u32));
        self.original
            .headers_mut()
            .unique_push(content_length_header);

        let message = if let Some(ref inspector) = self.endpoint_inner.message_inspector {
            inspector.before_send(self.original.to_owned().into(), self.destination.as_ref())
        } else {
            self.original.to_owned().into()
        };

        // Before the transition: Timer A is armed from the connection finally chosen.
        let message = self.select_transport_by_size(message).await;

        // Try to send if we have a connection; log errors instead of returning
        // so the transaction always enters the state machine (Calling) and
        // timers (Timer A / Timer B) handle retries and timeouts.
        if let Some(connection) = self.connection.as_ref() {
            if let Err(e) = connection.send(message, self.destination.as_ref()).await {
                warn!(key = %self.key, error = %e, "send failed");
            }
        } else {
            debug!(key = %self.key, "no connection, will retry on timer");
        }

        // Always transition to Calling — the transaction enters the state machine
        // even when transport is unavailable. Timer A will retry the send (and
        // redo the transport lookup if needed), and Timer B handles timeout.
        self.transition(TransactionState::Calling).map(|_| ())
    }

    /// RFC 3261 §18.1.1 for an outgoing request: one that would go over an unreliable
    /// transport but whose final size (after the inspector) is above the transport layer's
    /// `large_message_threshold` goes over TCP to the same destination instead, when a
    /// stream connector is set; `self.connection` becomes that connection and
    /// `self.destination` is kept. When no TCP connection can be had the request stays on
    /// UDP (the RFC's fallback). Either way the top Via of `message` and of `self.original`
    /// (which retransmissions, the non-2xx ACK and authentication retries are built from) is
    /// then made to name the transport of the connection used.
    async fn select_transport_by_size(&mut self, mut message: SipMessage) -> SipMessage {
        let transport_layer = &self.endpoint_inner.transport_layer;
        let unreliable = self
            .connection
            .as_ref()
            .is_some_and(|connection| !connection.is_reliable());
        if unreliable && transport_layer.has_stream_connector() {
            let size = message.to_bytes().len();
            let threshold = transport_layer.large_message_threshold();
            if size > threshold {
                // Where the UDP send would go: the resolved destination, else the Request-URI.
                let target = self.destination.clone().or_else(|| {
                    SipConnection::get_destination(&message)
                        .ok()
                        .map(SipAddr::from)
                });
                match target {
                    Some(target) => match transport_layer.reliable_connection_for(&target).await {
                        Ok(connection) => {
                            debug!(key = %self.key, size, threshold, %connection, "request above the UDP size threshold; sending it over TCP (RFC 3261 §18.1.1)");
                            self.connection = Some(connection);
                        }
                        Err(e) => {
                            warn!(key = %self.key, size, threshold, error = %e, "no TCP connection for a large request; sending it over UDP (RFC 3261 §18.1.1)");
                        }
                    },
                    None => {
                        warn!(key = %self.key, size, threshold, "large request without a destination address; sending it over UDP");
                    }
                }
            }
        }
        if let Some(transport) = self.connection.as_ref().and_then(via_transport_of) {
            if let SipMessage::Request(request) = &mut message {
                align_via_transport(request, transport);
            }
            align_via_transport(&mut self.original, transport);
        }
        message
    }

    /// A request bound to a stream connection that has ended since it was chosen — a CANCEL
    /// riding its INVITE's connection (RFC 3261 §9.1), an authentication retry riding the
    /// connection of the request it retries — goes over a new connection to the same remote
    /// (RFC 3261 §18.1.1: a closed connection is reopened) rather than into the dead one,
    /// where nothing but Timer B would end the transaction. When no new connection can be
    /// had, the request is unbound and takes the transport lookup like any other.
    async fn replace_ended_stream(&mut self) {
        let remote = match self.connection.as_ref() {
            Some(SipConnection::CustomTcp(stream)) if stream.is_closed() => {
                crate::transport::stream::StreamConnection::get_remote_addr(stream).clone()
            }
            _ => return,
        };
        let transport_layer = &self.endpoint_inner.transport_layer;
        match transport_layer.reliable_connection_for(&remote).await {
            Ok(connection) => {
                debug!(key = %self.key, %connection, "the request's TCP connection has ended; sending it over a new one");
                self.connection = Some(connection);
            }
            Err(e) => {
                warn!(key = %self.key, %remote, error = %e, "the request's TCP connection has ended and no new one could be opened; looking up a transport");
                self.connection = None;
            }
        }
    }

    /// Make the top Via of `self.original` name the transport of `self.connection`.
    fn align_original_via(&mut self) {
        if let Some(transport) = self.connection.as_ref().and_then(via_transport_of) {
            align_via_transport(&mut self.original, transport);
        }
    }

    /// Resolve the target URI for sending a request.
    ///
    /// Uses the same rule as `send()`: if `self.destination` is set, use it;
    /// otherwise consult the locator, then fall back to the request URI.
    /// Resolve the target URI for sending a request.
    ///
    /// Priority: self.destination (pre-set by dialog) >
    /// Request::destination() (first Route or request URI) + locator fallback.
    async fn resolve_target_uri(&self) -> Result<SipAddr> {
        match &self.destination {
            Some(addr) => Ok(addr.clone()),
            None => {
                let dest = self.original.destination();
                if let Some(locator) = self.endpoint_inner.locator.as_ref() {
                    locator.locate(&dest).await
                } else {
                    SipAddr::try_from(&dest)
                }
            }
        }
    }

    pub async fn reply_with(
        &mut self,
        status_code: StatusCode,
        headers: Vec<Header>,
        body: Option<Vec<u8>>,
    ) -> Result<()> {
        match status_code.kind() {
            StatusCodeKind::Provisional => {}
            _ => {
                let to = self.original.to_header()?;
                if to.tag()?.is_none() {
                    // Reuse the tag already sent on a provisional response (e.g. a
                    // reliable 183) so the final belongs to the same early dialog.
                    let tag = self
                        .local_to_tag
                        .clone()
                        .map(Into::into)
                        .unwrap_or_else(make_tag);
                    self.original
                        .headers
                        .unique_push(to.clone().with_tag(tag).into());
                }
            }
        }
        let mut resp = self
            .endpoint_inner
            .make_response(&self.original, status_code, body);
        resp.headers.extend(headers);
        self.respond(resp).await
    }
    /// Quick reply with status code
    pub async fn reply(&mut self, status_code: StatusCode) -> Result<()> {
        self.reply_with(status_code, vec![], None).await
    }
    /// Send a server response.
    ///
    /// For server INVITE transactions this is RFC 3262 aware — see the
    /// "Reliable Provisional Responses" section of [`Transaction`]. A reliable
    /// provisional response or a 2xx may be *queued* rather than sent; in that
    /// case `Ok(())` is returned and the response goes out once the outstanding
    /// reliable provisional response is acknowledged.
    pub async fn respond(&mut self, response: Response) -> Result<()> {
        match self.transaction_type {
            TransactionType::ServerInvite => self.respond_invite(response).await,
            TransactionType::ServerNonInvite => self.respond_plain(response).await,
            _ => Err(Error::TransactionError(
                "respond is only valid for server transactions".to_string(),
                self.key.clone(),
            )),
        }
    }

    /// RFC 3262 aware response path for server INVITE transactions.
    async fn respond_invite(&mut self, mut response: Response) -> Result<()> {
        match response.status_code.kind() {
            StatusCodeKind::Provisional => {
                if response.status_code == StatusCode::Trying {
                    if strip_reliable_headers(&mut response) {
                        warn!(
                            key = %self.key,
                            "100 Trying is never reliable (RFC 3262 §3); removed Require: 100rel / RSeq"
                        );
                    }
                    return self.respond_plain(response).await;
                }
                if !response.header_contains_token("Require", "100rel") {
                    // Plain provisional response: sent immediately, never tracked.
                    if strip_reliable_headers(&mut response) {
                        warn!(
                            key = %self.key,
                            "RSeq without Require: 100rel is meaningless; removed"
                        );
                    }
                    return self.respond_plain(response).await;
                }
                if !(self.original.header_contains_token("Supported", "100rel")
                    || self.original.header_contains_token("Require", "100rel"))
                {
                    // RFC 3262 §3: "If the request did not include either a
                    // Supported or Require header field indicating this feature,
                    // the UAS MUST NOT send the provisional response reliably."
                    strip_reliable_headers(&mut response);
                    warn!(
                        key = %self.key,
                        "UAC did not advertise 100rel; sending the provisional response unreliably (RFC 3262 §3)"
                    );
                    return self.respond_plain(response).await;
                }
                if self.original_to_has_tag() {
                    // RFC 3262 §3 / scope: only the initial (dialog-creating) INVITE
                    // gets reliable provisional responses.
                    strip_reliable_headers(&mut response);
                    warn!(
                        key = %self.key,
                        "100rel on an in-dialog (re-)INVITE is not supported; sending the provisional response unreliably"
                    );
                    return self.respond_plain(response).await;
                }
                if self.rel1xx_unacked.is_some() || !self.rel1xx_pending.is_empty() {
                    // RFC 3262 §3: MUST NOT send a second reliable provisional
                    // response until the first is acknowledged — queue it.
                    self.can_transition(&TransactionState::Proceeding)?;
                    debug!(
                        key = %self.key,
                        status = %response.status_code,
                        queued = self.rel1xx_pending.len() + 1,
                        "queueing reliable provisional response until the outstanding one is acknowledged"
                    );
                    self.rel1xx_pending.push_back(response);
                    return Ok(());
                }
                self.send_reliable_provisional(response).await
            }
            StatusCodeKind::Successful => {
                if strip_reliable_headers(&mut response) {
                    warn!(
                        key = %self.key,
                        "Require: 100rel / RSeq are only valid on provisional responses; removed from 2xx"
                    );
                }
                let unacked_has_body = self
                    .rel1xx_unacked
                    .as_ref()
                    .map(|u| u.has_body)
                    .unwrap_or(false);
                if unacked_has_body || !self.rel1xx_pending.is_empty() {
                    // RFC 3262 §3: MUST NOT send a 2xx while a reliable provisional
                    // response carrying a session description is unacknowledged.
                    // A 2xx also never overtakes a queued reliable provisional.
                    self.can_transition(&TransactionState::Completed)?;
                    debug!(
                        key = %self.key,
                        queued = self.rel1xx_pending.len() + 1,
                        "holding 2xx until reliable provisional responses are acknowledged"
                    );
                    self.rel1xx_pending.push_back(response);
                    return Ok(());
                }
                let result = self.respond_plain(response).await;
                self.finish_reliable_provisionals();
                result
            }
            _ => {
                if strip_reliable_headers(&mut response) {
                    warn!(
                        key = %self.key,
                        "Require: 100rel / RSeq are only valid on provisional responses; removed from final response"
                    );
                }
                let result = self.respond_plain(response).await;
                self.finish_reliable_provisionals();
                result
            }
        }
    }

    /// Send a response without any RFC 3262 bookkeeping: state check,
    /// inspector, `last_response`, transport send, state transition.
    async fn respond_plain(&mut self, response: Response) -> Result<()> {
        let new_state = match response.status_code.kind() {
            StatusCodeKind::Provisional => match response.status_code {
                StatusCode::Trying => TransactionState::Trying,
                _ => TransactionState::Proceeding,
            },
            _ => match self.transaction_type {
                TransactionType::ServerInvite => TransactionState::Completed,
                _ => TransactionState::Terminated,
            },
        };
        // check an transition to new state
        self.can_transition(&new_state)?;
        self.remember_local_to_tag(&response);

        let connection = self.connection.as_ref().ok_or(Error::TransactionError(
            "no connection found".to_string(),
            self.key.clone(),
        ))?;

        let response = self.inspect_before_send(response.into());
        trace!(key = %self.key, response = %response, "responding");

        match response.clone() {
            SipMessage::Response(resp) => self.last_response.replace(resp),
            _ => None,
        };
        connection.send(response, self.destination.as_ref()).await?;
        self.transition(new_state).map(|_| ())
    }

    /// Send a reliable provisional response (RFC 3262 §3): assign the RSeq,
    /// send it, remember it as unacknowledged and arm the retransmission
    /// (unreliable transports only) and 64*T1 timeout timers.
    ///
    /// Unlike [`Transaction::respond_plain`], a transport error does not abort:
    /// the timers are armed regardless so that retransmission or the timeout
    /// eventually resolve the INVITE instead of leaving it hanging.
    async fn send_reliable_provisional(&mut self, mut response: Response) -> Result<()> {
        self.can_transition(&TransactionState::Proceeding)?;
        let connection = self.connection.clone().ok_or(Error::TransactionError(
            "no connection found".to_string(),
            self.key.clone(),
        ))?;

        // RFC 3261 §8.2.6.2: every non-100 response carries a To tag, and a
        // reliable provisional response creates an early dialog.
        let to = response.to_header()?.clone();
        if to.tag()?.is_none() {
            let tag: String = self
                .local_to_tag
                .clone()
                .unwrap_or_else(|| make_tag().value().to_string());
            response.headers.unique_push(to.with_tag(tag.into()).into());
        }

        // RSeq: the dialog layer (the single generator for dialog users) may
        // already have assigned one; otherwise generate it here.
        // Once this transaction has assigned an RSeq it is authoritative: RFC
        // 3262 §3 requires +1 per reliable provisional response, and the
        // stale-timer guards in `on_timer` rely on every reliable provisional
        // of a transaction carrying a distinct RSeq.
        let rseq = match response.rseq_value() {
            Some(supplied) => match self.rel1xx_next_rseq {
                Some(expected) if expected != supplied => {
                    warn!(
                        key = %self.key,
                        supplied,
                        expected,
                        "supplied RSeq is not the expected next value; using the expected value (RFC 3262 §3: RSeq increments by exactly one per transaction)"
                    );
                    expected
                }
                _ => supplied,
            },
            None => self.rel1xx_next_rseq.unwrap_or(INITIAL_RSEQ),
        };
        let next_rseq = match rseq.checked_add(1) {
            Some(next) => next,
            None => {
                // RFC 3262 §3: RSeq numbers MUST NOT wrap around.
                strip_reliable_headers(&mut response);
                warn!(
                    key = %self.key,
                    rseq,
                    "RSeq space exhausted; sending the provisional response unreliably"
                );
                return self.respond_plain(response).await;
            }
        };
        response.headers.retain(|h| !is_rseq_header(h));
        response
            .headers
            .unique_push(Header::RSeq(rseq.to_string().into()));
        self.rel1xx_next_rseq = Some(next_rseq);

        let cseq_header = response.cseq_header()?;
        let cseq = cseq_header.seq()?;
        let method = cseq_header.method()?;
        let call_id = response.call_id_header()?.value().to_string();
        let from_tag = response
            .from_header()?
            .tag()?
            .map(|t| t.value().to_string());
        let to_tag = response.to_header()?.tag()?.map(|t| t.value().to_string());
        let unacked = ReliableProvisional {
            response: response.clone(),
            rseq,
            cseq,
            method,
            has_body: !response.body.is_empty(),
            call_id,
            from_tag,
            to_tag,
        };

        self.remember_local_to_tag(&response);
        let message = self.inspect_before_send(response.into());
        trace!(key = %self.key, response = %message, rseq, "responding reliably");
        if let SipMessage::Response(ref resp) = message {
            self.last_response.replace(resp.clone());
        }
        if let Err(e) = connection.send(message, self.destination.as_ref()).await {
            warn!(key = %self.key, error = %e, rseq, "reliable provisional response send failed");
        }

        self.cancel_rel1xx_timers();
        self.rel1xx_unacked.replace(unacked);
        if !connection.is_reliable() {
            let t1 = self.endpoint_inner.option.t1;
            let timer = self.endpoint_inner.timers.timeout(
                t1,
                TransactionTimer::TimerRel1xx(self.key.clone(), rseq, t1),
            );
            self.timer_rel1xx.replace(timer);
        }
        let timer = self.endpoint_inner.timers.timeout(
            self.endpoint_inner.option.t1x64,
            TransactionTimer::TimerRel1xxTimeout(self.key.clone(), rseq),
        );
        self.timer_rel1xx_timeout.replace(timer);
        self.transition(TransactionState::Proceeding).map(|_| ())
    }

    /// Flush queued responses after the outstanding reliable provisional
    /// response was acknowledged (or after one was just sent).
    async fn drain_rel1xx_pending(&mut self) {
        while let Some(front) = self.rel1xx_pending.front() {
            let is_final = front.status_code.kind() != StatusCodeKind::Provisional;
            if !is_final {
                if self.rel1xx_unacked.is_some() {
                    break;
                }
                let response = self.rel1xx_pending.pop_front().expect("front exists");
                if let Err(e) = self.send_reliable_provisional(response).await {
                    warn!(key = %self.key, error = %e, "failed to send queued reliable provisional response");
                }
                continue;
            }
            let blocked = self
                .rel1xx_unacked
                .as_ref()
                .map(|u| u.has_body)
                .unwrap_or(false);
            if blocked {
                break;
            }
            let response = self.rel1xx_pending.pop_front().expect("front exists");
            debug!(key = %self.key, status = %response.status_code, "sending held final response");
            if let Err(e) = self.respond_plain(response).await {
                warn!(key = %self.key, error = %e, "failed to send held final response");
            }
            self.finish_reliable_provisionals();
            break;
        }
    }

    /// A final response was sent: stop retransmitting the unacknowledged
    /// reliable provisional response (RFC 3262 §3 SHOULD NOT) and drop anything
    /// still queued (MUST NOT send new reliable provisionals after a final).
    fn finish_reliable_provisionals(&mut self) {
        self.cancel_rel1xx_timers();
        self.rel1xx_unacked.take();
        if !self.rel1xx_pending.is_empty() {
            warn!(
                key = %self.key,
                dropped = self.rel1xx_pending.len(),
                "final response sent; dropping queued responses (RFC 3262 §3)"
            );
            self.rel1xx_pending.clear();
        }
    }

    fn cancel_rel1xx_timers(&mut self) {
        self.timer_rel1xx
            .take()
            .map(|id| self.endpoint_inner.timers.cancel(id));
        self.timer_rel1xx_timeout
            .take()
            .map(|id| self.endpoint_inner.timers.cancel(id));
    }

    /// A PRACK forwarded to this server INVITE transaction (RFC 3262 §3).
    async fn on_prack(&mut self, prack: &Request) {
        let matched = self
            .rel1xx_unacked
            .as_ref()
            .map(|u| u.matches_prack(prack))
            .unwrap_or(false);
        if !matched {
            debug!(
                key = %self.key,
                rack = ?prack.rack_value(),
                unacked = ?self.rel1xx_unacked.as_ref().map(|u| u.rseq),
                "PRACK does not match the unacknowledged reliable provisional response; ignored"
            );
            return;
        }
        debug!(
            key = %self.key,
            rseq = self.rel1xx_unacked.as_ref().map(|u| u.rseq),
            "reliable provisional response acknowledged"
        );
        self.cancel_rel1xx_timers();
        self.rel1xx_unacked.take();
        self.drain_rel1xx_pending().await;
    }

    /// RFC 3262 §3: no PRACK within 64*T1 — reject the INVITE with a 5xx.
    async fn on_rel1xx_timeout(&mut self) -> Result<SipMessage> {
        self.cancel_rel1xx_timers();
        let unacked = self.rel1xx_unacked.take();
        let dropped_final = self
            .rel1xx_pending
            .iter()
            .any(|r| r.status_code.kind() != StatusCodeKind::Provisional);
        warn!(
            key = %self.key,
            rseq = unacked.as_ref().map(|u| u.rseq),
            dropped = self.rel1xx_pending.len(),
            dropped_final,
            "no PRACK received within 64*T1; rejecting INVITE with 500 (RFC 3262 §3)"
        );
        self.rel1xx_pending.clear();

        let mut response = self.endpoint_inner.make_response(
            &self.original,
            StatusCode::ServerInternalError,
            None,
        );
        // Carry the early dialog's To tag so the UAC matches the 500 to the
        // dialog created by the reliable provisional response.
        let to = match unacked.as_ref().and_then(|u| u.response.to_header().ok()) {
            Some(to) => to.clone(),
            None => response.to_header()?.clone(),
        };
        let to = if to.tag()?.is_none() {
            let tag: String = self
                .local_to_tag
                .clone()
                .unwrap_or_else(|| make_tag().value().to_string());
            to.with_tag(tag.into())
        } else {
            to
        };
        response.headers.unique_push(Header::To(to));

        if let Err(e) = self.respond_plain(response.clone()).await {
            warn!(key = %self.key, error = %e, "failed to send 500 after PRACK timeout");
            if self.state != TransactionState::Completed {
                self.transition(TransactionState::Terminated).ok();
            }
        }
        Ok(SipMessage::Response(response))
    }

    fn original_to_has_tag(&self) -> bool {
        self.original
            .to_header()
            .ok()
            .and_then(|to| to.tag().ok().flatten())
            .is_some()
    }

    /// Remember the To tag of the first non-100 response of a server INVITE
    /// transaction (see `local_to_tag`).
    fn remember_local_to_tag(&mut self, response: &Response) {
        if self.transaction_type != TransactionType::ServerInvite
            || self.local_to_tag.is_some()
            || response.status_code == StatusCode::Trying
        {
            return;
        }
        if let Ok(Some(tag)) = response.to_header().and_then(|to| to.tag()) {
            self.local_to_tag = Some(tag.value().to_string());
        }
    }

    fn inspect_before_send(&self, msg: SipMessage) -> SipMessage {
        if let Some(ref inspector) = self.endpoint_inner.message_inspector {
            inspector.before_send(msg, self.destination.as_ref())
        } else {
            msg
        }
    }

    /// Retransmit a response: message inspector + transport send, with no
    /// state or RFC 3262 bookkeeping. Used by every retransmission path
    /// (request retransmissions, Timer G, TimerRel1xx).
    async fn send_response_raw(&self, response: &Response) -> Result<()> {
        let connection = self.connection.as_ref().ok_or(Error::TransactionError(
            "no connection found".to_string(),
            self.key.clone(),
        ))?;
        let message = self.inspect_before_send(response.clone().into());
        connection.send(message, self.destination.as_ref()).await
    }

    fn can_transition(&self, target: &TransactionState) -> Result<()> {
        match (&self.state, target) {
            (&TransactionState::Nothing, &TransactionState::Calling)
            | (&TransactionState::Nothing, &TransactionState::Trying)
            | (&TransactionState::Nothing, &TransactionState::Proceeding)
            | (&TransactionState::Nothing, &TransactionState::Terminated)
            | (&TransactionState::Calling, &TransactionState::Calling)
            | (&TransactionState::Calling, &TransactionState::Trying)
            | (&TransactionState::Calling, &TransactionState::Proceeding)
            | (&TransactionState::Calling, &TransactionState::Completed)
            | (&TransactionState::Calling, &TransactionState::Terminated)
            | (&TransactionState::Trying, &TransactionState::Trying) // retransmission
            | (&TransactionState::Trying, &TransactionState::Proceeding)
            | (&TransactionState::Trying, &TransactionState::Completed)
            | (&TransactionState::Trying, &TransactionState::Confirmed)
            | (&TransactionState::Trying, &TransactionState::Terminated)
            | (&TransactionState::Proceeding, &TransactionState::Proceeding)
            | (&TransactionState::Proceeding, &TransactionState::Completed)
            | (&TransactionState::Proceeding, &TransactionState::Confirmed)
            | (&TransactionState::Proceeding, &TransactionState::Terminated)
            | (&TransactionState::Completed, &TransactionState::Confirmed)
            | (&TransactionState::Completed, &TransactionState::Terminated)
            | (&TransactionState::Confirmed, &TransactionState::Terminated) => Ok(()),
            _ => {
                Err(Error::TransactionError(
                    format!(
                        "invalid state transition from {} to {}",
                        self.state, target
                    ),
                    self.key.clone(),
                ))
            }
        }
    }
    pub async fn send_cancel(&mut self, cancel: Request) -> Result<()> {
        if self.transaction_type != TransactionType::ClientInvite {
            return Err(Error::TransactionError(
                "send_cancel is only valid for client invite transactions".to_string(),
                self.key.clone(),
            ));
        }

        match self.state {
            TransactionState::Calling | TransactionState::Trying | TransactionState::Proceeding => {
                if let Some(connection) = &self.connection {
                    let cancel = if let Some(ref inspector) = self.endpoint_inner.message_inspector
                    {
                        inspector.before_send(cancel.to_owned().into(), self.destination.as_ref())
                    } else {
                        cancel.to_owned().into()
                    };

                    connection.send(cancel, self.destination.as_ref()).await?;
                }
                Ok(())
            }
            _ => Err(Error::TransactionError(
                format!("invalid state for sending CANCEL {:?}", self.state),
                self.key.clone(),
            )),
        }
    }

    pub async fn send_ack(&mut self, mut connection: Option<SipConnection>) -> Result<()> {
        if self.transaction_type != TransactionType::ClientInvite {
            return Err(Error::TransactionError(
                "send_ack is only valid for client invite transactions".to_string(),
                self.key.clone(),
            ));
        }

        match self.state {
            TransactionState::Completed => {} // must be in completed state, to send ACK
            _ => {
                return Err(Error::TransactionError(
                    format!("invalid state for sending ACK {:?}", self.state),
                    self.key.clone(),
                ));
            }
        }
        let ack = match self.last_ack.clone() {
            Some(ack) => ack,
            None => match self.last_response {
                Some(ref resp) => self.endpoint_inner.make_ack(&self.original, resp)?,
                None => {
                    return Err(Error::TransactionError(
                        "no last response found to send ACK".to_string(),
                        self.key.clone(),
                    ));
                }
            },
        };

        // Capture locator + transport lookup result
        // so before_send is called regardless of lookup outcome
        if let Some(resp) = self.last_response.as_ref() {
            if resp.status_code.kind() == StatusCodeKind::Successful {
                // Per RFC 7118 §5 and general connection-oriented transport handling,
                // the 2xx ACK must reuse the existing flow the response arrived on
                // instead of dialing the Record-Route/Contact target (which may be
                // unreachable from the client) via lookup(). Only resolve a new
                // destination for UDP (connectionless) or when no connection is given.
                let reuse_existing = connection
                    .as_ref()
                    .map(|conn| conn.is_reliable())
                    .unwrap_or(false);

                if !reuse_existing {
                    // 2xx response, set destination from request
                    let target = ack.destination();
                    let addr = match self.endpoint_inner.locator.as_ref() {
                        Some(locator) => match locator.locate(&target).await {
                            Ok(addr) => Some(addr),
                            Err(e) => {
                                warn!(key = %self.key, error = %e, "ack locator failed");
                                None
                            }
                        },
                        None => (&target).try_into().ok(),
                    };
                    if let Some(addr) = addr {
                        match self
                            .endpoint_inner
                            .transport_layer
                            .lookup(&addr, Some(&self.key))
                            .await
                        {
                            Ok((via_connection, resolved_addr)) => {
                                // For UDP, we need to store the resolved destination address
                                if !via_connection.is_reliable() {
                                    self.destination.replace(resolved_addr);
                                }
                                connection = Some(via_connection);
                            }
                            Err(e) => {
                                warn!(key = %self.key, error = %e, "ack lookup failed");
                            }
                        }
                    }
                }
            }
        }

        let ack = if let Some(ref inspector) = self.endpoint_inner.message_inspector {
            inspector.before_send(ack.to_owned().into(), self.destination.as_ref())
        } else {
            ack.to_owned().into()
        };

        match ack.clone() {
            SipMessage::Request(ref ack_req) => self.last_ack.replace(ack_req.clone()),
            _ => None,
        };

        // Try to send if we have a connection; log errors instead of propagating
        // so the transaction always transitions to Terminated.
        if let Some(ref conn) = connection {
            if let Err(e) = conn.send(ack, self.destination.as_ref()).await {
                warn!(key = %self.key, error = %e, "ack send failed");
            }
        } else {
            debug!(key = %self.key, "no connection for ack");
        }
        // client send ack and transition to Terminated
        self.transition(TransactionState::Terminated).map(|_| ())
    }

    /// Wait for the next message that the transaction user must handle.
    ///
    /// Returns `None` once the transaction is terminated.
    ///
    /// For a server INVITE transaction a returned `SipMessage::Response` is a
    /// *locally synthesized* final response — currently only the
    /// `500 Server Internal Error` sent when a reliable provisional response was
    /// not acknowledged within 64*T1 (RFC 3262 §3). It has already been sent on
    /// the wire; the transaction user only needs to update its own state.
    pub async fn receive(&mut self) -> Option<SipMessage> {
        while let Some(event) = self.tu_receiver.recv().await {
            match event {
                TransactionEvent::Received(msg, connection) => {
                    if let Some(msg) = match msg {
                        SipMessage::Request(req) => self.on_received_request(req, connection).await,
                        SipMessage::Response(resp) => {
                            self.on_received_response(resp, connection).await
                        }
                    } {
                        return Some(msg);
                    }
                }
                TransactionEvent::Timer(t) => match self.on_timer(t).await {
                    Ok(Some(msg)) => return Some(msg),
                    Ok(None) => {}
                    Err(e) => debug!(key = %self.key, error = %e, "timer handling failed"),
                },
                TransactionEvent::Respond(response) => {
                    self.respond(response).await.ok();
                }
                TransactionEvent::Terminate(key) => {
                    debug!(%key, "received terminate event");
                    if matches!(self.state, TransactionState::Nothing) {
                        // Nothing has been sent yet; whatever prompted this does not concern
                        // this transaction (its request will go out on whatever transport is
                        // current when it is sent).
                        debug!(%key, "terminate before the request was sent; ignored");
                        continue;
                    }
                    // Terminated from outside while a client transaction still awaits its
                    // final response: the transport failed under it. RFC 3261 §8.1.3.1 has
                    // the TU treat that as a 503, so hand it one built from the request; the
                    // state machine then ends the transaction as for any final response.
                    let awaiting_final = matches!(
                        self.state,
                        TransactionState::Calling
                            | TransactionState::Trying
                            | TransactionState::Proceeding
                    );
                    if matches!(self.role(), TransactionRole::Client) && awaiting_final {
                        let failure = self.endpoint_inner.make_response(
                            &self.original,
                            StatusCode::ServiceUnavailable,
                            None,
                        );
                        match self.inform_tu_response(failure) {
                            Ok(()) => continue,
                            Err(e) => {
                                debug!(key = %self.key, error = %e, "transport failure report failed")
                            }
                        }
                    }
                    return None;
                }
            }
        }
        None
    }

    /// Stop request retransmissions while keeping the transaction alive to
    /// consume a provisional or final response already in flight.
    pub(crate) fn stop_retransmissions(&mut self) {
        self.retransmission = false;
        self.timer_a
            .take()
            .map(|id| self.endpoint_inner.timers.cancel(id));
    }

    pub async fn send_trying(&mut self) -> Result<()> {
        let response = self
            .endpoint_inner
            .make_response(&self.original, StatusCode::Trying, None);
        self.respond(response).await
    }

    pub fn is_terminated(&self) -> bool {
        self.state == TransactionState::Terminated
    }
}

impl Transaction {
    fn inform_tu_response(&mut self, response: Response) -> Result<()> {
        let msg = if let Some(ref inspector) = self.endpoint_inner.message_inspector {
            inspector.after_received(SipMessage::Response(response), None)
        } else {
            SipMessage::Response(response)
        };
        self.tu_sender
            .send(TransactionEvent::Received(msg, None))
            .map_err(|e| Error::TransactionError(e.to_string(), self.key.clone()))
    }

    async fn on_received_request(
        &mut self,
        req: Request,
        connection: Option<SipConnection>,
    ) -> Option<SipMessage> {
        match self.transaction_type {
            TransactionType::ClientInvite | TransactionType::ClientNonInvite => return None,
            _ => {}
        }

        if self.connection.is_none() && connection.is_some() {
            self.connection = connection;
        }
        if req.method == Method::Cancel {
            let forward_to_tu = match self.state {
                TransactionState::Proceeding | TransactionState::Trying => true,
                // RFC 3261 Section 9.2: after a final response, CANCEL has no
                // effect on the original request, its responses, or session state.
                TransactionState::Completed => false,
                _ => {
                    if let Some(connection) = &self.connection {
                        let resp = self.endpoint_inner.make_response(
                            &req,
                            StatusCode::CallTransactionDoesNotExist,
                            None,
                        );
                        let resp =
                            if let Some(ref inspector) = self.endpoint_inner.message_inspector {
                                inspector.before_send(resp.into(), self.destination.as_ref())
                            } else {
                                resp.into()
                            };

                        connection.send(resp, self.destination.as_ref()).await.ok();
                    }
                    return None;
                }
            };

            if let Some(connection) = &self.connection {
                let resp = self
                    .endpoint_inner
                    .make_response(&req, StatusCode::OK, None);
                let resp = if let Some(ref inspector) = self.endpoint_inner.message_inspector {
                    inspector.before_send(resp.into(), self.destination.as_ref())
                } else {
                    resp.into()
                };
                connection.send(resp, self.destination.as_ref()).await.ok();
            }
            return forward_to_tu.then(|| req.into());
        }

        // A PRACK forwarded by the dialog layer acknowledges the outstanding
        // reliable provisional response (RFC 3262). It has its own server
        // transaction, so it is never surfaced to the TU from here. This must
        // precede the request-retransmission arm below.
        if req.method == Method::PRack && self.transaction_type == TransactionType::ServerInvite {
            self.on_prack(&req).await;
            return None;
        }

        match self.state {
            TransactionState::Trying | TransactionState::Proceeding => {
                // retransmission of last response (no state / RFC 3262 bookkeeping)
                if let Some(last_response) = &self.last_response {
                    if let Err(e) = self.send_response_raw(last_response).await {
                        debug!(key = %self.key, error = %e, "response retransmission failed");
                    }
                }
            }
            TransactionState::Completed | TransactionState::Confirmed
                if req.method == Method::Ack =>
            {
                self.transition(TransactionState::Confirmed).ok();
                return Some(req.into());
            }
            _ => {}
        }
        None
    }

    async fn on_received_response(
        &mut self,
        resp: Response,
        connection: Option<SipConnection>,
    ) -> Option<SipMessage> {
        match self.transaction_type {
            TransactionType::ServerInvite | TransactionType::ServerNonInvite => return None,
            _ => {}
        }
        let new_state = match resp.status_code.kind() {
            StatusCodeKind::Provisional => {
                if resp.status_code == StatusCode::Trying {
                    TransactionState::Trying
                } else {
                    TransactionState::Proceeding
                }
            }
            _ => {
                if self.transaction_type == TransactionType::ClientInvite {
                    TransactionState::Completed
                } else {
                    TransactionState::Terminated
                }
            }
        };

        self.can_transition(&new_state).ok()?;
        if self.state == new_state {
            if let Some(last) = self.last_response.as_ref() {
                if last.status_code == resp.status_code && last.body == resp.body {
                    // ignore duplicate response
                    return None;
                }
            }
        }

        self.last_response.replace(resp.clone());
        let is_completed_client_invite = self.transaction_type == TransactionType::ClientInvite
            && new_state == TransactionState::Completed;

        self.transition(new_state).ok();

        if is_completed_client_invite {
            self.send_ack(connection).await.ok();
        }

        Some(SipMessage::Response(resp))
    }

    /// Handle a transaction timer. Returns a message the TU must handle, if any
    /// (the RFC 3262 timeout 500 for server INVITE transactions).
    async fn on_timer(&mut self, timer: TransactionTimer) -> Result<Option<SipMessage>> {
        match &timer {
            TransactionTimer::TimerRel1xx(key, rseq, duration) => {
                let current = self.rel1xx_unacked.as_ref().map(|u| u.rseq);
                if self.state != TransactionState::Proceeding || current != Some(*rseq) {
                    trace!(key = %self.key, rseq, "ignoring stale TimerRel1xx");
                    return Ok(None);
                }
                let response = self
                    .rel1xx_unacked
                    .as_ref()
                    .map(|u| u.response.clone())
                    .expect("checked above");
                if let Err(e) = self.send_response_raw(&response).await {
                    warn!(key = %self.key, error = %e, "reliable provisional retransmission failed");
                }
                // RFC 3262 §3: doubles on every retransmission, no T2 cap.
                let duration = *duration * 2;
                let timer_id = self.endpoint_inner.timers.timeout(
                    duration,
                    TransactionTimer::TimerRel1xx(key.clone(), *rseq, duration),
                );
                self.timer_rel1xx.replace(timer_id);
                return Ok(None);
            }
            TransactionTimer::TimerRel1xxTimeout(_, rseq) => {
                let current = self.rel1xx_unacked.as_ref().map(|u| u.rseq);
                if self.state != TransactionState::Proceeding || current != Some(*rseq) {
                    trace!(key = %self.key, rseq, "ignoring stale TimerRel1xxTimeout");
                    return Ok(None);
                }
                return self.on_rel1xx_timeout().await.map(Some);
            }
            _ => {}
        }
        match self.state {
            TransactionState::Calling | TransactionState::Trying => {
                if matches!(
                    self.transaction_type,
                    TransactionType::ClientInvite | TransactionType::ClientNonInvite
                ) {
                    if let TransactionTimer::TimerA(key, duration) = timer {
                        if !self.retransmission {
                            return Ok(None);
                        }
                        // If no connection (initial lookup failed), retry transport lookup
                        // using the same target resolution rule as send()
                        if self.connection.is_none() {
                            if let Ok(target) = self.resolve_target_uri().await {
                                if let Ok((connection, resolved_addr)) = self
                                    .endpoint_inner
                                    .transport_layer
                                    .lookup(&target, Some(&self.key))
                                    .await
                                {
                                    self.connection.replace(connection);
                                    self.destination.replace(resolved_addr);
                                    self.align_original_via();
                                }
                            }
                        }

                        // Resend the request if connection available
                        if let Some(connection) = &self.connection {
                            let retry_message = if let Some(ref inspector) =
                                self.endpoint_inner.message_inspector
                            {
                                inspector.before_send(
                                    self.original.to_owned().into(),
                                    self.destination.as_ref(),
                                )
                            } else {
                                self.original.to_owned().into()
                            };
                            if let Err(e) = connection
                                .send(retry_message, self.destination.as_ref())
                                .await
                            {
                                warn!(key = %self.key, error = %e, "timer A resend failed");
                            }
                        } else {
                            debug!(key = %self.key, "timer A: no connection yet");
                        }
                        // Restart Timer A with an upper limit
                        let duration = (duration * 2).min(self.endpoint_inner.option.t1x64);
                        let timer_a = self
                            .endpoint_inner
                            .timers
                            .timeout(duration, TransactionTimer::TimerA(key, duration));
                        self.timer_a.replace(timer_a);
                    } else if let TransactionTimer::TimerB(_) = timer {
                        let timeout_response = self.endpoint_inner.make_response(
                            &self.original,
                            StatusCode::RequestTimeout,
                            None,
                        );
                        self.inform_tu_response(timeout_response)?;
                    }
                }
            }
            TransactionState::Proceeding => {
                if let TransactionTimer::TimerC(_) = timer {
                    // Inform TU about timeout
                    let timeout_response = self.endpoint_inner.make_response(
                        &self.original,
                        StatusCode::RequestTimeout,
                        None,
                    );
                    self.inform_tu_response(timeout_response)?;
                }
            }
            TransactionState::Completed => {
                if let TransactionTimer::TimerG(key, duration) = timer {
                    // resend the response
                    if let Some(last_response) = &self.last_response {
                        if self.connection.is_some() {
                            self.send_response_raw(last_response).await?;
                        }
                    }
                    // restart Timer G with an upper limit
                    let duration = (duration * 2).min(self.endpoint_inner.option.t1x64);
                    let timer_g = self
                        .endpoint_inner
                        .timers
                        .timeout(duration, TransactionTimer::TimerG(key, duration));
                    self.timer_g.replace(timer_g);
                } else if let TransactionTimer::TimerD(_) = timer {
                    self.transition(TransactionState::Terminated)?;
                } else if let TransactionTimer::TimerK(_) = timer {
                    self.transition(TransactionState::Terminated)?;
                }
            }
            TransactionState::Confirmed => {
                if let TransactionTimer::TimerK(_) = timer {
                    self.transition(TransactionState::Terminated)?;
                }
            }
            _ => {}
        }
        Ok(None)
    }

    fn transition(&mut self, state: TransactionState) -> Result<TransactionState> {
        if self.state == state {
            return Ok(self.state.clone());
        }
        match state {
            TransactionState::Nothing => {}
            TransactionState::Calling => {
                if matches!(
                    self.transaction_type,
                    TransactionType::ClientInvite | TransactionType::ClientNonInvite
                ) {
                    match self.connection.as_ref() {
                        Some(connection) if !connection.is_reliable() => {
                            // Unreliable transport: start Timer A for retransmission
                            let timer_a = self.endpoint_inner.timers.timeout(
                                self.endpoint_inner.option.t1,
                                TransactionTimer::TimerA(
                                    self.key.clone(),
                                    self.endpoint_inner.option.t1,
                                ),
                            );
                            self.timer_a.replace(timer_a);
                        }
                        None => {
                            // No connection yet (e.g., DNS lookup failed).
                            // Start Timer A to retry transport lookup + send.
                            let timer_a = self.endpoint_inner.timers.timeout(
                                self.endpoint_inner.option.t1,
                                TransactionTimer::TimerA(
                                    self.key.clone(),
                                    self.endpoint_inner.option.t1,
                                ),
                            );
                            self.timer_a.replace(timer_a);
                        }
                        _ => {} // Reliable transport: no Timer A needed
                    }
                    self.timer_b.replace(self.endpoint_inner.timers.timeout(
                        self.endpoint_inner.option.t1x64,
                        TransactionTimer::TimerB(self.key.clone()),
                    ));
                }
            }
            TransactionState::Trying | TransactionState::Proceeding => {
                self.timer_a
                    .take()
                    .map(|id| self.endpoint_inner.timers.cancel(id));
                if matches!(self.transaction_type, TransactionType::ClientInvite) {
                    self.timer_b
                        .take()
                        .map(|id| self.endpoint_inner.timers.cancel(id));
                    if self.timer_c.is_none() {
                        // start Timer C for client invite only
                        let timer_c = self.endpoint_inner.timers.timeout(
                            self.endpoint_inner.option.timerc,
                            TransactionTimer::TimerC(self.key.clone()),
                        );
                        self.timer_c.replace(timer_c);
                    }
                }
            }
            TransactionState::Completed => {
                self.timer_a
                    .take()
                    .map(|id| self.endpoint_inner.timers.cancel(id));
                self.timer_b
                    .take()
                    .map(|id| self.endpoint_inner.timers.cancel(id));
                self.timer_c
                    .take()
                    .map(|id| self.endpoint_inner.timers.cancel(id));
                self.cancel_rel1xx_timers();

                if self.transaction_type == TransactionType::ServerInvite {
                    // start Timer G for server invite only
                    let connection = self.connection.as_ref().ok_or(Error::TransactionError(
                        "no connection found".to_string(),
                        self.key.clone(),
                    ))?;
                    // Resolve the dialog id before arming any timer so a failure
                    // leaves no half-applied state.
                    let dialog_id = match self.last_response {
                        Some(ref resp) => {
                            Some(DialogId::try_from((resp, TransactionRole::Server))?)
                        }
                        None => None,
                    };
                    if !connection.is_reliable() {
                        let timer_g = self.endpoint_inner.timers.timeout(
                            self.endpoint_inner.option.t1,
                            TransactionTimer::TimerG(
                                self.key.clone(),
                                self.endpoint_inner.option.t1,
                            ),
                        );
                        self.timer_g.replace(timer_g);
                    }
                    debug!(key=%self.key, last = self.last_response.is_none(), "entered confirmed state, waiting for ACK");
                    if let Some(dialog_id) = dialog_id {
                        self.endpoint_inner
                            .waiting_ack
                            .insert(dialog_id, self.key.clone());
                    }
                    // start Timer K, wait for ACK
                    let timer_k = self.endpoint_inner.timers.timeout(
                        self.endpoint_inner.option.t4,
                        TransactionTimer::TimerK(self.key.clone()),
                    );
                    self.timer_k.replace(timer_k);
                }
                // start Timer D
                let timer_d = self.endpoint_inner.timers.timeout(
                    self.endpoint_inner.option.t1x64,
                    TransactionTimer::TimerD(self.key.clone()),
                );
                self.timer_d.replace(timer_d);
            }
            TransactionState::Confirmed => {
                self.cleanup_timer();
                // ACK was received; remove waiting_ack entry since it's no longer needed.
                if self.transaction_type == TransactionType::ServerInvite {
                    if let Some(ref resp) = self.last_response {
                        if let Ok(dialog_id) = DialogId::try_from((resp, self.role())) {
                            self.endpoint_inner.waiting_ack.remove(&dialog_id);
                        }
                    }
                }
                let timer_k = self.endpoint_inner.timers.timeout(
                    self.endpoint_inner.option.t4,
                    TransactionTimer::TimerK(self.key.clone()),
                );
                self.timer_k.replace(timer_k);
            }
            TransactionState::Terminated => {
                self.cleanup();
                self.tu_sender
                    .send(TransactionEvent::Terminate(self.key.clone()))
                    .ok(); // tell TU to terminate
            }
        }
        debug!(
            key = %self.key,
            from = %self.state,
            to = %state,
            "transition"
        );
        self.state = state;
        Ok(self.state.clone())
    }

    fn cleanup_timer(&mut self) {
        self.timer_a
            .take()
            .map(|id| self.endpoint_inner.timers.cancel(id));
        self.timer_b
            .take()
            .map(|id| self.endpoint_inner.timers.cancel(id));
        self.timer_c
            .take()
            .map(|id| self.endpoint_inner.timers.cancel(id));
        self.timer_d
            .take()
            .map(|id| self.endpoint_inner.timers.cancel(id));
        self.timer_k
            .take()
            .map(|id| self.endpoint_inner.timers.cancel(id));
        self.timer_g
            .take()
            .map(|id| self.endpoint_inner.timers.cancel(id));
        self.cancel_rel1xx_timers();
    }

    pub fn role(&self) -> TransactionRole {
        match self.transaction_type {
            crate::transaction::TransactionType::ClientInvite
            | crate::transaction::TransactionType::ClientNonInvite => TransactionRole::Client,
            crate::transaction::TransactionType::ServerInvite
            | crate::transaction::TransactionType::ServerNonInvite => TransactionRole::Server,
        }
    }

    fn cleanup(&mut self) {
        if self.is_cleaned_up {
            return;
        }
        self.is_cleaned_up = true;
        if self.rel1xx_unacked.is_some() || !self.rel1xx_pending.is_empty() {
            warn!(
                key = %self.key,
                state = %self.state,
                unacked = ?self.rel1xx_unacked.as_ref().map(|u| u.rseq),
                dropped = self.rel1xx_pending.len(),
                held_final = self.rel1xx_pending.iter().any(|r| r.status_code.kind() != StatusCodeKind::Provisional),
                "transaction cleaned up with reliable provisional state outstanding; queued responses are lost"
            );
            self.rel1xx_pending.clear();
        }
        self.cleanup_timer();

        // For ServerInvite in Completed state, keep the waiting_ack entry
        // so that incoming ACK can still be routed and absorbed by finished_transactions.
        // Confirmed state means the ACK was already received, so the entry is no longer needed.
        let is_server_invite_waiting_ack =
            matches!(self.transaction_type, TransactionType::ServerInvite)
                && self.state == TransactionState::Completed;
        if !is_server_invite_waiting_ack {
            match self.last_response {
                Some(ref resp) => match DialogId::try_from((resp, self.role())) {
                    Ok(dialog_id) => self
                        .endpoint_inner
                        .waiting_ack
                        .remove(&dialog_id)
                        .map(|_| ()),
                    Err(_) => None,
                },
                _ => None,
            };
        }

        let last_message = {
            match self.transaction_type {
                TransactionType::ClientInvite => {
                    //
                    // For client invite, make a placeholder ACK if in proceeding or trying state
                    if matches!(
                        self.state,
                        TransactionState::Proceeding | TransactionState::Trying
                    ) && self.last_ack.is_none()
                    {
                        if let Some(ref resp) = self.last_response {
                            if let Ok(ack) = self.endpoint_inner.make_ack(&self.original, resp) {
                                self.last_ack.replace(ack);
                            }
                        }
                    }
                    self.last_ack.take().map(SipMessage::Request)
                }
                TransactionType::ServerNonInvite | TransactionType::ServerInvite => {
                    self.last_response.take().map(SipMessage::Response)
                }
                _ => None,
            }
        };
        self.endpoint_inner
            .detach_transaction(&self.key, last_message);
    }
}

#[cfg(test)]
impl Transaction {
    pub(crate) fn rel1xx_unacked_rseq(&self) -> Option<u32> {
        self.rel1xx_unacked.as_ref().map(|u| u.rseq)
    }
    pub(crate) fn rel1xx_pending_len(&self) -> usize {
        self.rel1xx_pending.len()
    }
    pub(crate) fn rel1xx_timers_armed(&self) -> (bool, bool) {
        (
            self.timer_rel1xx.is_some(),
            self.timer_rel1xx_timeout.is_some(),
        )
    }
    /// The pending RFC 3262 retransmission timer, if one is armed.
    pub(crate) fn rel1xx_retransmit_timer(&self) -> Option<TransactionTimer> {
        self.timer_rel1xx
            .and_then(|id| self.endpoint_inner.timers.peek(id))
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        self.cleanup();
        trace!(key=%self.key, state=%self.state, "transaction dropped");
    }
}
