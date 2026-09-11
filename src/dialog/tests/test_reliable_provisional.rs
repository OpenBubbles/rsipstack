//! RFC 3262 (100rel) UAS behaviour at the dialog layer.
//!
//! Covers `InviteDialog` and the deprecated `ServerInviteDialog` (both wrap the
//! same `DialogInner`), plus two end-to-end flows over real UDP through
//! `DialogLayer`.

#![allow(deprecated)]

use crate::dialog::dialog::{Dialog, DialogInner, DialogState, TerminatedReason};
use crate::dialog::dialog_layer::DialogLayer;
use crate::dialog::invite_dialog::InviteDialog;
use crate::dialog::server_dialog::ServerInviteDialog;
use crate::dialog::DialogId;
use crate::sip::headers::*;
use crate::sip::prelude::*;
use crate::sip::{Header, Method, Request, Response, SipMessage, StatusCode};
use crate::transaction::endpoint::{Endpoint, EndpointBuilder, EndpointOption};
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::transaction::transaction::{Transaction, TransactionEvent, TransactionEventSender};
use crate::transport::{
    channel::ChannelConnection, connection::TransportEvent, udp::UdpConnection, SipAddr,
    SipConnection, TransportLayer,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const T1: Duration = Duration::from_millis(20);
const T1X64: Duration = Duration::from_millis(20 * 64);

#[derive(Clone, Copy)]
enum UacRel {
    Require,
    Supported,
    None,
}

fn test_option() -> EndpointOption {
    EndpointOption {
        t1: T1,
        t1x64: T1X64,
        ..Default::default()
    }
}

async fn create_endpoint() -> Endpoint {
    let token = CancellationToken::new();
    EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(TransportLayer::new(token.child_token()))
        .with_option(test_option())
        .build()
}

fn make_invite(via_host: &str, branch: &str, call_id: &str, rel: UacRel) -> Request {
    let mut headers: Vec<Header> = vec![
        Via::new(format!("SIP/2.0/UDP {via_host};branch={branch}")).into(),
        CSeq::new("1 INVITE").into(),
        From::new("Alice <sip:alice@example.com>;tag=alice-tag").into(),
        To::new("Bob <sip:bob@example.com>").into(),
        CallId::new(call_id).into(),
        Contact::new(format!("<sip:alice@{via_host}>")).into(),
        MaxForwards::new("70").into(),
        Header::ContentType("application/sdp".into()),
    ];
    match rel {
        UacRel::Require => headers.push(Header::Require("100rel".into())),
        UacRel::Supported => headers.push(Header::Supported("100rel, timer".into())),
        UacRel::None => {}
    }
    Request {
        method: Method::Invite,
        uri: crate::sip::Uri::try_from("sip:bob@example.com").unwrap(),
        headers: headers.into(),
        version: crate::sip::Version::V2,
        body: b"v=0\r\no=alice 1 1 IN IP4 127.0.0.1\r\n".to_vec(),
    }
}

fn make_prack(invite: &Request, rack: Option<&str>, to_tag: &str, other_header: bool) -> Request {
    let call_id = invite.call_id_header().unwrap().clone();
    let from = invite.from_header().unwrap().clone();
    let mut headers: Vec<Header> = vec![
        Via::new(format!(
            "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKprack-{}",
            crate::transaction::random_text(6)
        ))
        .into(),
        CSeq::new("2 PRACK").into(),
        from.into(),
        To::new(format!("Bob <sip:bob@example.com>;tag={to_tag}")).into(),
        call_id.into(),
        MaxForwards::new("70").into(),
    ];
    if let Some(rack) = rack {
        headers.push(if other_header {
            Header::Other("RAck".into(), rack.into())
        } else {
            Header::RAck(rack.into())
        });
    }
    Request {
        method: Method::PRack,
        uri: invite.uri.clone(),
        headers: headers.into(),
        version: crate::sip::Version::V2,
        body: vec![],
    }
}

/// Server transaction over a `ChannelConnection`; every sent message shows up
/// on the returned receiver.
async fn channel_tx(
    endpoint: &Endpoint,
    req: Request,
) -> (Transaction, UnboundedReceiver<TransportEvent>) {
    let (_incoming_tx, incoming_rx) = unbounded_channel();
    let (transport_tx, wire) = unbounded_channel();
    let addr: SipAddr = crate::sip::HostWithPort::try_from("127.0.0.1:5060")
        .unwrap()
        .into();
    let channel =
        ChannelConnection::create_connection(incoming_rx, transport_tx, addr.clone(), None)
            .await
            .unwrap();
    let key = TransactionKey::from_request(&req, TransactionRole::Server).unwrap();
    let mut tx = Transaction::new_server(
        key,
        req,
        endpoint.inner.clone(),
        Some(SipConnection::Channel(channel)),
    );
    tx.destination = Some(addr);
    (tx, wire)
}

async fn next_wire_response(
    wire: &mut UnboundedReceiver<TransportEvent>,
    d: Duration,
) -> Option<Response> {
    match timeout(d, wire.recv()).await {
        Ok(Some(TransportEvent::Incoming(SipMessage::Response(resp), _, _))) => Some(resp),
        _ => None,
    }
}

async fn next_respond(
    rx: &mut UnboundedReceiver<TransactionEvent>,
    d: Duration,
) -> Option<Response> {
    match timeout(d, rx.recv()).await {
        Ok(Some(TransactionEvent::Respond(resp))) => Some(resp),
        _ => None,
    }
}

async fn next_forwarded_request(
    rx: &mut UnboundedReceiver<TransactionEvent>,
    d: Duration,
) -> Option<Request> {
    match timeout(d, rx.recv()).await {
        Ok(Some(TransactionEvent::Received(SipMessage::Request(req), _))) => Some(req),
        _ => None,
    }
}

fn has_100rel(resp: &Response) -> bool {
    resp.header_contains_token("Require", "100rel")
}

fn count_headers(resp: &Response, name: &str) -> usize {
    resp.headers
        .iter()
        .filter(|h| h.name().eq_ignore_ascii_case(name))
        .count()
}

/// Raw (untrimmed) value of the first header named `name`.
fn raw_header(resp: &Response, name: &str) -> Option<String> {
    resp.headers
        .iter()
        .find(|h| h.name().eq_ignore_ascii_case(name))
        .map(|h| h.value().to_string())
}

fn to_tag_of(resp: &Response) -> String {
    resp.to_header()
        .unwrap()
        .tag()
        .unwrap()
        .map(|t| t.value().to_string())
        .unwrap_or_default()
}

/// Both UAS dialog flavours must behave identically.
enum Uas {
    New(InviteDialog),
    Legacy(ServerInviteDialog),
}

impl Uas {
    fn build(legacy: bool, inner: DialogInner) -> Self {
        Self::from_arc(legacy, Arc::new(inner))
    }
    fn from_arc(legacy: bool, inner: Arc<DialogInner>) -> Self {
        if legacy {
            Uas::Legacy(ServerInviteDialog { inner })
        } else {
            Uas::New(InviteDialog::from_inner(inner))
        }
    }
    /// Second handle onto the same dialog (both wrappers are `Arc`-backed).
    fn clone_handle(&self) -> Self {
        match self {
            Uas::New(d) => Uas::New(d.clone()),
            Uas::Legacy(d) => Uas::Legacy(d.clone()),
        }
    }
    fn ringing(&self, headers: Option<Vec<Header>>, body: Option<Vec<u8>>) -> crate::Result<()> {
        match self {
            Uas::New(d) => d.ringing(headers, body),
            Uas::Legacy(d) => d.ringing(headers, body),
        }
    }
    fn accept(&self, headers: Option<Vec<Header>>, body: Option<Vec<u8>>) -> crate::Result<()> {
        match self {
            Uas::New(d) => d.accept(headers, body),
            Uas::Legacy(d) => d.accept(headers, body),
        }
    }
    fn reject(&self) -> crate::Result<()> {
        match self {
            Uas::New(d) => d.reject(None, None),
            Uas::Legacy(d) => d.reject(None, None),
        }
    }
    async fn handle(&mut self, tx: &mut Transaction) -> crate::Result<()> {
        match self {
            Uas::New(d) => d.handle(tx).await,
            Uas::Legacy(d) => d.handle(tx).await,
        }
    }
    fn is_terminated(&self) -> bool {
        match self {
            Uas::New(d) => d.state().is_terminated(),
            Uas::Legacy(d) => d.state().is_terminated(),
        }
    }
}

struct Fixture {
    endpoint: Endpoint,
    invite: Request,
    dialog_id: DialogId,
    uas: Uas,
}

fn build_fixture(
    endpoint: Endpoint,
    legacy: bool,
    rel: UacRel,
    call_id: &str,
    tu_sender: TransactionEventSender,
) -> Fixture {
    let dialog_id = DialogId {
        call_id: call_id.to_string(),
        local_tag: "bob-tag".to_string(),
        remote_tag: "alice-tag".to_string(),
    };
    let invite = make_invite("127.0.0.1:5060", "z9hG4bK-inv", call_id, rel);
    let (state_sender, _state_receiver) = unbounded_channel();
    let inner = DialogInner::new(
        TransactionRole::Server,
        dialog_id.clone(),
        invite.clone(),
        endpoint.inner.clone(),
        state_sender,
        None,
        Some(crate::sip::Uri::try_from("sip:bob@127.0.0.1:5060").unwrap()),
        tu_sender,
    )
    .unwrap();
    Fixture {
        endpoint,
        invite,
        dialog_id,
        uas: Uas::build(legacy, inner),
    }
}

impl Fixture {
    /// Route a PRACK through the dialog and return the status it replied with
    /// (`None` when nothing was sent).
    async fn prack(&mut self, rack: Option<&str>, other_header: bool) -> Option<StatusCode> {
        let prack = make_prack(&self.invite, rack, &self.dialog_id.local_tag, other_header);
        let (mut tx, mut wire) = channel_tx(&self.endpoint, prack).await;
        self.uas.handle(&mut tx).await.unwrap();
        next_wire_response(&mut wire, Duration::from_millis(200))
            .await
            .map(|r| r.status_code)
    }
}

// ── Policy tests (inspecting the Respond events) ─────────────────────────

/// INVITE with `Require: 100rel`: reliable only when the app asks; RSeq is
/// exactly 1 for the first reliable provisional and 2 for the second; a plain
/// provisional is untracked (later PRACK → 481).
async fn require_invite_app_switch(legacy: bool) {
    let endpoint = create_endpoint().await;
    let (tu_sender, mut tu_rx) = unbounded_channel();
    let mut f = build_fixture(endpoint, legacy, UacRel::Require, "d1@test", tu_sender);

    f.uas
        .ringing(Some(vec![Header::Require("100rel".into())]), None)
        .unwrap();
    let r1 = next_respond(&mut tu_rx, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(r1.status_code, StatusCode::Ringing);
    assert!(has_100rel(&r1));
    let n = r1.rseq_value().expect("RSeq assigned");
    assert_eq!(n, 1, "first reliable provisional must carry RSeq: 1");
    assert_eq!(count_headers(&r1, "RSeq"), 1);
    assert_eq!(count_headers(&r1, "Require"), 1);

    f.uas
        .ringing(
            Some(vec![Header::Require("100rel".into())]),
            Some(b"v=0".to_vec()),
        )
        .unwrap();
    let r2 = next_respond(&mut tu_rx, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(r2.status_code, StatusCode::SessionProgress);
    assert_eq!(r2.rseq_value(), Some(2));

    // Unreliable provisional against a Require: 100rel INVITE: plain, warned, untracked.
    f.uas.ringing(None, None).unwrap();
    let r3 = next_respond(&mut tu_rx, Duration::from_millis(200))
        .await
        .unwrap();
    assert!(r3.rseq_value().is_none());
    assert!(!has_100rel(&r3));
    assert_eq!(
        f.prack(Some(&format!("{} 1 INVITE", n + 2)), false).await,
        Some(StatusCode::CallTransactionDoesNotExist)
    );
    assert!(
        next_forwarded_request(&mut tu_rx, Duration::from_millis(50))
            .await
            .is_none()
    );

    // The two reliable ones are still acknowledgeable.
    assert_eq!(
        f.prack(Some(&format!("{n} 1 INVITE")), false).await,
        Some(StatusCode::OK)
    );
    let fwd = next_forwarded_request(&mut tu_rx, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(fwd.method, Method::PRack);
    assert_eq!(
        f.prack(Some(&format!("{} 1 INVITE", n + 1)), true).await,
        Some(StatusCode::OK)
    );
    assert!(
        next_forwarded_request(&mut tu_rx, Duration::from_millis(200))
            .await
            .is_some()
    );
    // Acknowledged once only.
    assert_eq!(
        f.prack(Some(&format!("{n} 1 INVITE")), false).await,
        Some(StatusCode::CallTransactionDoesNotExist)
    );
}

#[tokio::test]
async fn require_invite_app_switch_invite_dialog() {
    require_invite_app_switch(false).await;
}

#[tokio::test]
async fn require_invite_app_switch_server_dialog() {
    require_invite_app_switch(true).await;
}

/// INVITE with `Supported: 100rel` only: plain unless the app passes
/// `Require: 100rel`. Then, through a real transaction, a reliable 183 is
/// tracked/retransmitted while a plain 180 goes out immediately.
async fn supported_only_mix(legacy: bool) {
    let endpoint = create_endpoint().await;
    let (tu_sender, mut tu_rx) = unbounded_channel();
    let mut f = build_fixture(endpoint, legacy, UacRel::Supported, "d2@test", tu_sender);

    f.uas.ringing(None, None).unwrap();
    let plain = next_respond(&mut tu_rx, Duration::from_millis(200))
        .await
        .unwrap();
    assert!(plain.rseq_value().is_none() && !has_100rel(&plain));

    f.uas
        .ringing(
            Some(vec![Header::Require("100rel".into())]),
            Some(b"v=0".to_vec()),
        )
        .unwrap();
    let reliable = next_respond(&mut tu_rx, Duration::from_millis(200))
        .await
        .unwrap();
    assert!(has_100rel(&reliable));
    let n = reliable.rseq_value().unwrap();
    assert_eq!(n, 1, "the plain 180 did not consume an RSeq");
    assert_eq!(
        f.prack(Some(&format!("{n} 1 INVITE")), false).await,
        Some(StatusCode::OK)
    );
    drop(f);

    // Mix through a real INVITE transaction: the dialog drives tx.tu_sender.
    let endpoint = create_endpoint().await;
    let serve_inner = endpoint.inner.clone();
    let serve = tokio::spawn(async move {
        let _ = serve_inner.serve().await;
    });
    let invite = make_invite(
        "127.0.0.1:5060",
        "z9hG4bK-mix",
        "d2-mix@test",
        UacRel::Supported,
    );
    let (mut tx, mut wire) = channel_tx(&endpoint, invite.clone()).await;
    let dialog_id = DialogId {
        call_id: "d2-mix@test".into(),
        local_tag: "bob-tag".into(),
        remote_tag: "alice-tag".into(),
    };
    let (state_sender, _state_rx) = unbounded_channel();
    let inner = DialogInner::new(
        TransactionRole::Server,
        dialog_id.clone(),
        invite.clone(),
        endpoint.inner.clone(),
        state_sender,
        None,
        Some(crate::sip::Uri::try_from("sip:bob@127.0.0.1:5060").unwrap()),
        tx.tu_sender.clone(),
    )
    .unwrap();
    let mut uas = Uas::build(legacy, inner);

    uas.ringing(
        Some(vec![Header::Require("100rel".into())]),
        Some(b"v=0".to_vec()),
    )
    .unwrap();
    uas.ringing(None, None).unwrap();
    assert!(timeout(Duration::from_millis(100), tx.receive())
        .await
        .is_err());
    let w183 = next_wire_response(&mut wire, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(w183.status_code, StatusCode::SessionProgress);
    let n = w183.rseq_value().expect("183 reliable");
    assert_eq!(n, 1);
    let w180 = next_wire_response(&mut wire, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(
        w180.status_code,
        StatusCode::Ringing,
        "plain 180 goes out while the 183 is unacked"
    );
    assert!(w180.rseq_value().is_none() && !has_100rel(&w180));
    assert_eq!(tx.rel1xx_unacked_rseq(), Some(n));

    // PRACK via the dialog is forwarded and acknowledges the 183 in the transaction.
    let prack = make_prack(
        &invite,
        Some(&format!("{n} 1 INVITE")),
        &dialog_id.local_tag,
        false,
    );
    let (mut ptx, mut pwire) = channel_tx(&endpoint, prack).await;
    uas.handle(&mut ptx).await.unwrap();
    assert_eq!(
        next_wire_response(&mut pwire, Duration::from_millis(200))
            .await
            .map(|r| r.status_code),
        Some(StatusCode::OK)
    );
    assert!(timeout(Duration::from_millis(100), tx.receive())
        .await
        .is_err());
    assert_eq!(tx.rel1xx_unacked_rseq(), None);

    // Held 2xx is not needed here (183 acked); accept goes straight out.
    uas.accept(None, Some(b"v=0 answer".to_vec())).unwrap();
    assert!(timeout(Duration::from_millis(100), tx.receive())
        .await
        .is_err());
    let w200 = next_wire_response(&mut wire, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(w200.status_code, StatusCode::OK);
    serve.abort();
}

#[tokio::test]
async fn supported_only_mix_invite_dialog() {
    supported_only_mix(false).await;
}

#[tokio::test]
async fn supported_only_mix_server_dialog() {
    supported_only_mix(true).await;
}

/// INVITE advertising neither Supported nor Require: the app's
/// `Require: 100rel` is stripped and no RSeq is assigned; other tokens survive.
async fn neither_advertised_stripped(legacy: bool) {
    let endpoint = create_endpoint().await;
    let (tu_sender, mut tu_rx) = unbounded_channel();
    let mut f = build_fixture(endpoint, legacy, UacRel::None, "d3@test", tu_sender);
    f.uas
        .ringing(
            Some(vec![
                Header::Require("100rel, timer".into()),
                Header::RSeq("5".into()),
            ]),
            Some(b"v=0".to_vec()),
        )
        .unwrap();
    let r = next_respond(&mut tu_rx, Duration::from_millis(200))
        .await
        .unwrap();
    assert!(r.rseq_value().is_none());
    assert!(!has_100rel(&r));
    assert!(r.header_contains_token("Require", "timer"));
    // Only the 100rel token is removed; the rest keeps its original text.
    assert_eq!(raw_header(&r, "Require").as_deref(), Some("timer"));
    assert_eq!(
        f.prack(Some("5 1 INVITE"), false).await,
        Some(StatusCode::CallTransactionDoesNotExist)
    );
}

#[tokio::test]
async fn neither_advertised_stripped_invite_dialog() {
    neither_advertised_stripped(false).await;
}

#[tokio::test]
async fn neither_advertised_stripped_server_dialog() {
    neither_advertised_stripped(true).await;
}

/// App-supplied RSeq (typed or `Header::Other`) is ignored; exactly one RSeq
/// and one Require end up on the response; PRACK matching uses the
/// library-generated value.
async fn app_rseq_ignored(legacy: bool) {
    let endpoint = create_endpoint().await;
    let (tu_sender, mut tu_rx) = unbounded_channel();
    let mut f = build_fixture(endpoint, legacy, UacRel::Supported, "d4@test", tu_sender);

    f.uas
        .ringing(
            Some(vec![
                Header::Require("100rel".into()),
                Header::RSeq("5".into()),
            ]),
            None,
        )
        .unwrap();
    let r = next_respond(&mut tu_rx, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(
        r.rseq_value(),
        Some(1),
        "library-generated RSeq: 1, not the app's 5"
    );
    assert_eq!(count_headers(&r, "RSeq"), 1);
    assert_eq!(count_headers(&r, "Require"), 1);
    assert_eq!(
        f.prack(Some("5 1 INVITE"), false).await,
        Some(StatusCode::CallTransactionDoesNotExist)
    );
    assert!(
        next_forwarded_request(&mut tu_rx, Duration::from_millis(50))
            .await
            .is_none()
    );
    assert_eq!(
        f.prack(Some("1 1 INVITE"), false).await,
        Some(StatusCode::OK)
    );
    let fwd = next_forwarded_request(&mut tu_rx, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(fwd.rack_value(), Some((1, 1, Method::Invite)));

    // Untyped forms are honoured too, and application headers are never
    // reformatted: the Supported header keeps its exact spacing.
    f.uas
        .ringing(
            Some(vec![
                Header::Other("Require".into(), "100rel".into()),
                Header::Other("RSeq".into(), "5".into()),
                Header::Supported("100rel,path,replaces".into()),
            ]),
            None,
        )
        .unwrap();
    let r = next_respond(&mut tu_rx, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(r.rseq_value(), Some(2));
    assert_eq!(count_headers(&r, "RSeq"), 1);
    assert_eq!(count_headers(&r, "Require"), 1);
    assert_eq!(raw_header(&r, "Require").as_deref(), Some("100rel"));
    assert_eq!(
        raw_header(&r, "Supported").as_deref(),
        Some("100rel,path,replaces"),
        "headers must not be normalized"
    );
    assert!(r.headers.iter().any(|h| matches!(h, Header::RSeq(_))));
}

/// Application headers reach the wire byte-for-byte: no token merging, no
/// re-spacing, whether typed or untyped, reliable or not.
async fn app_headers_pass_through_verbatim(legacy: bool) {
    let endpoint = create_endpoint().await;
    let (tu_sender, mut tu_rx) = unbounded_channel();
    let mut f = build_fixture(endpoint, legacy, UacRel::Supported, "d5@test", tu_sender);

    // Reliable: Require kept verbatim, RSeq added by the library.
    f.uas
        .ringing(
            Some(vec![
                Header::Require("100rel,timer".into()),
                Header::Supported("100rel,path,replaces".into()),
                Header::Other("P-Custom".into(), " a ,b,  c".into()),
            ]),
            None,
        )
        .unwrap();
    let r = next_respond(&mut tu_rx, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(r.rseq_value(), Some(1));
    assert_eq!(raw_header(&r, "Require").as_deref(), Some("100rel,timer"));
    assert_eq!(
        raw_header(&r, "Supported").as_deref(),
        Some("100rel,path,replaces")
    );
    assert_eq!(raw_header(&r, "P-Custom").as_deref(), Some(" a ,b,  c"));

    // Unreliable: everything passes through untouched, nothing added.
    assert_eq!(
        f.prack(Some("1 1 INVITE"), false).await,
        Some(StatusCode::OK)
    );
    // Drain the PRACK forwarded to the INVITE transaction.
    assert!(
        next_forwarded_request(&mut tu_rx, Duration::from_millis(200))
            .await
            .is_some()
    );
    f.uas
        .ringing(
            Some(vec![
                Header::Supported("100rel,path,replaces".into()),
                Header::Require("timer".into()),
            ]),
            None,
        )
        .unwrap();
    let r = next_respond(&mut tu_rx, Duration::from_millis(200))
        .await
        .unwrap();
    assert!(r.rseq_value().is_none());
    assert_eq!(raw_header(&r, "Require").as_deref(), Some("timer"));
    assert_eq!(
        raw_header(&r, "Supported").as_deref(),
        Some("100rel,path,replaces")
    );
}

#[tokio::test]
async fn app_headers_pass_through_verbatim_invite_dialog() {
    app_headers_pass_through_verbatim(false).await;
}

#[tokio::test]
async fn app_headers_pass_through_verbatim_server_dialog() {
    app_headers_pass_through_verbatim(true).await;
}

#[tokio::test]
async fn app_rseq_ignored_invite_dialog() {
    app_rseq_ignored(false).await;
}

#[tokio::test]
async fn app_rseq_ignored_server_dialog() {
    app_rseq_ignored(true).await;
}

/// PRACK matching: 200 for the outstanding RSeq, 481 otherwise, 400 without
/// RAck; a reliable provisional stays acknowledgeable after reject() (RFC 3262
/// §3: the UAS MUST be prepared to process PRACKs for outstanding responses
/// after sending a final).
async fn prack_matching(legacy: bool) {
    let endpoint = create_endpoint().await;
    let (tu_sender, mut tu_rx) = unbounded_channel();
    let mut f = build_fixture(endpoint, legacy, UacRel::Require, "d5@test", tu_sender);
    f.uas
        .ringing(Some(vec![Header::Require("100rel".into())]), None)
        .unwrap();
    let n = next_respond(&mut tu_rx, Duration::from_millis(200))
        .await
        .unwrap()
        .rseq_value()
        .unwrap();

    assert_eq!(f.prack(None, false).await, Some(StatusCode::BadRequest));
    assert_eq!(
        f.prack(Some("garbage"), false).await,
        Some(StatusCode::BadRequest)
    );
    assert_eq!(
        f.prack(Some(&format!("{} 1 INVITE", n + 7)), false).await,
        Some(StatusCode::CallTransactionDoesNotExist)
    );
    assert_eq!(
        f.prack(Some(&format!("{n} 2 INVITE")), false).await,
        Some(StatusCode::CallTransactionDoesNotExist)
    );
    assert_eq!(
        f.prack(Some(&format!("{n} 1 UPDATE")), false).await,
        Some(StatusCode::CallTransactionDoesNotExist)
    );
    assert!(
        next_forwarded_request(&mut tu_rx, Duration::from_millis(50))
            .await
            .is_none()
    );
    assert_eq!(
        f.prack(Some(&format!("{n} 1 INVITE")), false).await,
        Some(StatusCode::OK)
    );
    assert!(
        next_forwarded_request(&mut tu_rx, Duration::from_millis(200))
            .await
            .is_some()
    );

    // A reliable provisional that was sent but never PRACKed stays
    // acknowledgeable after reject().
    f.uas
        .ringing(Some(vec![Header::Require("100rel".into())]), None)
        .unwrap();
    let r = next_respond(&mut tu_rx, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(r.rseq_value(), Some(n + 1));
    f.uas.reject().unwrap();
    assert!(f.uas.is_terminated());
    let r603 = next_respond(&mut tu_rx, Duration::from_millis(200))
        .await
        .expect("reject's final response");
    assert_eq!(r603.status_code, StatusCode::Decline);
    assert_eq!(
        f.prack(Some(&format!("{} 1 INVITE", n + 1)), false).await,
        Some(StatusCode::OK),
        "PRACK for a sent, unacknowledged reliable 1xx must get 200 after a final"
    );
    let fwd = next_forwarded_request(&mut tu_rx, Duration::from_millis(200))
        .await
        .expect("PRACK forwarded to the INVITE transaction");
    assert_eq!(fwd.method, Method::PRack);
    // Acknowledged once only.
    assert_eq!(
        f.prack(Some(&format!("{} 1 INVITE", n + 1)), false).await,
        Some(StatusCode::CallTransactionDoesNotExist)
    );
    assert!(
        next_forwarded_request(&mut tu_rx, Duration::from_millis(50))
            .await
            .is_none()
    );
    // accept() after termination is a no-op (no Respond event).
    f.uas.accept(None, None).unwrap();
    assert!(next_respond(&mut tu_rx, Duration::from_millis(100))
        .await
        .is_none());
}

/// Reliable 180 through a real INVITE transaction, no PRACK: after 64*T1 the
/// transaction sends a 500 (same To tag), the dialog's handle loop turns it
/// into `Terminated(PrackTimeout)`, a held 2xx never reaches the wire, a later
/// accept() is a no-op, and the outstanding 180 is still PRACK-able (200).
async fn prack_timeout_terminates_dialog(legacy: bool) {
    let endpoint = create_endpoint().await;
    let serve_inner = endpoint.inner.clone();
    let serve = tokio::spawn(async move {
        let _ = serve_inner.serve().await;
    });
    let call_id = if legacy { "d6-legacy@test" } else { "d6@test" };
    let invite = make_invite("127.0.0.1:5060", "z9hG4bK-to", call_id, UacRel::Require);
    let (mut tx, mut wire) = channel_tx(&endpoint, invite.clone()).await;
    let dialog_id = DialogId {
        call_id: call_id.into(),
        local_tag: "bob-tag".into(),
        remote_tag: "alice-tag".into(),
    };
    let (state_sender, mut state_rx) = unbounded_channel();
    let inner = DialogInner::new(
        TransactionRole::Server,
        dialog_id.clone(),
        invite.clone(),
        endpoint.inner.clone(),
        state_sender,
        None,
        Some(crate::sip::Uri::try_from("sip:bob@127.0.0.1:5060").unwrap()),
        tx.tu_sender.clone(),
    )
    .unwrap();
    let mut uas = Uas::build(legacy, inner);
    let app = uas.clone_handle();
    let handle_task = tokio::spawn(async move { uas.handle(&mut tx).await });

    app.ringing(
        Some(vec![Header::Require("100rel".into())]),
        Some(b"v=0".to_vec()),
    )
    .unwrap();
    // The legacy loop sends a 100 Trying first; skip it.
    let w183 = loop {
        let r = next_wire_response(&mut wire, Duration::from_millis(500))
            .await
            .expect("reliable 183 on the wire");
        if r.status_code != StatusCode::Trying {
            break r;
        }
    };
    assert_eq!(w183.status_code, StatusCode::SessionProgress);
    let rseq = w183.rseq_value().expect("RSeq");
    assert_eq!(rseq, 1);
    let to_tag = to_tag_of(&w183);
    // Accept while the body-carrying 183 is unacked: the 2xx is held.
    app.accept(None, Some(b"v=0 answer".to_vec())).unwrap();

    let started = Instant::now();
    let w500 = loop {
        let r = next_wire_response(&mut wire, T1X64 + Duration::from_secs(2))
            .await
            .expect("500 after the PRACK timeout");
        assert_ne!(r.status_code, StatusCode::OK, "held 2xx must never be sent");
        if r.status_code == StatusCode::ServerInternalError {
            break r;
        }
    };
    assert!(started.elapsed() < T1X64 + Duration::from_secs(1));
    assert_eq!(
        w500.cseq_header().unwrap().method().unwrap(),
        Method::Invite
    );
    assert_eq!(to_tag_of(&w500), to_tag);

    let reason = loop {
        match timeout(Duration::from_secs(2), state_rx.recv()).await {
            Ok(Some(DialogState::Terminated(_, reason))) => break Some(reason),
            Ok(Some(_)) => {}
            _ => break None,
        }
    };
    assert!(
        matches!(reason, Some(TerminatedReason::PrackTimeout)),
        "got {reason:?}"
    );
    assert!(app.is_terminated());

    // accept() after termination puts nothing new on the wire.
    app.accept(None, None).unwrap();
    assert!(
        next_wire_response(&mut wire, Duration::from_millis(200))
            .await
            .map(|r| r.status_code != StatusCode::OK)
            .unwrap_or(true),
        "no 200 OK after termination"
    );

    // The sent-but-unacknowledged 183 is still PRACK-able (RFC 3262 §3).
    let prack = make_prack(
        &invite,
        Some(&format!("{rseq} 1 INVITE")),
        &dialog_id.local_tag,
        false,
    );
    let (mut ptx, mut pwire) = channel_tx(&endpoint, prack).await;
    let mut app = app;
    app.handle(&mut ptx).await.unwrap();
    assert_eq!(
        next_wire_response(&mut pwire, Duration::from_millis(200))
            .await
            .map(|r| r.status_code),
        Some(StatusCode::OK)
    );

    handle_task.abort();
    serve.abort();
}

#[tokio::test]
async fn prack_timeout_terminates_invite_dialog() {
    prack_timeout_terminates_dialog(false).await;
}

#[tokio::test]
async fn prack_timeout_terminates_server_dialog() {
    prack_timeout_terminates_dialog(true).await;
}

#[tokio::test]
async fn prack_matching_invite_dialog() {
    prack_matching(false).await;
}

#[tokio::test]
async fn prack_matching_server_dialog() {
    prack_matching(true).await;
}

// ── End-to-end over UDP through DialogLayer ──────────────────────────────

struct E2e {
    server_addr: SipAddr,
    client: UdpConnection,
    dialogs: UnboundedReceiver<InviteDialog>,
    states: UnboundedReceiver<DialogState>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for E2e {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl E2e {
    async fn start() -> Self {
        Self::start_with(false).await
    }

    /// `legacy` runs the INVITE transaction through the deprecated
    /// `ServerInviteDialog::handle` loop instead of `Dialog::Invite`.
    async fn start_with(legacy: bool) -> Self {
        let token = CancellationToken::new();
        let server_conn =
            UdpConnection::create_connection("127.0.0.1:0".parse().unwrap(), None, None)
                .await
                .unwrap();
        let server_sip: SipConnection = server_conn.into();
        let server_addr = server_sip.get_addr().clone();
        let tl = TransportLayer::new(token.child_token());
        tl.add_transport(server_sip);
        let endpoint = EndpointBuilder::new()
            .with_user_agent("rsipstack-test")
            .with_transport_layer(tl)
            .with_option(test_option())
            .build();
        let mut incoming = endpoint.incoming_transactions().unwrap();
        let serve_inner = endpoint.inner.clone();
        let serve = tokio::spawn(async move {
            let _ = serve_inner.serve().await;
        });

        let dialog_layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
        let (state_sender, states) = unbounded_channel();
        let (dialog_tx, dialogs) = unbounded_channel();
        let contact =
            crate::sip::Uri::try_from(format!("sip:bob@{}", server_addr.addr).as_str()).unwrap();
        // Dispatch loop modelled on the consumer's `handle_incoming_transaction`.
        let dispatch = tokio::spawn(async move {
            while let Some(mut tx) = incoming.recv().await {
                if let Some(mut dialog) = dialog_layer.match_dialog(&tx) {
                    tokio::spawn(async move {
                        dialog.handle(&mut tx).await.ok();
                    });
                    continue;
                }
                if tx.original.method == Method::Invite {
                    let dlg = dialog_layer
                        .get_or_create_server_invite(
                            &tx,
                            state_sender.clone(),
                            None,
                            Some(contact.clone()),
                        )
                        .unwrap();
                    dialog_tx.send(dlg.clone()).ok();
                    if legacy {
                        let mut managed = ServerInviteDialog::from_inner(dlg.inner.clone());
                        tokio::spawn(async move {
                            managed.handle(&mut tx).await.ok();
                        });
                    } else {
                        let mut managed = Dialog::Invite(dlg);
                        tokio::spawn(async move {
                            managed.handle(&mut tx).await.ok();
                        });
                    }
                }
            }
        });
        let client = UdpConnection::create_connection("127.0.0.1:0".parse().unwrap(), None, None)
            .await
            .unwrap();
        E2e {
            server_addr,
            client,
            dialogs,
            states,
            tasks: vec![serve, dispatch],
        }
    }

    async fn send(&self, req: Request) {
        let client: SipConnection = self.client.clone().into();
        client
            .send(req.into(), Some(&self.server_addr))
            .await
            .unwrap();
    }

    async fn recv(&self, d: Duration) -> Option<Response> {
        let mut buf = vec![0u8; 4096];
        match timeout(d, self.client.recv_raw(&mut buf)).await {
            Ok(Ok((len, _))) => match SipMessage::try_from(&buf[..len]).ok()? {
                SipMessage::Response(r) => Some(r),
                SipMessage::Request(_) => None,
            },
            _ => None,
        }
    }

    /// Receive until a response with `status` arrives; returns it and how many
    /// 183s were seen meanwhile.
    async fn recv_until(&self, status: StatusCode, d: Duration) -> (Option<Response>, usize) {
        let deadline = Instant::now() + d;
        let mut seen_183 = 0;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return (None, seen_183);
            }
            match self.recv(remaining).await {
                Some(r) if r.status_code == status => return (Some(r), seen_183),
                Some(r) if r.status_code == StatusCode::SessionProgress => seen_183 += 1,
                Some(_) => {}
                None => return (None, seen_183),
            }
        }
    }

    /// Receive until a response with `status` whose CSeq method is `method`.
    async fn recv_until_method(
        &self,
        status: StatusCode,
        method: Method,
        d: Duration,
    ) -> Option<Response> {
        let deadline = Instant::now() + d;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match self.recv(remaining).await {
                Some(r)
                    if r.status_code == status
                        && r.cseq_header().ok()?.method().ok()? == method =>
                {
                    return Some(r)
                }
                Some(_) => {}
                None => return None,
            }
        }
    }

    fn invite(&self, call_id: &str) -> Request {
        make_invite(
            &self.client.get_addr().addr.to_string(),
            &format!("z9hG4bK-e2e-{call_id}"),
            call_id,
            UacRel::Require,
        )
    }

    async fn wait_terminated(&mut self, d: Duration) -> Option<TerminatedReason> {
        let deadline = Instant::now() + d;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match timeout(remaining, self.states.recv()).await {
                Ok(Some(DialogState::Terminated(_, reason))) => return Some(reason),
                Ok(Some(_)) => {}
                _ => return None,
            }
        }
    }
}

fn make_cancel(invite: &Request) -> Request {
    let keep = |h: &Header| {
        matches!(
            h,
            Header::Via(_)
                | Header::From(_)
                | Header::To(_)
                | Header::CallId(_)
                | Header::MaxForwards(_)
        )
    };
    let mut headers: Vec<Header> = invite.headers.iter().filter(|h| keep(h)).cloned().collect();
    headers.push(CSeq::new("1 CANCEL").into());
    Request {
        method: Method::Cancel,
        uri: invite.uri.clone(),
        headers: headers.into(),
        version: crate::sip::Version::V2,
        body: vec![],
    }
}

fn sdp_headers() -> Vec<Header> {
    vec![
        Header::Require("100rel".into()),
        Header::Supported("100rel, timer".into()),
        Header::ContentType("application/sdp".into()),
    ]
}

/// INVITE(Require: 100rel) → 100 → reliable 183 retransmitted → PRACK → 200 OK
/// to the PRACK, retransmissions stop → accept() → 200 OK to the INVITE.
#[tokio::test]
async fn e2e_udp_reliable_183_prack_then_accept() {
    let mut e = E2e::start().await;
    let invite = e.invite("e2e-ok");
    e.send(invite.clone()).await;
    let (trying, _) = e
        .recv_until(StatusCode::Trying, Duration::from_secs(2))
        .await;
    assert!(trying.is_some(), "100 Trying");
    let dlg = timeout(Duration::from_secs(2), e.dialogs.recv())
        .await
        .unwrap()
        .unwrap();

    dlg.ringing(
        Some(sdp_headers()),
        Some(b"v=0\r\no=bob 1 1 IN IP4 127.0.0.1\r\n".to_vec()),
    )
    .unwrap();
    let (first, _) = e
        .recv_until(StatusCode::SessionProgress, Duration::from_secs(2))
        .await;
    let first = first.expect("reliable 183");
    let rseq = first.rseq_value().expect("RSeq");
    assert!(has_100rel(&first));
    let to_tag = to_tag_of(&first);
    assert!(!to_tag.is_empty());
    let (second, _) = e
        .recv_until(StatusCode::SessionProgress, Duration::from_secs(1))
        .await;
    let second = second.expect("183 retransmitted over UDP");
    assert_eq!(second.rseq_value(), Some(rseq));

    // PRACK it.
    e.send(make_prack(
        &invite,
        Some(&format!("{rseq} 1 INVITE")),
        &to_tag,
        false,
    ))
    .await;
    let (ok, _) = e.recv_until(StatusCode::OK, Duration::from_secs(2)).await;
    let ok = ok.expect("200 OK to PRACK");
    assert_eq!(ok.cseq_header().unwrap().method().unwrap(), Method::PRack);

    // Retransmissions stop: drain in-flight copies, then silence.
    let _ = e
        .recv_until(StatusCode::Trying, Duration::from_millis(80))
        .await;
    let (_, late) = e.recv_until(StatusCode::Trying, T1 * 20).await;
    assert_eq!(late, 0, "183 must not be retransmitted after the PRACK");

    // Accept → 200 OK to the INVITE.
    dlg.accept(
        Some(vec![Header::ContentType("application/sdp".into())]),
        Some(b"v=0 answer".to_vec()),
    )
    .unwrap();
    let (ok, _) = e.recv_until(StatusCode::OK, Duration::from_secs(2)).await;
    let ok = ok.expect("200 OK to INVITE");
    assert_eq!(ok.cseq_header().unwrap().method().unwrap(), Method::Invite);
    assert_eq!(to_tag_of(&ok), to_tag);
    assert!(matches!(dlg.state(), DialogState::WaitAck(_, _)));
}

/// No PRACK → after 64*T1 the client receives a 500 carrying the 183's To tag
/// and the dialog terminates with `PrackTimeout`; a held 2xx is never sent; the
/// unacknowledged 183 is still PRACK-able afterwards (RFC 3262 §3).
async fn e2e_udp_prack_timeout_rejects_with_500(legacy: bool) {
    let mut e = E2e::start_with(legacy).await;
    let invite = e.invite(if legacy {
        "e2e-timeout-legacy"
    } else {
        "e2e-timeout"
    });
    e.send(invite.clone()).await;
    let dlg = timeout(Duration::from_secs(2), e.dialogs.recv())
        .await
        .unwrap()
        .unwrap();
    dlg.ringing(Some(sdp_headers()), Some(b"v=0".to_vec()))
        .unwrap();
    let (first, _) = e
        .recv_until(StatusCode::SessionProgress, Duration::from_secs(2))
        .await;
    let first = first.expect("reliable 183");
    let rseq = first.rseq_value().expect("RSeq");
    assert_eq!(rseq, 1);
    let to_tag = to_tag_of(&first);
    // The app accepts while the body-carrying 183 is unacked: the 2xx is held.
    dlg.accept(None, None).unwrap();

    let started = Instant::now();
    let (resp500, retransmissions) = e
        .recv_until(StatusCode::ServerInternalError, Duration::from_secs(4))
        .await;
    let resp500 = resp500.expect("500 after PRACK timeout");
    assert_eq!(to_tag_of(&resp500), to_tag);
    assert_eq!(
        resp500.cseq_header().unwrap().method().unwrap(),
        Method::Invite
    );
    assert!(
        retransmissions >= 3,
        "183 retransmitted before the timeout, got {retransmissions}"
    );
    assert!(started.elapsed() < T1X64 + Duration::from_secs(1));

    let reason = e.wait_terminated(Duration::from_secs(2)).await;
    assert!(
        matches!(reason, Some(TerminatedReason::PrackTimeout)),
        "got {reason:?}"
    );
    assert!(dlg.state().is_terminated());
    // The held 200 never reached the wire.
    let (ok, _) = e
        .recv_until(StatusCode::OK, Duration::from_millis(200))
        .await;
    assert!(ok.is_none(), "held 2xx must not be sent after the timeout");

    // A late PRACK for the 183 that was sent but never acknowledged gets 200.
    e.send(make_prack(
        &invite,
        Some(&format!("{rseq} 1 INVITE")),
        &to_tag,
        false,
    ))
    .await;
    let ok = e
        .recv_until_method(StatusCode::OK, Method::PRack, Duration::from_secs(2))
        .await;
    assert!(ok.is_some(), "PRACK after the 500 must be answered 200 OK");
}

#[tokio::test]
async fn e2e_udp_prack_timeout_rejects_with_500_invite_dialog() {
    e2e_udp_prack_timeout_rejects_with_500(false).await;
}

#[tokio::test]
async fn e2e_udp_prack_timeout_rejects_with_500_server_dialog() {
    e2e_udp_prack_timeout_rejects_with_500(true).await;
}

/// INVITE(Require: 100rel) → reliable 183 → CANCEL through the INVITE
/// transaction → 487, `Terminated(UacCancel)`; a late PRACK for the 183 is
/// still answered 200 (RFC 3262 §3) and only once.
async fn e2e_udp_cancel_keeps_183_prackable(legacy: bool) {
    let mut e = E2e::start_with(legacy).await;
    let invite = e.invite(if legacy {
        "e2e-cancel-legacy"
    } else {
        "e2e-cancel"
    });
    e.send(invite.clone()).await;
    let dlg = timeout(Duration::from_secs(2), e.dialogs.recv())
        .await
        .unwrap()
        .unwrap();
    dlg.ringing(Some(sdp_headers()), Some(b"v=0".to_vec()))
        .unwrap();
    let (first, _) = e
        .recv_until(StatusCode::SessionProgress, Duration::from_secs(2))
        .await;
    let first = first.expect("reliable 183");
    let rseq = first.rseq_value().expect("RSeq");
    let to_tag = to_tag_of(&first);

    e.send(make_cancel(&invite)).await;
    let resp487 = e
        .recv_until_method(
            StatusCode::RequestTerminated,
            Method::Invite,
            Duration::from_secs(2),
        )
        .await
        .expect("487 to the INVITE");
    assert_eq!(to_tag_of(&resp487), to_tag);
    let reason = e.wait_terminated(Duration::from_secs(2)).await;
    assert!(
        matches!(reason, Some(TerminatedReason::UacCancel)),
        "got {reason:?}"
    );
    assert!(dlg.state().is_terminated());

    e.send(make_prack(
        &invite,
        Some(&format!("{rseq} 1 INVITE")),
        &to_tag,
        false,
    ))
    .await;
    let ok = e
        .recv_until_method(StatusCode::OK, Method::PRack, Duration::from_secs(2))
        .await;
    assert!(ok.is_some(), "PRACK after the 487 must be answered 200 OK");

    // Acknowledged once only: a second PRACK for the same RSeq gets 481.
    e.send(make_prack(
        &invite,
        Some(&format!("{rseq} 1 INVITE")),
        &to_tag,
        false,
    ))
    .await;
    let r481 = e
        .recv_until_method(
            StatusCode::CallTransactionDoesNotExist,
            Method::PRack,
            Duration::from_secs(2),
        )
        .await;
    assert!(
        r481.is_some(),
        "second PRACK for the same RSeq must get 481"
    );
}

#[tokio::test]
async fn e2e_udp_cancel_keeps_183_prackable_invite_dialog() {
    e2e_udp_cancel_keeps_183_prackable(false).await;
}

#[tokio::test]
async fn e2e_udp_cancel_keeps_183_prackable_server_dialog() {
    e2e_udp_cancel_keeps_183_prackable(true).await;
}
