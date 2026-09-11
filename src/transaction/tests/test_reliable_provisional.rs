//! RFC 3262 (100rel) UAS behaviour at the transaction layer.
//!
//! Timers are shrunk via `EndpointOption` (T1 = 20ms, 64*T1 = 1280ms) so the
//! tests finish in a few seconds; every wait is bounded by `tokio::time::timeout`.

use crate::sip::headers::*;
use crate::sip::prelude::*;
use crate::sip::{Header, Method, Request, Response, SipMessage, StatusCode, StatusCodeKind};
use crate::transaction::endpoint::{Endpoint, EndpointBuilder, EndpointOption};
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::transaction::transaction::{Transaction, TransactionEvent};
use crate::transaction::{TransactionState, TransactionTimer};
use crate::transport::{
    channel::ChannelConnection, connection::TransportEvent, udp::UdpConnection, SipAddr,
    SipConnection, TransportLayer,
};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const T1: Duration = Duration::from_millis(20);
const T1X64: Duration = Duration::from_millis(20 * 64);
const SRV_TAG: &str = "srv-tag-100rel";

fn test_option() -> EndpointOption {
    EndpointOption {
        t1: T1,
        t1x64: T1X64,
        ..Default::default()
    }
}

fn build_endpoint(tl: TransportLayer) -> Endpoint {
    EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .with_option(test_option())
        .build()
}

fn make_invite(via_host: &str, branch: &str, to_tag: Option<&str>, call_id: &str) -> Request {
    let to = match to_tag {
        Some(tag) => format!("Bob <sip:bob@example.com>;tag={tag}"),
        None => "Bob <sip:bob@example.com>".to_string(),
    };
    Request {
        method: Method::Invite,
        uri: crate::sip::Uri::try_from("sip:bob@example.com").unwrap(),
        headers: vec![
            Via::new(format!("SIP/2.0/UDP {via_host};branch={branch}")).into(),
            CSeq::new("1 INVITE").into(),
            From::new("Alice <sip:alice@example.com>;tag=alice-tag").into(),
            To::new(to).into(),
            CallId::new(call_id).into(),
            Contact::new("<sip:alice@127.0.0.1:5060>").into(),
            MaxForwards::new("70").into(),
            Header::Supported("100rel".into()),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: Default::default(),
    }
}

/// Build a response to `tx.original` with a To tag, optional `Require: 100rel`
/// and optional body — the way a dialog layer / raw TU would hand it in.
fn make_resp(
    tx: &Transaction,
    status: StatusCode,
    reliable: bool,
    body: Option<Vec<u8>>,
) -> Response {
    let mut resp = tx.endpoint_inner.make_response(&tx.original, status, body);
    let to = resp.to_header().unwrap().clone();
    if to.tag().unwrap().is_none() {
        resp.headers
            .unique_push(to.with_tag(SRV_TAG.to_string().into()).into());
    }
    if reliable {
        resp.headers.unique_push(Header::Require("100rel".into()));
    }
    resp
}

fn make_prack(invite: &Request, rack: &str, to_tag: &str, other_header: bool) -> Request {
    let call_id = invite.call_id_header().unwrap().clone();
    let from = invite.from_header().unwrap().clone();
    let rack_header = if other_header {
        Header::Other("RAck".into(), rack.into())
    } else {
        Header::RAck(rack.into())
    };
    Request {
        method: Method::PRack,
        uri: invite.uri.clone(),
        headers: vec![
            Via::new("SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKprack-branch").into(),
            CSeq::new("2 PRACK").into(),
            from.into(),
            To::new(format!("Bob <sip:bob@example.com>;tag={to_tag}")).into(),
            call_id.into(),
            rack_header,
            MaxForwards::new("70").into(),
        ]
        .into(),
        version: crate::sip::Version::V2,
        body: vec![],
    }
}

fn to_tag_of(resp: &Response) -> String {
    resp.to_header()
        .unwrap()
        .tag()
        .unwrap()
        .map(|t| t.value().to_string())
        .unwrap_or_default()
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

/// Drive `tx.receive()` for at most `d`; returns what it surfaced, if anything.
async fn pump(tx: &mut Transaction, d: Duration) -> Option<SipMessage> {
    timeout(d, tx.receive()).await.ok().flatten()
}

// ── Channel (reliable transport) harness ─────────────────────────────────

struct ChannelHarness {
    _endpoint: Endpoint,
    tx: Transaction,
    wire: UnboundedReceiver<TransportEvent>,
    serve: JoinHandle<()>,
}

impl Drop for ChannelHarness {
    fn drop(&mut self) {
        self.serve.abort();
    }
}

async fn channel_harness(invite: Request) -> ChannelHarness {
    let token = CancellationToken::new();
    let endpoint = build_endpoint(TransportLayer::new(token.child_token()));
    let inner = endpoint.inner.clone();
    let serve = tokio::spawn(async move {
        let _ = inner.serve().await;
    });

    let (_incoming_tx, incoming_rx) = unbounded_channel();
    let (transport_tx, wire) = unbounded_channel();
    let addr: SipAddr = crate::sip::HostWithPort::try_from("127.0.0.1:5060")
        .unwrap()
        .into();
    let channel =
        ChannelConnection::create_connection(incoming_rx, transport_tx, addr.clone(), None)
            .await
            .unwrap();
    let key = TransactionKey::from_request(&invite, TransactionRole::Server).unwrap();
    let mut tx = Transaction::new_server(
        key,
        invite,
        endpoint.inner.clone(),
        Some(SipConnection::Channel(channel)),
    );
    tx.destination = Some(addr);
    ChannelHarness {
        _endpoint: endpoint,
        tx,
        wire,
        serve,
    }
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

// ── UDP (unreliable transport) harness ────────────────────────────────────

struct UdpHarness {
    endpoint: Endpoint,
    server_addr: SipAddr,
    client: UdpConnection,
    serve: JoinHandle<()>,
}

impl Drop for UdpHarness {
    fn drop(&mut self) {
        self.serve.abort();
    }
}

async fn udp_harness() -> UdpHarness {
    udp_harness_with(test_option()).await
}

async fn udp_harness_with(option: EndpointOption) -> UdpHarness {
    let token = CancellationToken::new();
    let server_conn = UdpConnection::create_connection("127.0.0.1:0".parse().unwrap(), None, None)
        .await
        .unwrap();
    let server_sip: SipConnection = server_conn.into();
    let server_addr = server_sip.get_addr().clone();
    let tl = TransportLayer::new(token.child_token());
    tl.add_transport(server_sip);
    let endpoint = EndpointBuilder::new()
        .with_user_agent("rsipstack-test")
        .with_transport_layer(tl)
        .with_option(option)
        .build();
    let inner = endpoint.inner.clone();
    let serve = tokio::spawn(async move {
        let _ = inner.serve().await;
    });
    let client = UdpConnection::create_connection("127.0.0.1:0".parse().unwrap(), None, None)
        .await
        .unwrap();
    UdpHarness {
        endpoint,
        server_addr,
        client,
        serve,
    }
}

impl UdpHarness {
    fn client_host(&self) -> String {
        self.client.get_addr().addr.to_string()
    }

    async fn send_invite(&self, branch: &str, call_id: &str) -> (Request, Transaction) {
        let invite = make_invite(&self.client_host(), branch, None, call_id);
        let client_sip: SipConnection = self.client.clone().into();
        client_sip
            .send(invite.clone().into(), Some(&self.server_addr))
            .await
            .unwrap();
        let mut incoming = self.endpoint.incoming_transactions().unwrap();
        let tx = timeout(Duration::from_secs(2), incoming.recv())
            .await
            .expect("incoming transaction")
            .expect("transaction");
        (invite, tx)
    }

    async fn recv(&self, d: Duration) -> Option<SipMessage> {
        let mut buf = vec![0u8; 4096];
        match timeout(d, self.client.recv_raw(&mut buf)).await {
            Ok(Ok((len, _))) => SipMessage::try_from(&buf[..len]).ok(),
            _ => None,
        }
    }

    /// Collect responses with `status` for `d`, alongside pumping the transaction.
    async fn collect_status(
        &self,
        tx: &mut Transaction,
        status: StatusCode,
        d: Duration,
    ) -> Vec<(Instant, Response)> {
        let collector = async {
            let mut out = vec![];
            let deadline = Instant::now() + d;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match self.recv(remaining).await {
                    Some(SipMessage::Response(resp)) if resp.status_code == status => {
                        out.push((Instant::now(), resp));
                    }
                    Some(_) => {}
                    None => break,
                }
            }
            out
        };
        let (out, _) = tokio::join!(collector, pump(tx, d));
        out
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

/// RSeq is generated when absent and the first one is exactly
/// `INITIAL_RSEQ` (1); the next reliable 1xx after each PRACK is exactly +1
/// (2, then 3); a dialog-layer RSeq on the first reliable 1xx is used for
/// tracking.
#[tokio::test]
async fn rseq_generated_when_absent_and_dialog_value_tracked() {
    // Generated by the transaction.
    let invite = make_invite("127.0.0.1:5060", "z9hG4bK-rseq-1", None, "rseq-1@test");
    let mut h = channel_harness(invite.clone()).await;
    let resp183 = make_resp(&h.tx, StatusCode::SessionProgress, true, None);
    assert!(resp183.rseq_value().is_none());
    h.tx.respond(resp183).await.unwrap();
    let wire183 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("183 on the wire");
    let rseq = wire183.rseq_value().expect("RSeq assigned");
    assert_eq!(
        rseq, 1,
        "first RSeq of the transaction must be INITIAL_RSEQ"
    );
    assert_eq!(rseq, crate::transaction::INITIAL_RSEQ);
    assert_eq!(crate::transaction::make_rseq(), 1);
    assert!(has_100rel(&wire183));
    assert_eq!(count_headers(&wire183, "RSeq"), 1);
    assert_eq!(h.tx.state, TransactionState::Proceeding);
    assert_eq!(h.tx.rel1xx_unacked_rseq(), Some(rseq));
    assert_eq!(h.tx.rel1xx_timers_armed(), (false, true));

    let prack = make_prack(&invite, &format!("{rseq} 1 INVITE"), SRV_TAG, false);
    h.tx.tu_sender
        .send(TransactionEvent::Received(prack.into(), None))
        .unwrap();
    assert!(pump(&mut h.tx, Duration::from_millis(100)).await.is_none());
    assert_eq!(h.tx.rel1xx_unacked_rseq(), None);
    assert_eq!(h.tx.rel1xx_timers_armed(), (false, false));

    let resp180 = make_resp(&h.tx, StatusCode::Ringing, true, None);
    h.tx.respond(resp180).await.unwrap();
    let wire180 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("180 on the wire");
    assert_eq!(wire180.rseq_value(), Some(2));

    let prack = make_prack(&invite, "2 1 INVITE", SRV_TAG, false);
    h.tx.tu_sender
        .send(TransactionEvent::Received(prack.into(), None))
        .unwrap();
    assert!(pump(&mut h.tx, Duration::from_millis(100)).await.is_none());
    assert_eq!(h.tx.rel1xx_unacked_rseq(), None);
    let resp180 = make_resp(&h.tx, StatusCode::Ringing, true, None);
    h.tx.respond(resp180).await.unwrap();
    let wire180 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("second 180 on the wire");
    assert_eq!(wire180.rseq_value(), Some(3));

    // Supplied by the dialog layer (honoured for the first reliable 1xx).
    let invite = make_invite("127.0.0.1:5060", "z9hG4bK-rseq-2", None, "rseq-2@test");
    let mut h = channel_harness(invite.clone()).await;
    let mut resp183 = make_resp(&h.tx, StatusCode::SessionProgress, true, None);
    resp183.headers.unique_push(Header::RSeq("42".into()));
    h.tx.respond(resp183).await.unwrap();
    let wire183 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("183 on the wire");
    assert_eq!(wire183.rseq_value(), Some(42));
    assert_eq!(h.tx.rel1xx_unacked_rseq(), Some(42));

    // A PRACK carried as Header::Other("RAck") also matches.
    let prack = make_prack(&invite, "42 1 INVITE", SRV_TAG, true);
    h.tx.tu_sender
        .send(TransactionEvent::Received(prack.into(), None))
        .unwrap();
    assert!(pump(&mut h.tx, Duration::from_millis(100)).await.is_none());
    assert_eq!(h.tx.rel1xx_unacked_rseq(), None);

    let resp180 = make_resp(&h.tx, StatusCode::Ringing, true, None);
    h.tx.respond(resp180).await.unwrap();
    let wire180 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("180 on the wire");
    assert_eq!(wire180.rseq_value(), Some(43));
}

/// RFC 3262 §3 retransmission schedule, checked without wall-clock timing:
/// the armed timer is `TimerRel1xx(key, rseq, T1)`; every firing re-sends the
/// same 183 and re-arms with the doubled interval (T1*2, then T1*4; no T2 cap).
/// Uses huge real timers so only the injected events drive the transaction.
#[tokio::test]
async fn retransmit_timer_doubles_on_every_firing() {
    let big_t1 = Duration::from_secs(60);
    let h = udp_harness_with(EndpointOption {
        t1: big_t1,
        t1x64: big_t1 * 64,
        ..Default::default()
    })
    .await;
    let (_invite, mut tx) = h.send_invite("z9hG4bK-udp-dbl", "udp-dbl@test").await;
    let key = tx.key.clone();

    tx.respond(make_resp(&tx, StatusCode::SessionProgress, true, None))
        .await
        .unwrap();
    let first = h
        .collect_status(
            &mut tx,
            StatusCode::SessionProgress,
            Duration::from_millis(100),
        )
        .await;
    assert_eq!(first.len(), 1, "original 183 only");
    let rseq = first[0].1.rseq_value().expect("RSeq");
    assert_eq!(
        tx.rel1xx_retransmit_timer(),
        Some(TransactionTimer::TimerRel1xx(key.clone(), rseq, big_t1))
    );

    let mut interval = big_t1;
    for round in 1..=3u32 {
        tx.tu_sender
            .send(TransactionEvent::Timer(TransactionTimer::TimerRel1xx(
                key.clone(),
                rseq,
                interval,
            )))
            .unwrap();
        let copies = h
            .collect_status(
                &mut tx,
                StatusCode::SessionProgress,
                Duration::from_millis(100),
            )
            .await;
        assert_eq!(copies.len(), 1, "round {round}: exactly one retransmission");
        assert_eq!(copies[0].1.rseq_value(), Some(rseq));
        interval *= 2;
        assert_eq!(
            tx.rel1xx_retransmit_timer(),
            Some(TransactionTimer::TimerRel1xx(key.clone(), rseq, interval)),
            "round {round}: re-armed with the doubled interval"
        );
    }
    assert_eq!(tx.state, TransactionState::Proceeding);
    assert_eq!(tx.rel1xx_unacked_rseq(), Some(rseq));
}

/// Over UDP the reliable 183 is retransmitted (same RSeq, >= 3 copies inside
/// the doubling schedule) until the matching PRACK is forwarded; afterwards no
/// further copies arrive.
#[tokio::test]
async fn udp_retransmits_reliable_1xx_until_prack() {
    let h = udp_harness().await;
    let (invite, mut tx) = h.send_invite("z9hG4bK-udp-rtx", "udp-rtx@test").await;
    assert_eq!(tx.original.method, Method::Invite);

    let resp183 = make_resp(&tx, StatusCode::SessionProgress, true, None);
    tx.respond(resp183).await.unwrap();
    assert_eq!(tx.rel1xx_timers_armed(), (true, true));

    // T1 + 2*T1 + 4*T1 = 140ms → original + 3 retransmissions within 200ms.
    let copies = h
        .collect_status(&mut tx, StatusCode::SessionProgress, T1 * 10)
        .await;
    assert!(
        copies.len() >= 3,
        "expected >= 3 copies of 183, got {}",
        copies.len()
    );
    let rseq = copies[0].1.rseq_value().expect("RSeq");
    assert!(copies.iter().all(|(_, r)| r.rseq_value() == Some(rseq)));
    // The doubling schedule itself is asserted deterministically in
    // `retransmit_timer_doubles_on_every_firing` (wall-clock gaps are
    // load-sensitive: a late first firing inflates gap1 without shrinking gap2).

    let prack = make_prack(&invite, &format!("{rseq} 1 INVITE"), SRV_TAG, false);
    tx.tu_sender
        .send(TransactionEvent::Received(prack.into(), None))
        .unwrap();
    assert!(pump(&mut tx, Duration::from_millis(50)).await.is_none());
    assert_eq!(tx.rel1xx_unacked_rseq(), None);
    assert_eq!(tx.rel1xx_timers_armed(), (false, false));

    // Drain anything already in flight, then expect silence.
    let _ = h
        .collect_status(
            &mut tx,
            StatusCode::SessionProgress,
            Duration::from_millis(60),
        )
        .await;
    let late = h
        .collect_status(&mut tx, StatusCode::SessionProgress, T1 * 20)
        .await;
    assert!(
        late.is_empty(),
        "no retransmission after PRACK, got {}",
        late.len()
    );
    assert_eq!(tx.state, TransactionState::Proceeding);
}

/// On a reliable transport the reliable 1xx is not retransmitted, but the
/// 64*T1 timeout still fires and synthesizes a 500 carrying the 183's To tag.
#[tokio::test]
async fn reliable_transport_no_retransmission_but_timeout_500() {
    let invite = make_invite("127.0.0.1:5060", "z9hG4bK-rel-to", None, "rel-to@test");
    let mut h = channel_harness(invite).await;
    let resp183 = make_resp(&h.tx, StatusCode::SessionProgress, true, None);
    h.tx.respond(resp183).await.unwrap();
    let wire183 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("183");
    assert_eq!(h.tx.rel1xx_timers_armed(), (false, true));

    let started = Instant::now();
    assert!(pump(&mut h.tx, T1 * 10).await.is_none());
    assert!(
        next_wire_response(&mut h.wire, Duration::from_millis(10))
            .await
            .is_none(),
        "no retransmission on a reliable transport"
    );

    let surfaced = pump(&mut h.tx, Duration::from_secs(3)).await;
    let elapsed = started.elapsed();
    match surfaced {
        Some(SipMessage::Response(resp)) => {
            assert_eq!(resp.status_code, StatusCode::ServerInternalError);
            assert_eq!(to_tag_of(&resp), to_tag_of(&wire183));
        }
        other => panic!("expected synthesized 500, got {other:?}"),
    }
    assert!(
        elapsed >= T1X64 - Duration::from_millis(50),
        "500 too early: {elapsed:?}"
    );
    let wire500 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("500 on the wire");
    assert_eq!(wire500.status_code, StatusCode::ServerInternalError);
    assert_eq!(to_tag_of(&wire500), to_tag_of(&wire183));
    assert_eq!(h.tx.state, TransactionState::Completed);
    assert_eq!(h.tx.rel1xx_unacked_rseq(), None);
    assert_eq!(h.tx.rel1xx_timers_armed(), (false, false));
}

/// Over UDP: no PRACK → 500 with the 183's To tag, surfaced from `receive()`,
/// state Completed, retransmit timer cancelled (no more 183 copies).
#[tokio::test]
async fn udp_timeout_sends_500_and_stops_retransmission() {
    let h = udp_harness().await;
    let (_invite, mut tx) = h.send_invite("z9hG4bK-udp-to", "udp-to@test").await;
    let resp183 = make_resp(&tx, StatusCode::SessionProgress, true, None);
    tx.respond(resp183).await.unwrap();

    let started = Instant::now();
    let deadline = Duration::from_secs(3);
    let mut surfaced = None;
    let mut copies_183 = 0usize;
    let mut wire500 = None;
    {
        let collector = async {
            let mut got500 = None;
            let end = Instant::now() + deadline;
            while got500.is_none() {
                let remaining = end.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match h.recv(remaining).await {
                    Some(SipMessage::Response(r))
                        if r.status_code == StatusCode::SessionProgress =>
                    {
                        copies_183 += 1
                    }
                    Some(SipMessage::Response(r))
                        if r.status_code == StatusCode::ServerInternalError =>
                    {
                        got500 = Some(r)
                    }
                    Some(_) => {}
                    None => break,
                }
            }
            got500
        };
        let pumped = async {
            let mut got = None;
            let end = Instant::now() + deadline;
            while got.is_none() {
                let remaining = end.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match pump(&mut tx, remaining).await {
                    Some(SipMessage::Response(r)) => got = Some(r),
                    Some(_) => {}
                    None => break,
                }
            }
            got
        };
        let (a, b) = tokio::join!(collector, pumped);
        wire500 = a.or(wire500);
        surfaced = b.or(surfaced);
    }
    let elapsed = started.elapsed();
    let surfaced = surfaced.expect("receive() surfaces the 500");
    let wire500 = wire500.expect("client receives the 500");
    assert_eq!(surfaced.status_code, StatusCode::ServerInternalError);
    assert_eq!(to_tag_of(&wire500), SRV_TAG);
    assert_eq!(to_tag_of(&surfaced), SRV_TAG);
    assert!(
        copies_183 >= 3,
        "expected retransmissions before timeout, got {copies_183}"
    );
    assert!(
        elapsed >= T1X64 - Duration::from_millis(50),
        "timeout fired early: {elapsed:?}"
    );
    assert_eq!(tx.state, TransactionState::Completed);
    assert_eq!(tx.rel1xx_timers_armed(), (false, false));
    assert_eq!(tx.rel1xx_unacked_rseq(), None);

    // Retransmission stopped: only the 500 (Timer G) may still show up.
    let late = h
        .collect_status(&mut tx, StatusCode::SessionProgress, T1 * 10)
        .await;
    assert!(
        late.is_empty(),
        "183 must not be retransmitted after the 500"
    );
}

/// A second reliable 1xx is queued until the first is PRACKed (consecutive
/// RSeq); an unreliable 1xx in between is sent immediately.
#[tokio::test]
async fn second_reliable_1xx_is_queued_until_prack() {
    let invite = make_invite("127.0.0.1:5060", "z9hG4bK-queue", None, "queue@test");
    let mut h = channel_harness(invite.clone()).await;

    let resp183 = make_resp(
        &h.tx,
        StatusCode::SessionProgress,
        true,
        Some(b"v=0".to_vec()),
    );
    h.tx.respond(resp183).await.unwrap();
    let wire183 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("183");
    let rseq = wire183.rseq_value().unwrap();

    let resp180 = make_resp(&h.tx, StatusCode::Ringing, true, None);
    h.tx.respond(resp180).await.unwrap();
    assert_eq!(h.tx.rel1xx_pending_len(), 1);
    assert!(
        next_wire_response(&mut h.wire, Duration::from_millis(50))
            .await
            .is_none(),
        "second reliable 1xx must not be on the wire before the PRACK"
    );

    // Unreliable provisional goes out immediately and is not tracked.
    let resp182 = make_resp(&h.tx, StatusCode::Queued, false, None);
    h.tx.respond(resp182).await.unwrap();
    let wire182 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("182");
    assert_eq!(wire182.status_code, StatusCode::Queued);
    assert!(wire182.rseq_value().is_none());
    assert_eq!(h.tx.rel1xx_unacked_rseq(), Some(rseq));
    assert_eq!(h.tx.rel1xx_pending_len(), 1);

    let prack = make_prack(&invite, &format!("{rseq} 1 INVITE"), SRV_TAG, false);
    h.tx.tu_sender
        .send(TransactionEvent::Received(prack.into(), None))
        .unwrap();
    assert!(pump(&mut h.tx, Duration::from_millis(100)).await.is_none());
    let wire180 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("queued 180 released");
    assert_eq!(wire180.status_code, StatusCode::Ringing);
    assert_eq!(wire180.rseq_value(), Some(rseq + 1));
    assert!(has_100rel(&wire180));
    assert_eq!(h.tx.rel1xx_unacked_rseq(), Some(rseq + 1));
    assert_eq!(h.tx.rel1xx_pending_len(), 0);
    assert_eq!(h.tx.rel1xx_timers_armed(), (false, true));
}

/// 2xx is held while the unacked reliable 1xx carried a body and released by
/// the PRACK; a 2xx behind a queued reliable 1xx waits for that one too.
#[tokio::test]
async fn two_hundred_held_behind_body_and_released_on_prack() {
    let invite = make_invite("127.0.0.1:5060", "z9hG4bK-hold", None, "hold@test");
    let mut h = channel_harness(invite.clone()).await;

    let resp183 = make_resp(
        &h.tx,
        StatusCode::SessionProgress,
        true,
        Some(b"v=0".to_vec()),
    );
    h.tx.respond(resp183).await.unwrap();
    let rseq = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .unwrap()
        .rseq_value()
        .unwrap();

    let resp200 = make_resp(&h.tx, StatusCode::OK, false, Some(b"v=0 answer".to_vec()));
    h.tx.respond(resp200).await.unwrap();
    assert_eq!(h.tx.state, TransactionState::Proceeding);
    assert_eq!(h.tx.rel1xx_pending_len(), 1);
    assert!(
        next_wire_response(&mut h.wire, Duration::from_millis(50))
            .await
            .is_none(),
        "2xx must be held"
    );

    let prack = make_prack(&invite, &format!("{rseq} 1 INVITE"), SRV_TAG, false);
    h.tx.tu_sender
        .send(TransactionEvent::Received(prack.into(), None))
        .unwrap();
    assert!(pump(&mut h.tx, Duration::from_millis(100)).await.is_none());
    let wire200 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("held 2xx released");
    assert_eq!(wire200.status_code, StatusCode::OK);
    assert_eq!(h.tx.state, TransactionState::Completed);
    assert_eq!(h.tx.rel1xx_pending_len(), 0);
    assert_eq!(h.tx.rel1xx_timers_armed(), (false, false));

    // Queue ordering: unacked body-less 180, then queued reliable 183 with a
    // body, then 2xx → the 2xx never overtakes the 183 and waits for its PRACK.
    let invite = make_invite("127.0.0.1:5060", "z9hG4bK-hold2", None, "hold2@test");
    let mut h = channel_harness(invite.clone()).await;
    h.tx.respond(make_resp(&h.tx, StatusCode::Ringing, true, None))
        .await
        .unwrap();
    let rseq = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .unwrap()
        .rseq_value()
        .unwrap();
    h.tx.respond(make_resp(
        &h.tx,
        StatusCode::SessionProgress,
        true,
        Some(b"v=0".to_vec()),
    ))
    .await
    .unwrap();
    h.tx.respond(make_resp(&h.tx, StatusCode::OK, false, None))
        .await
        .unwrap();
    assert_eq!(h.tx.rel1xx_pending_len(), 2);
    assert!(next_wire_response(&mut h.wire, Duration::from_millis(50))
        .await
        .is_none());

    let prack = make_prack(&invite, &format!("{rseq} 1 INVITE"), SRV_TAG, false);
    h.tx.tu_sender
        .send(TransactionEvent::Received(prack.into(), None))
        .unwrap();
    assert!(pump(&mut h.tx, Duration::from_millis(100)).await.is_none());
    let wire183 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("queued 183 released");
    assert_eq!(wire183.status_code, StatusCode::SessionProgress);
    assert_eq!(wire183.rseq_value(), Some(rseq + 1));
    assert!(
        next_wire_response(&mut h.wire, Duration::from_millis(50))
            .await
            .is_none(),
        "2xx must wait for the PRACK of the body-carrying 183"
    );
    assert_eq!(h.tx.rel1xx_pending_len(), 1);

    let prack = make_prack(&invite, &format!("{} 1 INVITE", rseq + 1), SRV_TAG, false);
    h.tx.tu_sender
        .send(TransactionEvent::Received(prack.into(), None))
        .unwrap();
    assert!(pump(&mut h.tx, Duration::from_millis(100)).await.is_none());
    let wire200 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("2xx released");
    assert_eq!(wire200.status_code, StatusCode::OK);
    assert_eq!(h.tx.state, TransactionState::Completed);
}

/// 2xx goes out immediately when the unacked reliable 1xx had no body; a
/// non-2xx final goes out immediately, stops retransmission and drops pending.
#[tokio::test]
async fn finals_without_hold_condition_are_immediate() {
    // 2xx, unacked 180 without body.
    let invite = make_invite("127.0.0.1:5060", "z9hG4bK-imm", None, "imm@test");
    let mut h = channel_harness(invite).await;
    h.tx.respond(make_resp(&h.tx, StatusCode::Ringing, true, None))
        .await
        .unwrap();
    next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("180");
    h.tx.respond(make_resp(
        &h.tx,
        StatusCode::OK,
        false,
        Some(b"v=0".to_vec()),
    ))
    .await
    .unwrap();
    let wire200 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("immediate 2xx");
    assert_eq!(wire200.status_code, StatusCode::OK);
    assert_eq!(h.tx.state, TransactionState::Completed);
    assert_eq!(h.tx.rel1xx_unacked_rseq(), None);
    assert_eq!(h.tx.rel1xx_timers_armed(), (false, false));

    // 4xx over UDP with a body-carrying unacked 183 and a queued reliable 180.
    let h = udp_harness().await;
    let (_invite, mut tx) = h.send_invite("z9hG4bK-udp-4xx", "udp-4xx@test").await;
    tx.respond(make_resp(
        &tx,
        StatusCode::SessionProgress,
        true,
        Some(b"v=0".to_vec()),
    ))
    .await
    .unwrap();
    tx.respond(make_resp(&tx, StatusCode::Ringing, true, None))
        .await
        .unwrap();
    assert_eq!(tx.rel1xx_pending_len(), 1);
    let before = h
        .collect_status(&mut tx, StatusCode::SessionProgress, T1 * 4)
        .await;
    assert!(before.len() >= 2, "183 retransmitted before the final");

    tx.respond(make_resp(&tx, StatusCode::BusyHere, false, None))
        .await
        .unwrap();
    assert_eq!(tx.state, TransactionState::Completed);
    assert_eq!(tx.rel1xx_unacked_rseq(), None);
    assert_eq!(tx.rel1xx_pending_len(), 0);
    assert_eq!(tx.rel1xx_timers_armed(), (false, false));

    let busy = h
        .collect_status(&mut tx, StatusCode::BusyHere, T1 * 3)
        .await;
    assert!(!busy.is_empty(), "486 on the wire");
    let _ = h
        .collect_status(
            &mut tx,
            StatusCode::SessionProgress,
            Duration::from_millis(60),
        )
        .await;
    let late183 = h
        .collect_status(&mut tx, StatusCode::SessionProgress, T1 * 12)
        .await;
    assert!(
        late183.is_empty(),
        "183 retransmission must stop after the final"
    );
    let late180 = h.collect_status(&mut tx, StatusCode::Ringing, T1 * 2).await;
    assert!(
        late180.is_empty(),
        "queued 180 must be dropped by the final"
    );
}

/// An INVITE retransmission in Proceeding re-sends the same 183 (same RSeq)
/// without restarting the 64*T1 timeout.
#[tokio::test]
async fn invite_retransmission_resends_same_183_without_restarting_timeout() {
    let invite = make_invite("127.0.0.1:5060", "z9hG4bK-inv-rtx", None, "inv-rtx@test");
    let mut h = channel_harness(invite.clone()).await;
    let started = Instant::now();
    h.tx.respond(make_resp(&h.tx, StatusCode::SessionProgress, true, None))
        .await
        .unwrap();
    let wire183 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("183");
    let rseq = wire183.rseq_value().unwrap();

    // Retransmitted INVITE arrives after 16*T1.
    assert!(pump(&mut h.tx, T1 * 16).await.is_none());
    h.tx.tu_sender
        .send(TransactionEvent::Received(invite.clone().into(), None))
        .unwrap();
    assert!(pump(&mut h.tx, Duration::from_millis(50)).await.is_none());
    let again = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("183 re-sent for INVITE retransmission");
    assert_eq!(again.status_code, StatusCode::SessionProgress);
    assert_eq!(again.rseq_value(), Some(rseq));
    assert_eq!(h.tx.state, TransactionState::Proceeding);
    assert_eq!(h.tx.rel1xx_unacked_rseq(), Some(rseq));

    let surfaced = pump(&mut h.tx, Duration::from_secs(3)).await;
    let elapsed = started.elapsed();
    assert!(
        matches!(surfaced, Some(SipMessage::Response(ref r)) if r.status_code == StatusCode::ServerInternalError),
        "expected 500, got {surfaced:?}"
    );
    // A restarted timeout would land at >= 16*T1 + 64*T1 = 1600ms.
    assert!(
        elapsed < T1X64 + T1 * 10,
        "timeout was restarted by the INVITE retransmission: {elapsed:?}"
    );
    assert_eq!(h.tx.state, TransactionState::Completed);
}

/// A forwarded PRACK whose RAck (or dialog) does not match is ignored and
/// retransmissions continue.
#[tokio::test]
async fn non_matching_prack_is_ignored() {
    let h = udp_harness().await;
    let (invite, mut tx) = h
        .send_invite("z9hG4bK-udp-nomatch", "udp-nomatch@test")
        .await;
    tx.respond(make_resp(&tx, StatusCode::SessionProgress, true, None))
        .await
        .unwrap();
    let first = h
        .collect_status(&mut tx, StatusCode::SessionProgress, T1 * 2)
        .await;
    let rseq = first[0].1.rseq_value().unwrap();

    // Wrong RSeq.
    let prack = make_prack(&invite, &format!("{} 1 INVITE", rseq + 7), SRV_TAG, false);
    tx.tu_sender
        .send(TransactionEvent::Received(prack.into(), None))
        .unwrap();
    // Right RSeq but a different dialog (Call-ID).
    let mut foreign = make_prack(&invite, &format!("{rseq} 1 INVITE"), SRV_TAG, false);
    foreign
        .headers
        .unique_push(CallId::new("someone-else@test").into());
    tx.tu_sender
        .send(TransactionEvent::Received(foreign.into(), None))
        .unwrap();
    // Right RSeq but wrong CSeq method.
    let prack = make_prack(&invite, &format!("{rseq} 1 UPDATE"), SRV_TAG, false);
    tx.tu_sender
        .send(TransactionEvent::Received(prack.into(), None))
        .unwrap();

    let after = h
        .collect_status(&mut tx, StatusCode::SessionProgress, T1 * 12)
        .await;
    assert!(
        after.len() >= 2,
        "retransmission must continue, got {}",
        after.len()
    );
    assert_eq!(tx.rel1xx_unacked_rseq(), Some(rseq));
    assert_eq!(tx.rel1xx_timers_armed(), (true, true));
}

/// A TimerRel1xxTimeout event that was already queued when the PRACK arrived
/// is stale and must not 500 the transaction.
#[tokio::test]
async fn stale_timeout_event_after_prack_is_ignored() {
    let invite = make_invite("127.0.0.1:5060", "z9hG4bK-stale", None, "stale@test");
    let mut h = channel_harness(invite.clone()).await;
    h.tx.respond(make_resp(&h.tx, StatusCode::SessionProgress, true, None))
        .await
        .unwrap();
    let rseq = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .unwrap()
        .rseq_value()
        .unwrap();
    h.tx.respond(make_resp(&h.tx, StatusCode::Ringing, true, None))
        .await
        .unwrap();

    let prack = make_prack(&invite, &format!("{rseq} 1 INVITE"), SRV_TAG, false);
    let key = h.tx.key.clone();
    h.tx.tu_sender
        .send(TransactionEvent::Received(prack.into(), None))
        .unwrap();
    h.tx.tu_sender
        .send(TransactionEvent::Timer(
            TransactionTimer::TimerRel1xxTimeout(key.clone(), rseq),
        ))
        .unwrap();
    h.tx.tu_sender
        .send(TransactionEvent::Timer(TransactionTimer::TimerRel1xx(
            key, rseq, T1,
        )))
        .unwrap();

    assert!(
        pump(&mut h.tx, Duration::from_millis(100)).await.is_none(),
        "no 500"
    );
    let wire180 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("queued 180 flushed");
    assert_eq!(wire180.rseq_value(), Some(rseq + 1));
    assert!(
        next_wire_response(&mut h.wire, Duration::from_millis(50))
            .await
            .is_none(),
        "stale TimerRel1xx must not resend anything"
    );
    assert_eq!(h.tx.state, TransactionState::Proceeding);
    assert_eq!(h.tx.rel1xx_unacked_rseq(), Some(rseq + 1));
}

/// A re-INVITE (To tag present) never gets reliable provisionals: headers are
/// stripped, no timers, and a following 2xx is not held.
#[tokio::test]
async fn reinvite_provisional_with_100rel_is_sent_unreliably() {
    let invite = make_invite(
        "127.0.0.1:5060",
        "z9hG4bK-reinv",
        Some("existing-tag"),
        "reinv@test",
    );
    let mut h = channel_harness(invite).await;
    let mut resp183 = make_resp(
        &h.tx,
        StatusCode::SessionProgress,
        true,
        Some(b"v=0".to_vec()),
    );
    resp183.headers.unique_push(Header::RSeq("7".into()));
    h.tx.respond(resp183).await.unwrap();
    let wire183 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("183");
    assert!(wire183.rseq_value().is_none());
    assert!(!has_100rel(&wire183));
    assert_eq!(h.tx.rel1xx_unacked_rseq(), None);
    assert_eq!(h.tx.rel1xx_timers_armed(), (false, false));

    h.tx.respond(make_resp(&h.tx, StatusCode::OK, false, None))
        .await
        .unwrap();
    let wire200 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("2xx not held");
    assert_eq!(wire200.status_code, StatusCode::OK);
    assert_eq!(h.tx.state, TransactionState::Completed);
}

/// 100 Trying, finals, RSeq-without-Require and an exhausted RSeq space are
/// never sent reliably; the offending headers are stripped.
#[tokio::test]
async fn never_reliable_cases_are_stripped() {
    let invite = make_invite("127.0.0.1:5060", "z9hG4bK-strip", None, "strip@test");
    let mut h = channel_harness(invite).await;

    let mut trying = make_resp(&h.tx, StatusCode::Trying, true, None);
    trying.headers.unique_push(Header::RSeq("3".into()));
    h.tx.respond(trying).await.unwrap();
    let wire = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(wire.status_code, StatusCode::Trying);
    assert!(wire.rseq_value().is_none() && !has_100rel(&wire));
    assert_eq!(h.tx.rel1xx_timers_armed(), (false, false));

    // RSeq without Require: 100rel is meaningless → plain provisional.
    let mut plain = make_resp(&h.tx, StatusCode::Ringing, false, None);
    plain.headers.unique_push(Header::RSeq("9".into()));
    h.tx.respond(plain).await.unwrap();
    let wire = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .unwrap();
    assert!(wire.rseq_value().is_none());
    assert_eq!(h.tx.rel1xx_unacked_rseq(), None);

    // RSeq space exhausted: MUST NOT wrap → sent unreliably.
    let mut last = make_resp(&h.tx, StatusCode::SessionProgress, true, None);
    last.headers
        .unique_push(Header::RSeq(u32::MAX.to_string().into()));
    h.tx.respond(last).await.unwrap();
    let wire = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .unwrap();
    assert!(wire.rseq_value().is_none() && !has_100rel(&wire));
    assert_eq!(h.tx.rel1xx_unacked_rseq(), None);
    assert_eq!(h.tx.rel1xx_timers_armed(), (false, false));

    // Other Require tokens survive stripping.
    let mut mixed = make_resp(&h.tx, StatusCode::OK, false, None);
    mixed
        .headers
        .unique_push(Header::Require("timer, 100rel".into()));
    mixed.headers.unique_push(Header::RSeq("11".into()));
    h.tx.respond(mixed).await.unwrap();
    let wire = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(wire.status_code, StatusCode::OK);
    assert!(wire.rseq_value().is_none() && !has_100rel(&wire));
    assert!(wire.header_contains_token("Require", "timer"));
    // Surgical removal: the surviving tokens keep their original text and
    // separators; unrelated headers are never touched.
    let raw_require = wire
        .headers
        .iter()
        .find(|h| h.name().eq_ignore_ascii_case("Require"))
        .map(|h| h.value().to_string());
    assert_eq!(raw_require.as_deref(), Some("timer"));

    // Fresh transaction (the previous one already sent its final).
    let invite = make_invite("127.0.0.1:5060", "z9hG4bK-strip2", None, "strip2@test");
    let mut h = channel_harness(invite).await;
    let mut mixed2 = make_resp(&h.tx, StatusCode::OK, false, None);
    mixed2
        .headers
        .unique_push(Header::Require("timer,100rel,replaces".into()));
    mixed2
        .headers
        .unique_push(Header::Supported("100rel,path,replaces".into()));
    h.tx.respond(mixed2).await.unwrap();
    let wire = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .unwrap();
    let raw = |name: &str| {
        wire.headers
            .iter()
            .find(|h| h.name().eq_ignore_ascii_case(name))
            .map(|h| h.value().to_string())
    };
    assert_eq!(raw("Require").as_deref(), Some("timer,replaces"));
    assert_eq!(raw("Supported").as_deref(), Some("100rel,path,replaces"));
}

/// A raw transaction user handing in a tagless reliable 183 gets a To tag
/// generated; the timeout 500 and a CANCEL-triggered 487 reuse that tag.
#[tokio::test]
async fn generated_to_tag_is_reused_by_local_finals() {
    // Timeout 500.
    let invite = make_invite("127.0.0.1:5060", "z9hG4bK-tag", None, "tag@test");
    let mut h = channel_harness(invite).await;
    let mut resp183 =
        h.tx.endpoint_inner
            .make_response(&h.tx.original, StatusCode::SessionProgress, None);
    resp183
        .headers
        .unique_push(Header::Require("100rel".into()));
    assert!(resp183.to_header().unwrap().tag().unwrap().is_none());
    h.tx.respond(resp183).await.unwrap();
    let wire183 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .unwrap();
    let tag = to_tag_of(&wire183);
    assert!(!tag.is_empty(), "To tag generated for a reliable 183");

    let surfaced = pump(&mut h.tx, Duration::from_secs(3)).await;
    match surfaced {
        Some(SipMessage::Response(r)) => {
            assert_eq!(r.status_code, StatusCode::ServerInternalError);
            assert_eq!(to_tag_of(&r), tag);
        }
        other => panic!("expected 500, got {other:?}"),
    }
    assert_eq!(h.tx.state, TransactionState::Completed);

    // CANCEL → 487 via reply() reuses the tag of the reliable 183.
    let invite = make_invite("127.0.0.1:5060", "z9hG4bK-tag2", None, "tag2@test");
    let mut h = channel_harness(invite).await;
    h.tx.respond(make_resp(
        &h.tx,
        StatusCode::SessionProgress,
        true,
        Some(b"v=0".to_vec()),
    ))
    .await
    .unwrap();
    let wire183 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(to_tag_of(&wire183), SRV_TAG);
    // A held 2xx is dropped by the non-2xx final.
    h.tx.respond(make_resp(&h.tx, StatusCode::OK, false, None))
        .await
        .unwrap();
    assert_eq!(h.tx.rel1xx_pending_len(), 1);
    h.tx.reply(StatusCode::RequestTerminated).await.unwrap();
    let wire487 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .unwrap();
    assert_eq!(wire487.status_code, StatusCode::RequestTerminated);
    assert_eq!(to_tag_of(&wire487), SRV_TAG);
    assert_eq!(wire487.status_code.kind(), StatusCodeKind::RequestFailure);
    assert_eq!(h.tx.rel1xx_pending_len(), 0);
    assert_eq!(h.tx.state, TransactionState::Completed);
}

/// RFC 3262 §3: when the INVITE advertised neither `Supported: 100rel` nor
/// `Require: 100rel` the UAS MUST NOT send the provisional response reliably —
/// even a raw transaction user asking for it gets an unreliable 183, nothing is
/// tracked, no timers run, and a following 2xx is not held.
#[tokio::test]
async fn invite_without_100rel_option_tag_downgrades_to_unreliable() {
    let mut invite = make_invite("127.0.0.1:5060", "z9hG4bK-noopt", None, "noopt@test");
    invite
        .headers
        .retain(|h| !matches!(h, Header::Supported(_) | Header::Require(_)));
    assert!(!invite.header_contains_token("Supported", "100rel"));
    assert!(!invite.header_contains_token("Require", "100rel"));
    let mut h = channel_harness(invite).await;

    let resp183 = make_resp(
        &h.tx,
        StatusCode::SessionProgress,
        true,
        Some(b"v=0".to_vec()),
    );
    h.tx.respond(resp183).await.unwrap();
    let wire183 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("183 on the wire");
    assert!(!has_100rel(&wire183), "Require: 100rel must be stripped");
    assert!(
        wire183.rseq_value().is_none(),
        "no RSeq on an unreliable 1xx"
    );
    assert_eq!(count_headers(&wire183, "RSeq"), 0);
    assert_eq!(h.tx.rel1xx_unacked_rseq(), None);
    assert_eq!(h.tx.rel1xx_timers_armed(), (false, false));
    assert_eq!(h.tx.state, TransactionState::Proceeding);

    // Not held: the 2xx goes straight out.
    h.tx.respond(make_resp(
        &h.tx,
        StatusCode::OK,
        false,
        Some(b"v=0".to_vec()),
    ))
    .await
    .unwrap();
    let wire200 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("200 on the wire immediately");
    assert_eq!(wire200.status_code, StatusCode::OK);
    assert_eq!(h.tx.rel1xx_pending_len(), 0);
    assert_eq!(h.tx.state, TransactionState::Completed);

    // No 500 ever shows up (no timeout was armed).
    assert!(pump(&mut h.tx, Duration::from_millis(100)).await.is_none());
}

/// Once the transaction has assigned an RSeq it is authoritative: a supplied
/// duplicate (or otherwise non-monotonic) RSeq on a later reliable 1xx is
/// replaced by the expected next value, so a stale timer event queued behind a
/// PRACK can never match the freshly sent response and 500 it.
#[tokio::test]
async fn supplied_non_monotonic_rseq_is_replaced_by_expected_value() {
    let invite = make_invite("127.0.0.1:5060", "z9hG4bK-dup-rseq", None, "dup-rseq@test");
    let mut h = channel_harness(invite.clone()).await;
    let key = h.tx.key.clone();

    let mut resp183 = make_resp(
        &h.tx,
        StatusCode::SessionProgress,
        true,
        Some(b"v=0".to_vec()),
    );
    resp183.headers.unique_push(Header::RSeq("5".into()));
    h.tx.respond(resp183).await.unwrap();
    let wire183 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("183 on the wire");
    assert_eq!(
        wire183.rseq_value(),
        Some(5),
        "first supplied RSeq is honoured"
    );

    // Buggy TU re-uses RSeq 5 on the queued 180.
    let mut resp180 = make_resp(&h.tx, StatusCode::Ringing, true, None);
    resp180.headers.unique_push(Header::RSeq("5".into()));
    h.tx.respond(resp180).await.unwrap();
    assert_eq!(h.tx.rel1xx_pending_len(), 1);

    // PRACK for 5 followed by the (already popped) timeout event for 5.
    let prack = make_prack(&invite, "5 1 INVITE", SRV_TAG, false);
    h.tx.tu_sender
        .send(TransactionEvent::Received(prack.into(), None))
        .unwrap();
    h.tx.tu_sender
        .send(TransactionEvent::Timer(
            TransactionTimer::TimerRel1xxTimeout(key.clone(), 5),
        ))
        .unwrap();
    assert!(
        pump(&mut h.tx, Duration::from_millis(100)).await.is_none(),
        "stale timeout must not 500 the freshly sent 180"
    );
    let wire180 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("queued 180 flushed");
    assert_eq!(wire180.status_code, StatusCode::Ringing);
    assert_eq!(
        wire180.rseq_value(),
        Some(6),
        "duplicate RSeq replaced by 6"
    );
    assert_eq!(count_headers(&wire180, "RSeq"), 1);
    assert!(
        next_wire_response(&mut h.wire, Duration::from_millis(50))
            .await
            .is_none(),
        "no 500 on the wire"
    );
    assert_eq!(h.tx.state, TransactionState::Proceeding);
    assert_eq!(h.tx.rel1xx_unacked_rseq(), Some(6));
    assert_eq!(h.tx.rel1xx_timers_armed(), (false, true));

    // A smaller supplied value is replaced too.
    let prack = make_prack(&invite, "6 1 INVITE", SRV_TAG, false);
    h.tx.tu_sender
        .send(TransactionEvent::Received(prack.into(), None))
        .unwrap();
    assert!(pump(&mut h.tx, Duration::from_millis(100)).await.is_none());
    let mut resp180 = make_resp(&h.tx, StatusCode::Ringing, true, None);
    resp180.headers.unique_push(Header::RSeq("2".into()));
    h.tx.respond(resp180).await.unwrap();
    let wire180 = next_wire_response(&mut h.wire, Duration::from_millis(200))
        .await
        .expect("180 on the wire");
    assert_eq!(wire180.rseq_value(), Some(7));
}
