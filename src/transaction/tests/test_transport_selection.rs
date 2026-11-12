//! RFC 3261 §18.1.1 in `Transaction::send`: a request that would go over UDP but is larger
//! than the transport layer's threshold goes over TCP to the same destination (through the
//! stream connector), falls back to UDP when no TCP connection can be had, and the top Via
//! always names the transport actually used. And what rides on that: a request bound to a
//! connection that has ended goes over a new one.
use crate::sip::headers::*;
use crate::sip::{prelude::HeadersExt, Method, Request, SipMessage, Transport, Uri, Version};
use crate::transaction::endpoint::Endpoint;
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::transaction::transaction::{align_via_transport, Transaction};
use crate::transaction::TransactionState;
use crate::transport::custom_tcp::tests::{header, loopback, Peer, WAIT};
use crate::transport::{CustomUdpConnection, SipAddr, SipConnection, TransportLayer};
use crate::EndpointBuilder;
use epdg::NetStack;
use parking_lot::Mutex;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// The P-CSCF stand-in: a UDP socket and a TCP listener on one port.
fn udp_and_tcp_on_one_port() -> (UdpSocket, TcpListener, SocketAddr) {
    for _ in 0..50 {
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = udp.local_addr().unwrap();
        if let Ok(tcp) = TcpListener::bind(addr) {
            udp.set_read_timeout(Some(WAIT)).unwrap();
            return (udp, tcp, addr);
        }
    }
    panic!("no port free for both UDP and TCP");
}

/// `listener.accept()` with a deadline, so a peer thread never outlives a failed test (the
/// runtime waits for blocking tasks on shutdown).
fn accept_within(listener: &TcpListener, within: Duration) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = std::time::Instant::now() + within;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // BSD sockets inherit O_NONBLOCK from the listener.
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                assert!(std::time::Instant::now() < deadline, "no connection within {within:?}");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("accept: {e}"),
        }
    }
}

/// A line like the embedder's: one custom UDP connection pinned to the peer.
fn endpoint_with_udp_line(peer: SocketAddr) -> Endpoint {
    let tl = TransportLayer::new(CancellationToken::new());
    let socket = loopback().bind_udp(0).unwrap();
    tl.add_connection(CustomUdpConnection::new(socket, Some(peer), None).into());
    EndpointBuilder::new().with_transport_layer(tl).build()
}

/// Records the remotes it is asked for and connects through the loopback stack.
fn recording_connector(
    calls: &Arc<Mutex<Vec<SocketAddr>>>,
) -> impl Fn(SocketAddr) -> io::Result<Box<dyn epdg::TcpStreamLike>> + Send + Sync + 'static {
    let calls = calls.clone();
    move |remote| {
        calls.lock().push(remote);
        loopback().connect_tcp(remote, WAIT)
    }
}

/// A MESSAGE to the peer with a `body_len`-byte body; its Via names `via_transport`.
fn message(peer: SocketAddr, body_len: usize, via_transport: &str, tag: &str) -> Request {
    Request {
        method: Method::Message,
        uri: Uri::try_from(format!("sip:bob@{peer};transport=udp").as_str()).unwrap(),
        headers: vec![
            Via::new(format!(
                "SIP/2.0/{via_transport} 127.0.0.1:5060;branch=z9hG4bK-{tag};rport"
            ))
            .into(),
            CSeq::new("1 MESSAGE").into(),
            From::new(format!("<sip:alice@example.com>;tag={tag}")).into(),
            To::new("<sip:bob@example.com>").into(),
            CallId::new(format!("{tag}@example.com")).into(),
            MaxForwards::new("70").into(),
            ContentType::new("text/plain").into(),
        ]
        .into(),
        version: Version::V2,
        body: vec![b'x'; body_len],
    }
}

fn client(endpoint: &Endpoint, request: Request) -> Transaction {
    let key = TransactionKey::from_request(&request, TransactionRole::Client).unwrap();
    Transaction::new_client(key, request, endpoint.inner.clone(), None)
}

fn top_via(request: &Request) -> String {
    request.via_header().unwrap().value().to_string()
}

async fn recv_udp(socket: UdpSocket) -> String {
    tokio::task::spawn_blocking(move || {
        let mut buf = vec![0u8; 65535];
        let (n, _) = socket.recv_from(&mut buf).expect("a datagram");
        String::from_utf8(buf[..n].to_vec()).unwrap()
    })
    .await
    .unwrap()
}

/// Below the threshold the request takes the UDP connection the lookup found, and its Via
/// (built as if a TCP listener were the endpoint's first address) is made to say UDP.
#[tokio::test]
async fn a_small_request_goes_over_udp_with_a_udp_via() {
    let (udp, _tcp, peer) = udp_and_tcp_on_one_port();
    let endpoint = endpoint_with_udp_line(peer);
    let calls = Arc::default();
    endpoint
        .inner
        .transport_layer
        .set_stream_connector(recording_connector(&calls));

    let mut tx = client(&endpoint, message(peer, 100, "TCP", "small"));
    tx.send().await.unwrap();

    let sent = timeout(WAIT, recv_udp(udp)).await.unwrap();
    assert!(sent.starts_with("MESSAGE sip:bob@"), "{sent}");
    assert_eq!(
        header(&sent, "Via"),
        Some("SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-small;rport")
    );
    assert_eq!(
        top_via(&tx.original),
        "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-small;rport"
    );
    assert!(matches!(tx.connection, Some(SipConnection::CustomUdp(_))));
    assert!(tx.timer_a.is_some(), "UDP: Timer A retransmits");
    assert!(calls.lock().is_empty(), "no TCP below the threshold");
    assert_eq!(tx.state, TransactionState::Calling);
}

/// Above the threshold the request goes over TCP to the same address — the connection is
/// opened through the stream connector, reused by the next large request — with a TCP Via
/// and no Timer A (reliable transport).
#[tokio::test]
async fn a_large_request_goes_over_tcp_to_the_same_destination() {
    let (udp, tcp, peer) = udp_and_tcp_on_one_port();
    let endpoint = endpoint_with_udp_line(peer);
    let calls = Arc::default();
    endpoint
        .inner
        .transport_layer
        .set_stream_connector(recording_connector(&calls));
    let peer_side = tokio::task::spawn_blocking(move || {
        let mut peer = Peer::new(accept_within(&tcp, WAIT));
        (peer.read_message(), peer.read_message())
    });

    let mut tx = client(&endpoint, message(peer, 2000, "UDP", "large"));
    tx.send().await.unwrap();
    assert!(matches!(tx.connection, Some(SipConnection::CustomTcp(_))));
    assert!(tx.connection.as_ref().unwrap().is_reliable());
    assert!(tx.timer_a.is_none(), "TCP: no Timer A");
    assert!(tx.timer_b.is_some(), "Timer B still bounds the transaction");
    assert_eq!(
        tx.destination,
        Some(SipAddr {
            r#type: Some(Transport::Udp),
            addr: peer.into()
        }),
        "destination kept"
    );
    assert_eq!(
        top_via(&tx.original),
        "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-large;rport",
        "retransmissions, ACK and auth retries are built from the TCP Via"
    );

    let mut second = client(&endpoint, message(peer, 2000, "UDP", "large2"));
    second.send().await.unwrap();
    let (first_sent, second_sent) = timeout(WAIT, peer_side).await.unwrap().unwrap();
    for (sent, tag) in [(&first_sent, "large"), (&second_sent, "large2")] {
        assert!(sent.starts_with("MESSAGE sip:bob@"), "{sent}");
        assert_eq!(
            header(sent, "Via"),
            Some(format!("SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-{tag};rport").as_str())
        );
        assert!(sent.ends_with(&"x".repeat(2000)), "body intact");
    }
    assert_eq!(calls.lock().as_slice(), &[peer], "one connection, reused");

    udp.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    let mut buf = [0u8; 64];
    assert!(udp.recv_from(&mut buf).is_err(), "nothing went over UDP");
}

/// When no TCP connection can be had, the large request goes over UDP after all
/// (RFC 3261 §18.1.1), Via UDP, Timer A armed.
#[tokio::test]
async fn a_large_request_falls_back_to_udp_when_tcp_fails() {
    let (udp, _tcp, peer) = udp_and_tcp_on_one_port();
    let endpoint = endpoint_with_udp_line(peer);
    let calls: Arc<Mutex<Vec<SocketAddr>>> = Arc::default();
    endpoint.inner.transport_layer.set_stream_connector({
        let calls = calls.clone();
        move |remote: SocketAddr| -> io::Result<Box<dyn epdg::TcpStreamLike>> {
            calls.lock().push(remote);
            Err(io::ErrorKind::ConnectionRefused.into())
        }
    });

    let mut tx = client(&endpoint, message(peer, 2000, "UDP", "fallback"));
    tx.send().await.unwrap();

    let sent = timeout(WAIT, recv_udp(udp)).await.unwrap();
    assert!(sent.starts_with("MESSAGE sip:bob@"), "{sent}");
    assert_eq!(
        header(&sent, "Via"),
        Some("SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-fallback;rport")
    );
    assert!(sent.ends_with(&"x".repeat(2000)), "body intact");
    assert_eq!(calls.lock().as_slice(), &[peer], "TCP was tried first");
    assert!(matches!(tx.connection, Some(SipConnection::CustomUdp(_))));
    assert!(tx.timer_a.is_some(), "UDP: Timer A retransmits");
}

/// Without a stream connector nothing changes: every size goes over the looked-up UDP
/// connection (the behaviour before RFC 3261 §18.1.1 selection existed).
#[tokio::test]
async fn without_a_stream_connector_large_requests_stay_on_udp() {
    let (udp, _tcp, peer) = udp_and_tcp_on_one_port();
    let endpoint = endpoint_with_udp_line(peer);
    let mut tx = client(&endpoint, message(peer, 2000, "UDP", "noconnector"));
    tx.send().await.unwrap();
    let sent = timeout(WAIT, recv_udp(udp)).await.unwrap();
    assert!(sent.ends_with(&"x".repeat(2000)));
    assert!(matches!(tx.connection, Some(SipConnection::CustomUdp(_))));
}

/// A request bound to a TCP connection that has ended since it was chosen — an
/// authentication retry riding the connection of the request it retries, a CANCEL riding
/// its INVITE's — goes over a new connection to the same remote (RFC 3261 §18.1.1), not
/// into the dead one where only Timer B would end its transaction.
#[tokio::test]
async fn a_request_bound_to_an_ended_tcp_connection_goes_over_a_new_one() {
    let (udp, tcp, peer) = udp_and_tcp_on_one_port();
    let endpoint = endpoint_with_udp_line(peer);
    let calls = Arc::default();
    let transport_layer = &endpoint.inner.transport_layer;
    transport_layer.set_stream_connector(recording_connector(&calls));
    let destination = SipAddr {
        r#type: Some(Transport::Udp),
        addr: peer.into(),
    };
    let first = transport_layer
        .reliable_connection_for(&destination)
        .await
        .unwrap();
    let SipConnection::CustomTcp(first_tcp) = &first else {
        panic!("expected a custom TCP connection, got {first}");
    };
    // The peer hangs up on the first connection, then takes the request on a second one.
    let peer_side = tokio::task::spawn_blocking(move || {
        drop(accept_within(&tcp, WAIT));
        Peer::new(accept_within(&tcp, WAIT)).read_message()
    });
    let deadline = tokio::time::Instant::now() + WAIT;
    while !first_tcp.is_closed() {
        assert!(tokio::time::Instant::now() < deadline, "the first connection never ended");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let request = message(peer, 100, "UDP", "rebound");
    let key = TransactionKey::from_request(&request, TransactionRole::Client).unwrap();
    let mut tx = Transaction::new_client(key, request, endpoint.inner.clone(), Some(first.clone()));
    tx.send().await.unwrap();
    let sent = timeout(WAIT, peer_side).await.unwrap().unwrap();
    assert!(sent.starts_with("MESSAGE sip:bob@"), "{sent}");
    assert_eq!(
        header(&sent, "Via"),
        Some("SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-rebound;rport")
    );
    assert!(
        matches!(&tx.connection, Some(SipConnection::CustomTcp(c)) if !c.same_connection(first_tcp)),
        "bound to the new connection"
    );
    assert_eq!(calls.lock().as_slice(), &[peer, peer], "a second connect to the same remote");
    udp.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    assert!(udp.recv_from(&mut [0u8; 64]).is_err(), "nothing went over UDP");
}

fn request_with_vias(vias: &[&str]) -> Request {
    let mut headers: Vec<Header> = vias.iter().map(|v| Via::new(*v).into()).collect();
    headers.extend([
        CSeq::new("1 OPTIONS").into(),
        From::new("<sip:alice@example.com>;tag=t").into(),
        To::new("<sip:bob@example.com>").into(),
        CallId::new("via@example.com").into(),
    ]);
    Request {
        method: Method::Options,
        uri: Uri::try_from("sip:bob@example.com").unwrap(),
        headers: headers.into(),
        version: Version::V2,
        body: vec![],
    }
}

fn vias(request: &Request) -> Vec<String> {
    request
        .headers
        .iter()
        .filter_map(|h| match h {
            Header::Via(v) => Some(v.value().to_string()),
            _ => None,
        })
        .collect()
}

/// Only the transport token of the top Via changes; branch, sent-by, every parameter, the
/// other Via values and the transaction key stay exactly as they were.
#[test]
fn align_via_transport_changes_only_the_top_transport_token() {
    let cases: &[(&[&str], Transport, &[&str])] = &[
        (
            &["SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1;rport;alias"],
            Transport::Tcp,
            &["SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK1;rport;alias"],
        ),
        (
            &["SIP/2.0/TCP [2001:db8::1]:5060;rport;branch=z9hG4bK2;keep"],
            Transport::Udp,
            &["SIP/2.0/UDP [2001:db8::1]:5060;rport;branch=z9hG4bK2;keep"],
        ),
        // Whitespace around the slashes (RFC 3261 SLASH = SWS "/" SWS) is kept.
        (
            &["SIP / 2.0 / UDP host.example.com;branch=z9hG4bK3"],
            Transport::Tcp,
            &["SIP / 2.0 / TCP host.example.com;branch=z9hG4bK3"],
        ),
        // Already right (any case): untouched.
        (
            &["SIP/2.0/udp 192.0.2.1;branch=z9hG4bK4"],
            Transport::Udp,
            &["SIP/2.0/udp 192.0.2.1;branch=z9hG4bK4"],
        ),
        // Only the top value of a comma-separated Via, and only the top Via header.
        (
            &[
                "SIP/2.0/UDP a.example.com;branch=z9hG4bK5, SIP/2.0/UDP b.example.com;branch=z9hG4bK6",
                "SIP/2.0/UDP c.example.com;branch=z9hG4bK7",
            ],
            Transport::Tcp,
            &[
                "SIP/2.0/TCP a.example.com;branch=z9hG4bK5, SIP/2.0/UDP b.example.com;branch=z9hG4bK6",
                "SIP/2.0/UDP c.example.com;branch=z9hG4bK7",
            ],
        ),
        // A transport we cannot read is left alone rather than guessed at.
        (
            &["SIP/2.0/UDPhost;branch=z9hG4bK8"],
            Transport::Tcp,
            &["SIP/2.0/UDPhost;branch=z9hG4bK8"],
        ),
    ];
    for (before, transport, after) in cases {
        let mut request = request_with_vias(before);
        let key = TransactionKey::from_request(&request, TransactionRole::Client).ok();
        align_via_transport(&mut request, *transport);
        assert_eq!(vias(&request), *after, "{before:?} -> {transport}");
        assert_eq!(
            TransactionKey::from_request(&request, TransactionRole::Client).ok(),
            key,
            "the transaction key does not depend on the transport"
        );
    }
    // No Via at all: nothing to do, no panic.
    let mut request = request_with_vias(&[]);
    align_via_transport(&mut request, Transport::Tcp);
    assert!(vias(&request).is_empty());
    // The message as sent carries it too.
    let mut request = request_with_vias(&["SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK9"]);
    align_via_transport(&mut request, Transport::Tcp);
    let text = SipMessage::Request(request).to_string();
    assert!(text.contains("Via: SIP/2.0/TCP 192.0.2.1;branch=z9hG4bK9\r\n"), "{text}");
}
