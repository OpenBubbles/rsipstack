//! UPDATE on an early dialog (RFC 3311 §5.1), in both directions, between two endpoints over
//! loopback UDP.
//!
//! The UAS's UPDATE reaches the UAC while the UAC's dialog is still filed under the ID it was
//! registered with (no remote tag) by `do_invite_async`; the 180 gave it its remote tag only on
//! the dialog itself. Both sides must find the dialog and hand the UPDATE to the application as
//! `DialogState::Updated`, before the INVITE completes and without changing the dialog's state.
//! Run through `InviteDialog` and through the deprecated `ClientInviteDialog` /
//! `ServerInviteDialog`, which must behave the same.

#![allow(deprecated)]

use crate::dialog::client_dialog::ClientInviteDialog;
use crate::dialog::dialog::{Dialog, DialogState};
use crate::dialog::server_dialog::ServerInviteDialog;
use crate::dialog::dialog_layer::DialogLayer;
use crate::dialog::invitation::InviteOption;
use crate::dialog::invite_dialog::InviteDialog;
use crate::dialog::DialogId;
use crate::sip::headers::*;
use crate::sip::{Header, Method, Request, Response, StatusCode, Uri};
use crate::transaction::endpoint::{Endpoint, EndpointBuilder};
use crate::transaction::key::{TransactionKey, TransactionRole};
use crate::transaction::transaction::Transaction;
use crate::transport::{udp::UdpConnection, SipConnection, TransportLayer};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const WAIT: Duration = Duration::from_secs(5);

/// Hands `tx` to `dialog`. With `legacy`, an INVITE dialog handles it through the deprecated
/// wrapper for its role instead of `InviteDialog`.
async fn handle(dialog: Dialog, tx: &mut Transaction, legacy: bool) {
    let _ = match dialog {
        Dialog::Invite(dialog) if legacy => match dialog.role() {
            TransactionRole::Server => {
                ServerInviteDialog::try_from(dialog).unwrap().handle(tx).await
            }
            TransactionRole::Client => {
                ClientInviteDialog::try_from(dialog).unwrap().handle(tx).await
            }
        },
        mut dialog => dialog.handle(tx).await,
    };
}

/// An endpoint on a loopback UDP port with a dispatch loop modelled on a consumer's: a request
/// `match_dialog` places goes to that dialog; a new INVITE gets a server dialog, handed out on
/// `invites`; any other request is reported on `unmatched` and left unanswered.
struct Ua {
    endpoint: Endpoint,
    layer: Arc<DialogLayer>,
    port: u16,
    state_sender: UnboundedSender<DialogState>,
    states: UnboundedReceiver<DialogState>,
    invites: UnboundedReceiver<InviteDialog>,
    unmatched: UnboundedReceiver<Method>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Ua {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Ua {
    async fn start(legacy: bool) -> Self {
        let token = CancellationToken::new();
        let udp = UdpConnection::create_connection("127.0.0.1:0".parse().unwrap(), None, None)
            .await
            .unwrap();
        let sip: SipConnection = udp.into();
        let port = sip.get_addr().addr.port.map(u16::from).unwrap();
        let transport_layer = TransportLayer::new(token.child_token());
        transport_layer.add_transport(sip);
        let endpoint = EndpointBuilder::new()
            .with_user_agent("rsipstack-test")
            .with_transport_layer(transport_layer)
            .build();
        let mut incoming = endpoint.incoming_transactions().unwrap();
        let serving = endpoint.inner.clone();
        let serve = tokio::spawn(async move {
            let _ = serving.serve().await;
        });

        let layer = Arc::new(DialogLayer::new(endpoint.inner.clone()));
        let (state_sender, states) = unbounded_channel();
        let (invite_sender, invites) = unbounded_channel();
        let (unmatched_sender, unmatched) = unbounded_channel();
        let contact = Uri::try_from(format!("sip:ua@127.0.0.1:{port}").as_str()).unwrap();
        let dispatch_layer = layer.clone();
        let dispatch_states = state_sender.clone();
        let dispatch = tokio::spawn(async move {
            while let Some(mut tx) = incoming.recv().await {
                if let Some(dialog) = dispatch_layer.match_dialog(&tx) {
                    tokio::spawn(async move {
                        handle(dialog, &mut tx, legacy).await;
                    });
                } else if tx.original.method == Method::Invite {
                    let dialog = dispatch_layer
                        .get_or_create_server_invite(
                            &tx,
                            dispatch_states.clone(),
                            None,
                            Some(contact.clone()),
                        )
                        .unwrap();
                    invite_sender.send(dialog.clone()).ok();
                    tokio::spawn(async move {
                        handle(Dialog::Invite(dialog), &mut tx, legacy).await;
                    });
                } else {
                    unmatched_sender.send(tx.original.method.clone()).ok();
                }
            }
        });

        Ua {
            endpoint,
            layer,
            port,
            state_sender,
            states,
            invites,
            unmatched,
            tasks: vec![serve, dispatch],
        }
    }

    fn contact(&self) -> Uri {
        Uri::try_from(format!("sip:ua@127.0.0.1:{}", self.port).as_str()).unwrap()
    }

    /// The next dialog state `pick` accepts; the ones before it are skipped.
    async fn next_state(&mut self, pick: impl Fn(&DialogState) -> bool) -> DialogState {
        loop {
            let state = timeout(WAIT, self.states.recv())
                .await
                .expect("a dialog state in time")
                .expect("the state channel is open");
            if pick(&state) {
                return state;
            }
        }
    }

    /// An UPDATE as this endpoint would receive it from the far end of its UAC dialog `id`,
    /// sent with the From tag `from_tag`: a server transaction that is only matched, never sent.
    fn update_from(&self, id: &DialogId, from_tag: &str) -> Transaction {
        let request = Request {
            method: Method::Update,
            uri: self.contact(),
            headers: vec![
                Via::new("SIP/2.0/UDP 127.0.0.1:9;branch=z9hG4bK-early-update-probe").into(),
                CSeq::new("7 UPDATE").into(),
                From::new(format!("<sip:bob@example.com>;tag={from_tag}")).into(),
                To::new(format!("<sip:alice@example.com>;tag={}", id.local_tag)).into(),
                CallId::new(id.call_id.clone()).into(),
                MaxForwards::new("70").into(),
            ]
            .into(),
            version: crate::sip::Version::V2,
            body: vec![],
        };
        let key = TransactionKey::from_request(&request, TransactionRole::Server).unwrap();
        Transaction::new_server(key, request, self.endpoint.inner.clone(), None)
    }
}

/// Sends an UPDATE carrying `offer` on `dialog` in whatever state it is in.
/// `InviteDialog::update` sends only on a confirmed dialog; what is under test here is the
/// receiving side of an early one.
async fn send_update(dialog: &InviteDialog, offer: &[u8]) -> Option<Response> {
    let request = dialog
        .inner
        .make_request(
            Method::Update,
            None,
            None,
            None,
            Some(vec![Header::ContentType("application/sdp".into())]),
            Some(offer.to_vec()),
        )
        .unwrap();
    dialog.inner.do_request(request).await.unwrap()
}

/// The application's side of `DialogState::Updated`: checks the request and answers `answer`.
async fn answer_update(ua: &mut Ua, dialog: &InviteDialog, offer: &[u8], answer: &[u8]) {
    let DialogState::Updated(id, request, handle) = ua
        .next_state(|s| matches!(s, DialogState::Updated(..)))
        .await
    else {
        unreachable!()
    };
    assert_eq!(id, dialog.id());
    assert_eq!(request.method, Method::Update);
    assert_eq!(request.body, offer);
    handle
        .respond(
            StatusCode::OK,
            Some(vec![Header::ContentType("application/sdp".into())]),
            Some(answer.to_vec()),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn update_on_an_early_dialog_invite_dialog() {
    update_on_an_early_dialog_in_both_directions(false).await;
}

#[tokio::test]
async fn update_on_an_early_dialog_legacy_dialogs() {
    update_on_an_early_dialog_in_both_directions(true).await;
}

async fn update_on_an_early_dialog_in_both_directions(legacy: bool) {
    let mut uas = Ua::start(legacy).await;
    let mut uac = Ua::start(legacy).await;

    let option = InviteOption {
        caller: Uri::try_from("sip:alice@example.com").unwrap(),
        callee: Uri::try_from(format!("sip:bob@127.0.0.1:{};transport=udp", uas.port).as_str())
            .unwrap(),
        contact: uac.contact(),
        content_type: Some("application/sdp".into()),
        offer: Some(b"v=0 invite offer".to_vec()),
        ..Default::default()
    };
    let (caller, invite) = uac
        .layer
        .do_invite_async(option, uac.state_sender.clone())
        .unwrap();
    let registered = caller.id();
    assert!(registered.remote_tag.is_empty());
    let callee = timeout(WAIT, uas.invites.recv()).await.unwrap().unwrap();

    // No 1xx with a To tag yet: no early dialog for a request to belong to.
    let probe = uac.update_from(&registered, "uas-tag");
    assert!(uac.layer.match_dialog(&probe).is_none());

    // An unreliable 180 with a To tag makes an early dialog on both sides (RFC 3261 §12.1).
    callee.ringing(None, None).unwrap();
    uac.next_state(|s| matches!(s, DialogState::Early(..))).await;
    let early = caller.id();
    assert_eq!(early.remote_tag, callee.id().local_tag, "the 180's To tag");
    assert!(
        uac.layer.get_dialog_with(&registered.to_string()).is_some(),
        "the UAC's dialog is still filed under the ID it was registered with"
    );
    assert!(uac.layer.get_dialog(&early).is_some(), "and is found by its own ID");
    let matched = uac.layer.match_dialog(&uac.update_from(&early, &early.remote_tag));
    assert_eq!(matched.map(|d| d.id()), Some(early.clone()));
    let stranger = uac.update_from(&early, "someone-else");
    assert!(
        uac.layer.match_dialog(&stranger).is_none(),
        "a request with another remote tag belongs to another dialog"
    );

    // Callee to caller: the UAC answers an UPDATE on its early dialog.
    let callee_update = tokio::spawn({
        let callee = callee.clone();
        async move { send_update(&callee, b"v=0 callee offer").await }
    });
    answer_update(&mut uac, &caller, b"v=0 callee offer", b"v=0 caller answer").await;
    let response = timeout(WAIT, callee_update)
        .await
        .unwrap()
        .unwrap()
        .expect("the UAC answered the UPDATE");
    assert_eq!(response.status_code, StatusCode::OK);
    assert_eq!(response.body, b"v=0 caller answer");

    // Caller to callee: the UAS answers one on its early dialog.
    let caller_update = tokio::spawn({
        let caller = caller.clone();
        async move { send_update(&caller, b"v=0 caller offer").await }
    });
    answer_update(&mut uas, &callee, b"v=0 caller offer", b"v=0 callee answer").await;
    let response = timeout(WAIT, caller_update)
        .await
        .unwrap()
        .unwrap()
        .expect("the UAS answered the UPDATE");
    assert_eq!(response.status_code, StatusCode::OK);
    assert_eq!(response.body, b"v=0 callee answer");

    // An UPDATE leaves the dialog's state alone (RFC 3311).
    assert!(matches!(caller.state(), DialogState::Early(..)));
    assert!(matches!(callee.state(), DialogState::Early(..)));
    assert!(uac.unmatched.try_recv().is_err(), "every request to the UAC found its dialog");
    assert!(uas.unmatched.try_recv().is_err(), "every request to the UAS found its dialog");

    // The INVITE then completes as usual, and the UAC's dialog is refiled under its ID.
    callee
        .accept(
            Some(vec![Header::ContentType("application/sdp".into())]),
            Some(b"v=0 invite answer".to_vec()),
        )
        .unwrap();
    let (confirmed, final_response) = timeout(WAIT, invite).await.unwrap().unwrap().unwrap();
    assert_eq!(final_response.map(|r| r.status_code), Some(StatusCode::OK));
    assert_eq!(confirmed, early);
    assert!(uac.layer.get_dialog_with(&confirmed.to_string()).is_some());
    assert!(uac.layer.get_dialog_with(&registered.to_string()).is_none());
    uas.next_state(|s| s.is_confirmed()).await;
}
