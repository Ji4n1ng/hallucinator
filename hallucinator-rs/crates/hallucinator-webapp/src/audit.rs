//! Audit log of API calls (agent tool standard, section 4): every call by an
//! agent account, and every call by anyone that changes data. Sign-ins and
//! token changes are such calls; the `agent` token command on the server adds
//! its own rows. Only the path is kept, never the query string or the body,
//! so no secret from either reaches the log.
//!
//! The middleware puts a [`Slot`] into each request. The extractors that
//! authenticate (auth.rs) and the sign-in handler fill it with who called, so
//! the log names the account that was actually checked.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;

use crate::auth::{Sealed, client_ip};
use crate::state::AppState;
use crate::store::{KIND_AGENT, KIND_PERSON, NewAudit, User};

/// Entries are kept this long (the standard asks for at least 90 days).
pub const RETENTION_SECS: i64 = 90 * 86400;

/// Who made a call.
#[derive(Debug, Clone)]
pub struct Actor {
    pub username: String,
    pub kind: String,
    /// `session`, `token` or `password` (a sign-in).
    pub via: &'static str,
}

impl Actor {
    pub fn of(user: &User, via: &'static str) -> Self {
        Actor {
            username: user.username.clone(),
            kind: user.kind.clone(),
            via,
        }
    }
}

/// Filled with the caller once a request is authenticated.
#[derive(Debug, Clone, Default)]
pub struct Slot(Arc<Mutex<Option<Actor>>>);

impl Slot {
    pub fn set(&self, actor: Actor) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(actor);
    }

    fn take(&self) -> Option<Actor> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

/// Whether a call goes in the log.
fn audited(method: &Method, actor: Option<&Actor>) -> bool {
    let reads = matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS);
    !reads || actor.is_some_and(|a| a.kind == KIND_AGENT)
}

pub async fn middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Response {
    let slot = Slot::default();
    req.extensions_mut().insert(slot.clone());
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let sealed = req.extensions().get::<Sealed>().is_some();
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let ip = client_ip(req.headers(), peer, state.settings.trust_proxy);

    let resp = next.run(req).await;

    let actor = slot.take();
    if audited(&method, actor.as_ref()) {
        let entry = NewAudit {
            username: actor.as_ref().map(|a| a.username.as_str()),
            kind: actor.as_ref().map_or(KIND_PERSON, |a| a.kind.as_str()),
            method: method.as_str(),
            path: &path,
            status: resp.status().as_u16(),
            ip: &ip,
            via: actor.as_ref().map_or("none", |a| a.via),
            sealed,
            detail: None,
        };
        if let Err(e) = state.store.add_audit(&entry) {
            tracing::warn!(error = %e, %path, "could not write the audit log");
        }
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_audited() {
        let agent = Actor {
            username: "Frieren".into(),
            kind: KIND_AGENT.into(),
            via: "token",
        };
        let person = Actor {
            username: "alice".into(),
            kind: KIND_PERSON.into(),
            via: "session",
        };
        assert!(audited(&Method::GET, Some(&agent)));
        assert!(!audited(&Method::GET, Some(&person)));
        assert!(!audited(&Method::GET, None));
        assert!(audited(&Method::POST, Some(&person)));
        assert!(audited(&Method::DELETE, None));
    }
}
