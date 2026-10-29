//! Router-level tests: the guide documents every route (and only real ones),
//! what agent accounts may do, the audit log, and the end-to-end tunnel.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};
use tower::ServiceExt;

use crate::auth::{LoginPolicy, SESSION_COOKIE, hash_password, issue_api_token};
use crate::e2e::{self, Key, Keyring, REQUEST, RESPONSE};
use crate::state::{AppState, Settings};
use crate::store::{Store, User};

struct Harness {
    state: Arc<AppState>,
    _dir: tempfile::TempDir,
}

impl Harness {
    fn new(keyring: Option<Keyring>) -> Self {
        use hallucinator_core::config_file::{ConfigFile, DatabasesConfig};
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&dir.path().join("webapp.db")).unwrap());
        // Offline databases at paths that do not exist: nothing is loaded.
        let missing = |n: &str| Some(dir.path().join(n).display().to_string());
        let cfg = ConfigFile {
            databases: Some(DatabasesConfig {
                dblp_offline_path: missing("dblp.db"),
                acl_offline_path: missing("acl.db"),
                arxiv_offline_path: missing("arxiv.db"),
                iacr_eprint_offline_path: missing("iacr.db"),
                openalex_offline_path: missing("openalex"),
                local_corpus_path: missing("corpus.db"),
                ..Default::default()
            }),
            ..Default::default()
        };
        let refdb = Arc::new(crate::refdb::RefDbRegistry::new(
            cfg,
            None,
            dir.path().join("cache.db"),
            30,
        ));
        let settings = Settings {
            data_dir: dir.path().to_path_buf(),
            secure_cookies: false,
            trust_proxy: false,
            max_concurrent_runs: 1,
            max_upload_bytes: 10 * 1024 * 1024,
            session_ttl_secs: 3600,
            static_dir: None,
            policy: LoginPolicy::default(),
        };
        let state = Arc::new(AppState {
            runs: Arc::new(crate::runs::RunManager::new(
                store.clone(),
                refdb.clone(),
                1,
            )),
            jobs: Arc::new(crate::jobs::JobManager::new(
                store.clone(),
                refdb.clone(),
                None,
            )),
            settings,
            store,
            refdb,
            shutdown: tokio_util::sync::CancellationToken::new(),
            e2e: keyring.map(Arc::new),
        });
        Harness { state, _dir: dir }
    }

    fn app(&self) -> Router {
        super::app(self.state.clone())
    }

    fn person(&self, name: &str, role: &str) -> User {
        self.state
            .store
            .create_user(
                name,
                &hash_password("correct horse battery").unwrap(),
                role,
                "active",
            )
            .unwrap()
    }

    fn token(&self, user: &User) -> String {
        issue_api_token(&self.state.store, user.id, "test", None)
            .unwrap()
            .0
    }

    async fn send(&self, req: Request<Body>) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        send(self.app(), req, "10.1.2.3:4000").await
    }
}

async fn send(
    app: Router,
    mut req: Request<Body>,
    peer: &str,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let addr: SocketAddr = peer.parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(addr));
    let resp = app.oneshot(req).await.unwrap();
    let (parts, body) = resp.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes().to_vec();
    (parts.status, parts.headers, bytes)
}

fn request(method: Method, path: &str, token: Option<&str>, body: Option<Value>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(path);
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    match body {
        Some(v) => b
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(v.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    }
}

fn json_of(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or(Value::Null)
}

// ── the guide and the routes ───────────────────────────────────────────

/// `(METHOD, /api/path)` of every route in [`super::router`]'s API block.
fn router_routes() -> BTreeSet<(String, String)> {
    let src = include_str!("mod.rs");
    let start = src.find("let api = Router::new()").expect("API router");
    let end = start
        + src[start..]
            .find(".fallback(api_not_found)")
            .expect("API fallback");
    let block = &src[start..end];
    let mut out = BTreeSet::new();
    for seg in block.split(".route(").skip(1) {
        let path = seg.split('"').nth(1).expect("route path");
        for m in ["get", "post", "put", "patch", "delete"] {
            let called = seg.match_indices(&format!("{m}(")).any(|(i, _)| {
                i == 0
                    || !seg.as_bytes()[i - 1].is_ascii_alphanumeric()
                        && seg.as_bytes()[i - 1] != b'_'
            });
            if called {
                out.insert((m.to_uppercase(), format!("/api{path}")));
            }
        }
    }
    out
}

/// `(METHOD, path)` of every `### METHOD /api/…` heading in the guide.
fn guide_routes() -> BTreeSet<(String, String)> {
    super::docs::GUIDE
        .lines()
        .filter_map(|l| l.strip_prefix("### "))
        .filter_map(|l| {
            let (m, p) = l.trim().split_once(' ')?;
            (["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&m) && p.starts_with("/api"))
                .then(|| (m.to_string(), p.to_string()))
        })
        .collect()
}

#[test]
fn guide_and_routes_match() {
    let routes = router_routes();
    let guide = guide_routes();
    assert!(routes.len() > 30, "parsed only {} routes", routes.len());
    let undocumented: Vec<_> = routes.difference(&guide).collect();
    let unknown: Vec<_> = guide.difference(&routes).collect();
    assert!(
        undocumented.is_empty(),
        "routes missing from API-GUIDE.md: {undocumented:?}"
    );
    assert!(
        unknown.is_empty(),
        "API-GUIDE.md names routes that do not exist: {unknown:?}"
    );
}

#[tokio::test]
async fn every_guide_route_reaches_a_handler() {
    let h = Harness::new(None);
    for (m, p) in guide_routes() {
        let path = p
            .replace("{id}", "x")
            .replace("{pidx}", "0")
            .replace("{ridx}", "0")
            .replace("{key}", "dblp")
            .replace("{ip}", "192.0.2.1");
        let (status, _, body) = h
            .send(request(
                Method::from_bytes(m.as_bytes()).unwrap(),
                &path,
                None,
                None,
            ))
            .await;
        let text = String::from_utf8_lossy(&body);
        assert!(
            status != StatusCode::METHOD_NOT_ALLOWED && !text.contains("No such API endpoint"),
            "{m} {p}: {status} {text}"
        );
    }
}

#[tokio::test]
async fn guide_whoami_and_health() {
    let h = Harness::new(None);
    let agent = h.state.store.create_agent("Frieren").unwrap();
    let t = h.token(&agent);

    let (s, _, b) = h
        .send(request(Method::GET, "/api/agent/whoami", Some(&t), None))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        json_of(&b),
        json!({"name": "Frieren", "kind": "agent", "role": "user"})
    );

    let (s, hd, b) = h
        .send(request(Method::GET, "/api/agent/guide", Some(&t), None))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        hd[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/markdown")
    );
    assert!(
        String::from_utf8_lossy(&b).starts_with("# Hallucinator agent guide\n\n## Quick start")
    );

    let (s, _, b) = h
        .send(request(
            Method::GET,
            "/api/agent/guide?section=check-access",
            Some(&t),
            None,
        ))
        .await;
    assert_eq!(s, StatusCode::OK);
    let text = String::from_utf8_lossy(&b);
    assert!(text.starts_with("## Check access") && !text.contains("## Check a paper"));

    let (s, _, b) = h
        .send(request(
            Method::GET,
            "/api/agent/guide?section=nope",
            Some(&t),
            None,
        ))
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(
        json_of(&b)["error"]
            .as_str()
            .unwrap()
            .contains("quick-start")
    );

    // The guide and whoami need an account.
    let (s, _, _) = h
        .send(request(Method::GET, "/api/agent/guide", None, None))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, _, b) = h
        .send(request(Method::GET, "/api/health", None, None))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(json_of(&b), json!({"ok": true, "e2e": {"required": false}}));
}

// ── agent accounts and the audit log ───────────────────────────────────

#[tokio::test]
async fn agents_are_users_and_never_admins() {
    let h = Harness::new(None);
    let admin = h.person("root", "admin");
    let admin_t = h.token(&admin);
    let agent = h.state.store.create_agent("Frieren").unwrap();
    let t = h.token(&agent);

    for (m, p) in [
        (Method::GET, "/api/runs"),
        (Method::GET, "/api/options"),
        (Method::GET, "/api/databases"),
        (Method::GET, "/api/jobs"),
        (Method::GET, "/api/auth/me"),
    ] {
        let (s, _, b) = h.send(request(m.clone(), p, Some(&t), None)).await;
        assert_eq!(
            s,
            StatusCode::OK,
            "{m} {p}: {}",
            String::from_utf8_lossy(&b)
        );
    }
    let forbidden = [
        (Method::GET, "/api/admin/users"),
        (Method::GET, "/api/admin/audit"),
        (Method::GET, "/api/admin/tokens"),
        (Method::GET, "/api/tokens"),
        (Method::POST, "/api/tokens"),
        (Method::POST, "/api/auth/password"),
        (Method::POST, "/api/databases/cache/clear"),
    ];
    for (m, p) in &forbidden {
        let body = (*m == Method::POST).then(|| json!({}));
        let (s, _, b) = h.send(request(m.clone(), p, Some(&t), body)).await;
        assert!(
            s == StatusCode::FORBIDDEN || s == StatusCode::UNPROCESSABLE_ENTITY,
            "{m} {p}: {s} {}",
            String::from_utf8_lossy(&b)
        );
    }
    // Even a stored admin role does not make an agent an admin.
    h.state.store.set_user_role(agent.id, "admin").unwrap();
    let (s, _, _) = h
        .send(request(Method::GET, "/api/admin/users", Some(&t), None))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    h.state.store.set_user_role(agent.id, "user").unwrap();

    // An admin cannot make an agent an admin.
    let (s, _, b) = h
        .send(request(
            Method::PATCH,
            &format!("/api/admin/users/{}", agent.id),
            Some(&admin_t),
            Some(json!({"role": "admin"})),
        ))
        .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "{}",
        String::from_utf8_lossy(&b)
    );

    // An agent has no password.
    let (s, _, _) = h
        .send(request(
            Method::POST,
            "/api/auth/login",
            None,
            Some(json!({"username": "Frieren", "password": "anything long enough"})),
        ))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // A revoke works at once.
    assert_eq!(h.state.store.delete_user_tokens(agent.id, None).unwrap(), 1);
    let (s, _, _) = h
        .send(request(Method::GET, "/api/agent/whoami", Some(&t), None))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn audit_log_names_agent_or_person() {
    let h = Harness::new(None);
    let admin = h.person("root", "admin");
    let admin_t = h.token(&admin);
    let agent = h.state.store.create_agent("Frieren").unwrap();
    let t = h.token(&agent);

    // Agent reads are logged, without the query string.
    h.send(request(
        Method::GET,
        "/api/runs?limit=5&q=secret",
        Some(&t),
        None,
    ))
    .await;
    h.send(request(Method::GET, "/api/agent/whoami", Some(&t), None))
        .await;
    // A person's reads are not; their changes are.
    h.send(request(Method::GET, "/api/runs", Some(&admin_t), None))
        .await;
    h.send(request(
        Method::DELETE,
        "/api/runs/nope",
        Some(&admin_t),
        None,
    ))
    .await;
    // A sign-in names the account tried.
    h.send(request(
        Method::POST,
        "/api/auth/login",
        None,
        Some(json!({"username": "root", "password": "wrong password!"})),
    ))
    .await;

    let audit = |q: &'static str| {
        let h = &h;
        let admin_t = admin_t.clone();
        async move {
            let (s, _, b) = h
                .send(request(
                    Method::GET,
                    &format!("/api/admin/audit{q}"),
                    Some(&admin_t),
                    None,
                ))
                .await;
            assert_eq!(s, StatusCode::OK);
            json_of(&b)["entries"].as_array().unwrap().clone()
        }
    };
    let all = audit("").await;
    let rows: Vec<(String, String, String, String, i64)> = all
        .iter()
        .map(|e| {
            (
                e["username"].as_str().unwrap_or("").to_string(),
                e["kind"].as_str().unwrap().to_string(),
                e["method"].as_str().unwrap().to_string(),
                e["path"].as_str().unwrap().to_string(),
                e["status"].as_i64().unwrap(),
            )
        })
        .collect();
    let row = |u: &str, k: &str, m: &str, p: &str, s: i64| {
        (
            u.to_string(),
            k.to_string(),
            m.to_string(),
            p.to_string(),
            s,
        )
    };
    assert_eq!(
        rows,
        [
            row("root", "person", "POST", "/api/auth/login", 401),
            row("root", "person", "DELETE", "/api/runs/nope", 404),
            row("Frieren", "agent", "GET", "/api/agent/whoami", 200),
            row("Frieren", "agent", "GET", "/api/runs", 200),
        ]
    );
    assert_eq!(all[2]["via"], "token");
    assert_eq!(all[0]["via"], "password");

    let agents = audit("?kind=agent").await;
    assert_eq!(agents.len(), 2);
    assert!(agents.iter().all(|e| e["kind"] == "agent"));
    assert_eq!(audit("?account=frieren").await.len(), 2);
    assert_eq!(audit("?account=root&kind=person").await.len(), 2);
    assert_eq!(audit("?account=root&kind=agent").await.len(), 0);
    let older = audit("?limit=1").await;
    let before = older[0]["id"].as_i64().unwrap();
    let page = h
        .send(request(
            Method::GET,
            &format!("/api/admin/audit?before={before}&limit=10"),
            Some(&admin_t),
            None,
        ))
        .await;
    // The admin's own audit reads are not logged; the page holds the rest.
    assert_eq!(json_of(&page.2)["entries"].as_array().unwrap().len(), 3);
    let (s, _, _) = h
        .send(request(
            Method::GET,
            "/api/admin/audit?kind=robot",
            Some(&admin_t),
            None,
        ))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

// ── the end-to-end tunnel ──────────────────────────────────────────────

const KEY: &str = "cek1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

struct Sealed {
    status: u16,
    headers: Map<String, Value>,
    body: Vec<u8>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// One envelope for `POST /api/e2e`, and its nonce.
fn envelope(key: &Key, meta: Value, body: &[u8]) -> (Vec<u8>, [u8; 12]) {
    let nonce: [u8; 12] = rand::random();
    let plain = e2e::pack_plaintext(meta.to_string().as_bytes(), body);
    (
        e2e::seal(key, REQUEST, &plain, now_ms(), &nonce, &[]),
        nonce,
    )
}

fn tunnel_request(env: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/api/e2e")
        .header(header::CONTENT_TYPE, e2e::CONTENT_TYPE)
        .header(header::CONTENT_LENGTH, env.len())
        .body(Body::from(env))
        .unwrap()
}

async fn sealed_call(h: &Harness, key: &Key, meta: Value, body: &[u8]) -> Sealed {
    let (env, nonce) = envelope(key, meta, body);
    let (s, hd, b) = h.send(tunnel_request(env)).await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&b));
    assert_eq!(hd[header::CONTENT_TYPE], e2e::CONTENT_TYPE);
    let opened = e2e::open_envelope(key, &b, RESPONSE, &nonce).unwrap();
    let (meta, body) = e2e::unpack_plaintext(&opened.plaintext).unwrap();
    Sealed {
        status: meta["s"].as_u64().unwrap() as u16,
        headers: meta["h"].as_object().unwrap().clone(),
        body: body.to_vec(),
    }
}

#[tokio::test]
async fn e2e_refuses_plain_and_serves_sealed() {
    let key = Key::from_string(KEY).unwrap();
    let h = Harness::new(Some(Keyring::new(key.clone(), None)));
    let agent = h.state.store.create_agent("Frieren").unwrap();
    let t = h.token(&agent);
    let admin = h.person("root", "admin");

    // Plain: refused, except the health check and the page shells.
    for (m, p, tok) in [
        (Method::GET, "/api/agent/whoami", Some(t.as_str())),
        (Method::GET, "/api/auth/me", None),
        (Method::GET, "/api/docs", None),
        (Method::GET, "/llms.txt", None),
        (Method::POST, "/api/auth/login", None),
        (Method::GET, "/api/health", Some(t.as_str())),
    ] {
        let (s, _, b) = h.send(request(m.clone(), p, tok, None)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{m} {p}");
        assert_eq!(json_of(&b)["e2e"], "required", "{m} {p}");
    }
    let (s, _, b) = h
        .send(request(Method::GET, "/api/health", None, None))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        json_of(&b),
        json!({"ok": true, "e2e": {"required": true, "kids": [e2e::hex(&key.kid)]}})
    );
    let (s, _, _) = h.send(request(Method::GET, "/", None, None)).await;
    assert_eq!(s, StatusCode::OK, "the page shell loads without a cookie");
    let (s, _, _) = h
        .send(request(Method::GET, "/static/app.js", None, None))
        .await;
    assert_eq!(s, StatusCode::OK);

    // Sealed: whoami, the guide and a section.
    let auth = json!({"authorization": format!("Bearer {t}")});
    let r = sealed_call(
        &h,
        &key,
        json!({"m": "GET", "p": "/api/agent/whoami", "h": auth}),
        b"",
    )
    .await;
    assert_eq!(r.status, 200);
    assert_eq!(json_of(&r.body)["kind"], "agent");
    let r = sealed_call(
        &h,
        &key,
        json!({"m": "GET", "p": "/api/agent/guide?section=quick-start", "h": auth}),
        b"",
    )
    .await;
    assert_eq!(r.status, 200);
    assert!(String::from_utf8_lossy(&r.body).starts_with("## Quick start"));
    // Without a token the guide is a sealed 401, not a plain one.
    let r = sealed_call(&h, &key, json!({"m": "GET", "p": "/api/agent/guide"}), b"").await;
    assert_eq!(r.status, 401);
    // Big text answers come gzipped when the client asks.
    let mut gz = auth.clone();
    gz["accept-encoding"] = json!("gzip");
    let r = sealed_call(
        &h,
        &key,
        json!({"m": "GET", "p": "/api/agent/guide", "h": gz}),
        b"",
    )
    .await;
    assert_eq!(r.headers["content-encoding"], "gzip");
    let mut text = String::new();
    std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&r.body[..]), &mut text)
        .unwrap();
    assert!(text.starts_with("# Hallucinator agent guide"));

    // A replayed envelope is refused.
    let (env, _) = envelope(
        &key,
        json!({"m": "GET", "p": "/api/agent/whoami", "h": auth}),
        b"",
    );
    let (s, _, _) = h.send(tunnel_request(env.clone())).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, b) = h.send(tunnel_request(env)).await;
    assert_eq!(
        (s, json_of(&b)["e2e"].clone()),
        (StatusCode::BAD_REQUEST, json!("replay"))
    );
    // The tunnel cannot be nested; another key is unknown.
    let (env, _) = envelope(&key, json!({"m": "POST", "p": "/api/e2e"}), b"");
    let (_, _, b) = h.send(tunnel_request(env)).await;
    assert_eq!(json_of(&b)["e2e"], "bad_envelope");
    let (env, _) = envelope(
        &Key::from_master([9; 32]),
        json!({"m": "GET", "p": "/"}),
        b"",
    );
    let (_, _, b) = h.send(tunnel_request(env)).await;
    assert_eq!(json_of(&b)["e2e"], "unknown_kid");

    // A person signs in through the tunnel; the cookie comes back sealed and
    // works without a CSRF token inside the tunnel.
    let login = sealed_call(
        &h,
        &key,
        json!({"m": "POST", "p": "/api/auth/login", "h": {"content-type": "application/json"}}),
        br#"{"username":"root","password":"correct horse battery"}"#,
    )
    .await;
    assert_eq!(login.status, 200);
    let cookie = login.headers["set-cookie"][0]
        .as_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(cookie.starts_with(&format!("{SESSION_COOKIE}=")));
    let r = sealed_call(
        &h,
        &key,
        json!({"m": "PATCH", "p": format!("/api/admin/users/{}", admin.id),
               "h": {"cookie": cookie, "content-type": "application/json"}}),
        br#"{"unlock":true}"#,
    )
    .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));

    // The same cookie sent plain is exposed: the page loads, the cookie is
    // cleared, and the session is over.
    let mut plain = request(Method::GET, "/", None, None);
    plain
        .headers_mut()
        .insert(header::COOKIE, cookie.parse().unwrap());
    let (s, hd, _) = h.send(plain).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        hd[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    let r = sealed_call(
        &h,
        &key,
        json!({"m": "GET", "p": "/api/auth/me", "h": {"cookie": cookie}}),
        b"",
    )
    .await;
    assert_eq!(json_of(&r.body)["user"], Value::Null);

    // An event stream cannot be sealed: 406.
    h.state
        .store
        .create_run("run1", agent.id, "t", "{}", &[])
        .unwrap();
    h.state
        .store
        .set_run_finished("run1", "done", None)
        .unwrap();
    let r = sealed_call(
        &h,
        &key,
        json!({"m": "GET", "p": "/api/runs/run1/events", "h": auth}),
        b"",
    )
    .await;
    assert_eq!(r.status, 406);

    // Calls through the tunnel are marked in the audit log.
    let rows = h
        .state
        .store
        .list_audit(Some("Frieren"), None, None, 100)
        .unwrap();
    assert!(!rows.is_empty() && rows.iter().all(|e| e.sealed));
}

#[tokio::test]
async fn e2e_blocks_an_address_that_sends_garbage() {
    let key = Key::from_string(KEY).unwrap();
    let h = Harness::new(Some(Keyring::new(key.clone(), None)));
    let peer = "203.0.113.7:5000";
    let mut env = envelope(&key, json!({"m": "GET", "p": "/api/health"}), b"").0;
    let last = env.len() - 1;
    env[last] ^= 1; // the tag no longer matches
    for _ in 0..e2e::BLOCK_AFTER {
        let (s, _, b) = send(h.app(), tunnel_request(env.clone()), peer).await;
        assert_eq!(
            (s, json_of(&b)["e2e"].clone()),
            (StatusCode::BAD_REQUEST, json!("bad_envelope"))
        );
    }
    // Another site's garbage (any other type) is refused and never counts.
    for _ in 0..e2e::BLOCK_AFTER + 2 {
        let mut r = tunnel_request(env.clone());
        r.headers_mut()
            .insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
        let (s, _, _) = send(h.app(), r, "203.0.113.9:5000").await;
        assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let good = envelope(&key, json!({"m": "GET", "p": "/api/health"}), b"").0;
    let (s, _, _) = send(h.app(), tunnel_request(good), "203.0.113.9:5000").await;
    assert_eq!(s, StatusCode::OK);
    // A body without a length is refused before it is read.
    let mut r = tunnel_request(env.clone());
    r.headers_mut().remove(header::CONTENT_LENGTH);
    let (s, _, _) = send(h.app(), r, "203.0.113.9:5000").await;
    assert_eq!(s, StatusCode::LENGTH_REQUIRED);

    let (s, hd, b) = send(h.app(), tunnel_request(env), peer).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(json_of(&b)["e2e"], "blocked");
    assert!(hd.contains_key(header::RETRY_AFTER));
    let events = h.state.store.list_auth_events(10).unwrap();
    assert!(events.iter().any(|e| e.kind == "e2e_blocked"));
    // Another address is not blocked.
    let good = envelope(&key, json!({"m": "GET", "p": "/api/health"}), b"").0;
    let (s, _, _) = send(h.app(), tunnel_request(good), "203.0.113.8:5000").await;
    assert_eq!(s, StatusCode::OK);
}

/// The vendored vectors are Catelier's own: fail when they drift apart.
#[test]
fn vectors_match_catelier() {
    let dir = std::env::var_os("CATELIER_DIR")
        .map(std::path::PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join("GitHub/Catelier")));
    let Some(path) = dir.map(|d| d.join("server/tests/e2e_vectors.json")) else {
        return;
    };
    let Ok(theirs) = std::fs::read_to_string(&path) else {
        eprintln!("skipped: {} not found", path.display());
        return;
    };
    let ours = include_str!("../../tests/e2e_vectors.json");
    assert_eq!(
        serde_json::from_str::<Value>(ours).unwrap(),
        serde_json::from_str::<Value>(&theirs).unwrap(),
        "tests/e2e_vectors.json differs from {}; copy it again",
        path.display()
    );
}

/// The browser client (static/e2e.js) passes the same vectors, on both of
/// its backends. Needs `node`; skipped without it.
#[test]
fn web_client_passes_vectors() {
    let out = std::process::Command::new("node")
        .arg("tests/e2e-web.test.mjs")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output();
    match out {
        Err(_) => eprintln!("skipped: node is not installed"),
        Ok(out) => assert!(
            out.status.success(),
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    }
}
