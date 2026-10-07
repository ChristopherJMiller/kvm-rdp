//! `/cgi-bin/login.lua` on the web port (§3.1, §3.2): logins coexist and
//! each gets a `0.<digits>` token; `?logout` is global — every token dies,
//! open FLVs keep streaming.
use crate::http::{Request, respond};
use crate::state::{Shared, SimEvent};
use tokio::io::AsyncWrite;

pub(crate) async fn serve<S: AsyncWrite + Unpin>(
    mut io: S,
    req: Request,
    shared: &Shared,
    password: &str,
) {
    let json = "application/json";
    match (req.method.as_str(), req.path()) {
        ("POST", "/cgi-bin/login.lua") => {
            let pass = serde_json::from_slice::<serde_json::Value>(&req.body)
                .ok()
                .and_then(|v| v.get("pass").and_then(|p| p.as_str()).map(str::to_owned));
            let ok = !shared.policy().reject_logins && pass.as_deref() == Some(password);
            shared.record(SimEvent::Login { ok });
            let body = if ok {
                format!(
                    "{{\"result\":0,\"token\":\"{}\",\"role\":\"admin\"}}",
                    shared.mint_token()
                )
            } else {
                "{\"result\":\"invalid password\",\"code\":200}".to_owned()
            };
            let _ = respond(&mut io, 200, json, body.as_bytes()).await;
        }
        ("GET", "/cgi-bin/login.lua") if req.query() == "logout" => {
            shared.clear_tokens();
            shared.record(SimEvent::Logout);
            let _ = respond(&mut io, 200, json, b"{\"result\":0}").await;
        }
        _ => {
            let _ = respond(&mut io, 404, "text/plain", b"not found").await;
        }
    }
}
