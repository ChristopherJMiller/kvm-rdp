use serde::Serialize;

#[derive(Clone, Copy, Debug)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn http(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
    pub fn ws(self) -> &'static str {
        match self {
            Scheme::Http => "ws",
            Scheme::Https => "wss",
        }
    }
}

#[derive(Clone, Debug)]
pub struct KvmTarget {
    pub scheme: Scheme,
    pub host: String,
    pub login_port: u16,
    pub video_port: u16,
    pub control_port: u16,
}

#[derive(Serialize)]
struct LoginBody<'a> {
    pass: &'a str,
    timezone: &'a str,
    time: i64,
}

/// Body of `POST /cgi-bin/login.lua` (login.html). Infallible: the struct has no maps.
pub fn build_login_body(password: &str, timezone: &str, now_unix: i64) -> String {
    let body = LoginBody {
        pass: password,
        timezone,
        time: now_unix,
    };
    serde_json::to_string(&body).unwrap_or_else(|_| String::new())
}

pub fn flv_url(t: &KvmTarget, token: &str) -> String {
    format!(
        "{}://{}:{}/av.flv?token={}",
        t.scheme.http(),
        t.host,
        t.video_port,
        token
    )
}
pub fn logout_url(t: &KvmTarget) -> String {
    format!(
        "{}://{}:{}/cgi-bin/login.lua?logout",
        t.scheme.http(),
        t.host,
        t.login_port
    )
}
pub fn websocket_url(t: &KvmTarget) -> String {
    format!(
        "{}://{}:{}/websocket",
        t.scheme.ws(),
        t.host,
        t.control_port
    )
}
pub fn token_cookie_header(token: &str) -> String {
    format!("token={token}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn https_target() -> KvmTarget {
        KvmTarget {
            scheme: Scheme::Https,
            host: "192.168.0.50".to_string(),
            login_port: 443,
            video_port: 8881,
            control_port: 8889,
        }
    }

    #[test]
    fn login_body_is_pass_timezone_time_in_order() {
        assert_eq!(
            build_login_body("s3cret", "America/Chicago", 1_759_680_000),
            r#"{"pass":"s3cret","timezone":"America/Chicago","time":1759680000}"#
        );
    }

    #[test]
    fn urls_and_cookie_match_the_web_ui() {
        let t = https_target();
        assert_eq!(
            flv_url(&t, "0.12345"),
            "https://192.168.0.50:8881/av.flv?token=0.12345"
        );
        assert_eq!(
            logout_url(&t),
            "https://192.168.0.50:443/cgi-bin/login.lua?logout"
        );
        assert_eq!(websocket_url(&t), "wss://192.168.0.50:8889/websocket");
        assert_eq!(token_cookie_header("0.12345"), "token=0.12345");
    }

    #[test]
    fn http_scheme_uses_ws_not_wss() {
        let t = KvmTarget {
            scheme: Scheme::Http,
            host: "h".into(),
            login_port: 80,
            video_port: 8880,
            control_port: 8888,
        };
        assert_eq!(websocket_url(&t), "ws://h:8888/websocket");
        assert_eq!(flv_url(&t, "0.1"), "http://h:8880/av.flv?token=0.1");
    }
}
