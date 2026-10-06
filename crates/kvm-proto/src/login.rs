//! Login-response parsing for the ES3 KVM (§3.1). The vendor UI posts
//! `{"pass","timezone","time"}` to `/cgi-bin/login.lua` and reads back
//! `{"result":0,"token":"0.<digits>",...}` (login.html:129, kvm.js:191).
#![deny(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use core::str;

/// A validated session token of the form `0.<digits>` (the vendor matches
/// `/token=0\.\d+/`), sent back as `Cookie: token=<token>` and `?token=`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn into_string(self) -> String {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginError {
    NotUtf8,
    ResultNotOk,
    NoToken,
    BadTokenFormat,
}

/// Parse the JSON body of `POST /cgi-bin/login.lua`. Success is
/// `"result":0` plus a `"token"` string matching `0.<digits>`.
pub fn parse_login_token(body: &[u8]) -> Result<Token, LoginError> {
    let text = str::from_utf8(body).map_err(|_| LoginError::NotUtf8)?;
    if !result_is_zero(text) {
        return Err(LoginError::ResultNotOk);
    }
    let raw = json_string_value(text, "token").ok_or(LoginError::NoToken)?;
    if is_valid_token(raw) {
        Ok(Token(raw.to_owned()))
    } else {
        Err(LoginError::BadTokenFormat)
    }
}

/// `0.` followed by one or more ASCII digits and nothing else.
fn is_valid_token(s: &str) -> bool {
    match s.strip_prefix("0.") {
        Some(rest) => !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// Raw inner text of the first `"key":"..."` string value. No escape
/// processing — adequate for the fixed, tiny login body (M0).
fn json_string_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let needle = ["\"", key, "\""].concat();
    let key_at = text.find(&needle)?;
    let after_key = key_at.checked_add(needle.len())?;
    let tail = text.get(after_key..)?;
    let colon = tail.find(':')?;
    let after_colon = colon.checked_add(1)?;
    let vtail = tail.get(after_colon..)?.trim_start();
    let inner = vtail.strip_prefix('"')?;
    let end = inner.find('"')?;
    inner.get(..end)
}

/// True when a numeric `"result"` value is exactly `0` (a string result is
/// a failure message and is rejected).
fn result_is_zero(text: &str) -> bool {
    let needle = "\"result\"";
    let Some(key_at) = text.find(needle) else {
        return false;
    };
    let Some(after_key) = key_at.checked_add(needle.len()) else {
        return false;
    };
    let Some(tail) = text.get(after_key..) else {
        return false;
    };
    let Some(colon) = tail.find(':') else {
        return false;
    };
    let Some(after_colon) = colon.checked_add(1) else {
        return false;
    };
    let Some(vtail) = tail.get(after_colon..).map(str::trim_start) else {
        return false;
    };
    let num: String = vtail
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-' || *c == '+')
        .collect();
    num == "0"
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::as_conversions
    )]
    use super::*;

    #[test]
    fn extracts_token_from_success_body() {
        let body = br#"{"result":0,"token":"0.123456789","role":"admin"}"#;
        assert_eq!(parse_login_token(body).unwrap().as_str(), "0.123456789");
    }

    #[test]
    fn rejects_missing_bad_and_failed() {
        assert_eq!(
            parse_login_token(br#"{"result":0,"role":"x"}"#),
            Err(LoginError::NoToken)
        );
        assert_eq!(
            parse_login_token(br#"{"result":0,"token":"0.12a"}"#),
            Err(LoginError::BadTokenFormat)
        );
        assert_eq!(
            parse_login_token(br#"{"result":0,"token":"1.5"}"#),
            Err(LoginError::BadTokenFormat)
        );
        assert_eq!(
            parse_login_token(br#"{"result":0,"token":"0."}"#),
            Err(LoginError::BadTokenFormat)
        );
        assert_eq!(
            parse_login_token(br#"{"result":"invalid password","code":200}"#),
            Err(LoginError::ResultNotOk)
        );
        assert_eq!(parse_login_token(&[0xFFu8, 0xFE]), Err(LoginError::NotUtf8));
    }
}
