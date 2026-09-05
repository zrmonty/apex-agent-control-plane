//! Small, bounded HTTP/1.1 framing for this gate's fixed Keycloak paths only.
use super::{BACKEND, FRONT};
use reqwest::{
    Client, Method,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::server::TlsStream;
use zeroize::Zeroizing;

const MAX_REQUEST: usize = 16 * 1024;
const MAX_RESPONSE: usize = 64 * 1024;
const TOKEN_PATH: &str = "/realms/apex/protocol/openid-connect/token";
const REVOKE_PATH: &str = "/realms/apex/protocol/openid-connect/revoke";

pub(super) struct Request {
    method: Method,
    target: String,
    headers: HeaderMap,
    body: Zeroizing<Vec<u8>>,
}

impl Request {
    pub fn is_refresh(&self) -> bool {
        self.method == Method::POST
            && self.target == TOKEN_PATH
            && url::form_urlencoded::parse(&self.body)
                .any(|(name, value)| name == "grant_type" && value == "refresh_token")
    }

    pub fn is_revocation(&self) -> bool {
        self.method == Method::POST && self.target == REVOKE_PATH
    }

    pub async fn forward(mut self, client: &Client) -> Result<reqwest::Response, &'static str> {
        for name in [
            "host",
            "connection",
            "content-length",
            "accept-encoding",
            "proxy-authorization",
            "proxy-connection",
            "keep-alive",
            "te",
            "trailer",
            "upgrade",
        ] {
            self.headers.remove(name);
        }
        client
            .request(self.method, format!("{BACKEND}{}", self.target))
            .headers(self.headers)
            .header("host", FRONT)
            .body(std::mem::take(&mut *self.body))
            .send()
            .await
            .map_err(|_| "fixed HTTPS Keycloak backend request failed")
    }
}

pub(super) async fn read_request(tls: &mut TlsStream<TcpStream>) -> Result<Request, &'static str> {
    let mut bytes = Zeroizing::new(Vec::new());
    let header_end = loop {
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
        read_more(tls, &mut bytes).await?;
    };
    let head = std::str::from_utf8(&bytes[..header_end]).map_err(|_| "non-UTF8 request header")?;
    let mut lines = head.split("\r\n");
    let mut line = lines.next().ok_or("missing request line")?.split(' ');
    let method = match line.next() {
        Some("GET") => Method::GET,
        Some("POST") => Method::POST,
        _ => return Err("gate accepts only GET and POST"),
    };
    let target = line.next().ok_or("missing request target")?.to_owned();
    if line.next() != Some("HTTP/1.1") || line.next().is_some() || target.contains('#') {
        return Err("invalid gate request line");
    }
    let (path, query) = target
        .split_once('?')
        .map_or((target.as_str(), None), |(p, q)| (p, Some(q)));
    let allowed = match (method.as_str(), path) {
        ("GET", "/realms/apex/protocol/openid-connect/auth")
        | ("POST", "/realms/apex/login-actions/authenticate") => true,
        ("GET", "/realms/apex/.well-known/openid-configuration")
        | ("GET", "/realms/apex/protocol/openid-connect/certs")
        | ("POST", TOKEN_PATH | REVOKE_PATH) => query.is_none(),
        _ => false,
    };
    if !allowed {
        return Err("request is outside fixed gate paths");
    }
    let mut headers = HeaderMap::new();
    for line in lines.take_while(|line| !line.is_empty()) {
        if headers.len() >= 64 || line.starts_with([' ', '\t']) {
            return Err("invalid request headers");
        }
        let (name, value) = line.split_once(':').ok_or("invalid header field")?;
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| "invalid header name")?;
        let mut value = HeaderValue::from_str(value.trim()).map_err(|_| "invalid header value")?;
        if name == "authorization" || name == "cookie" {
            value.set_sensitive(true);
        }
        headers.append(name, value);
    }
    let hosts: Vec<_> = headers.get_all("host").iter().collect();
    if hosts.len() != 1
        || hosts[0].as_bytes() != FRONT.as_bytes()
        || headers.contains_key("transfer-encoding")
        || headers.contains_key("expect")
        || headers.contains_key("content-encoding")
    {
        return Err("invalid host or unsupported request framing");
    }
    let lengths: Vec<_> = headers.get_all("content-length").iter().collect();
    let length = match lengths.as_slice() {
        [] if method == Method::GET => 0,
        [value] => {
            let value = value.to_str().map_err(|_| "invalid length")?;
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid length");
            }
            value.parse::<usize>().map_err(|_| "invalid length")?
        }
        _ => return Err("ambiguous or missing request length"),
    };
    if length > MAX_REQUEST - header_end {
        return Err("request exceeds 16 KiB");
    }
    let end = header_end + length;
    while bytes.len() < end {
        read_more(tls, &mut bytes).await?;
    }
    if bytes.len() != end {
        return Err("request pipelining is not supported");
    }
    Ok(Request {
        method,
        target,
        headers,
        body: Zeroizing::new(bytes[header_end..].to_vec()),
    })
}

async fn read_more(
    tls: &mut TlsStream<TcpStream>,
    bytes: &mut Vec<u8>,
) -> Result<(), &'static str> {
    let available = MAX_REQUEST
        .checked_sub(bytes.len())
        .filter(|v| *v > 0)
        .ok_or("request exceeds 16 KiB")?;
    let mut chunk = Zeroizing::new([0u8; 1024]);
    let size = available.min(chunk.len());
    let count = tls
        .read(&mut chunk[..size])
        .await
        .map_err(|_| "gate request read failed")?;
    if count == 0 {
        return Err("incomplete gate request");
    }
    bytes.extend_from_slice(&chunk[..count]);
    Ok(())
}

pub(super) struct Reply {
    pub status: u16,
    pub body: Zeroizing<Vec<u8>>,
    head: Zeroizing<Vec<u8>>,
}

pub(super) async fn read_reply(mut response: reqwest::Response) -> Result<Reply, &'static str> {
    if response.headers().contains_key("content-encoding")
        || response
            .content_length()
            .is_some_and(|size| size > MAX_RESPONSE as u64)
    {
        return Err("unsupported or oversized Keycloak response");
    }
    let status = response.status();
    let mut head = Zeroizing::new(
        format!(
            "HTTP/1.1 {} {}\r\n",
            status.as_u16(),
            status.canonical_reason().unwrap_or("Response")
        )
        .into_bytes(),
    );
    for (name, value) in response.headers() {
        if matches!(
            name.as_str(),
            "connection"
                | "transfer-encoding"
                | "content-length"
                | "keep-alive"
                | "trailer"
                | "upgrade"
                | "proxy-authenticate"
                | "proxy-authorization"
        ) {
            continue;
        }
        if name.as_str().len() + value.as_bytes().len() + 4 > MAX_RESPONSE - head.len() {
            return Err("Keycloak response headers exceed bound");
        }
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    // Reserve enough bytes for our explicit length/connection-close framing;
    // the total forwarded response, not just its body, is limited to 64 KiB.
    let room = MAX_RESPONSE
        .checked_sub(head.len() + 64)
        .ok_or("response headers exceed bound")?;
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "incomplete Keycloak reply")?
    {
        if chunk.len() > room - body.len() {
            return Err("Keycloak response exceeds 64 KiB");
        }
        body.extend_from_slice(&chunk);
    }
    head.extend_from_slice(
        format!(
            "content-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        )
        .as_bytes(),
    );
    Ok(Reply {
        status: status.as_u16(),
        body,
        head,
    })
}

impl Reply {
    pub async fn write(self, tls: &mut TlsStream<TcpStream>) -> Result<(), &'static str> {
        tls.write_all(&self.head)
            .await
            .map_err(|_| "gate response header write failed")?;
        tls.write_all(&self.body)
            .await
            .map_err(|_| "gate response body write failed")?;
        tls.shutdown().await.map_err(|_| "gate TLS close failed")
    }
}
