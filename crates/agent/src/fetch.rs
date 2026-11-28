//! Downloads for image imports: HTTPS only, and only to addresses that the image may reach.
//!
//! The URL is a tenant's and the node sits inside the operator's network, so:
//! - every address that the host name resolves to is checked, at every redirect, and the
//!   connection goes to an address that was checked (a second lookup could answer otherwise);
//! - loopback, link-local (cloud metadata), multicast, reserved and documentation addresses are
//!   never reached; private and shared (CGNAT) ones only where the operator allows them;
//! - the length must be announced and is enforced, the checksum is computed while writing, and
//!   connecting, the answer, each read and the number of redirects are bounded.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode, Uri, header};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use sha2::Digest;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;
use torngat_api::image::{Checksum, valid_url};

/// Which addresses a download may reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Public addresses only.
    Public,
    /// Also private and shared (CGNAT) ones: for platform images, where the operator allows a
    /// mirror on their own network.
    Private,
    /// Anything but the unspecified address: tests only.
    #[cfg(test)]
    Loopback,
}

#[derive(Debug, Clone)]
pub struct Limits {
    /// Largest file.
    pub max_bytes: u64,
    pub max_redirects: usize,
    /// For each name lookup and each connection, TLS included.
    pub connect: Duration,
    /// From the request to the headers of the answer.
    pub response: Duration,
    /// Longest wait for more of the body.
    pub idle: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: 64 << 40,
            max_redirects: 5,
            connect: Duration::from_secs(10),
            response: Duration::from_secs(30),
            idle: Duration::from_secs(60),
        }
    }
}

/// Errors are shown to the image's owner: they name the host, never a resolved address.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("not a valid https URL")]
    Url,
    #[error("{0} cannot be reached from here: it is not a public address")]
    NotAllowed(String),
    #[error("{0} has no address")]
    NoAddress(String),
    #[error("cannot connect to {0}")]
    Connect(String),
    #[error("TLS with {0} failed: {1}")]
    Tls(String, String),
    #[error("HTTP: {0}")]
    Http(String),
    #[error("the server answered {0}")]
    Status(u16),
    #[error("more than {0} redirects")]
    Redirects(usize),
    #[error("a redirect to something other than an https URL")]
    Redirect,
    #[error("the server does not say how long the file is")]
    NoLength,
    #[error("the file is larger than {0} bytes")]
    TooLarge(u64),
    #[error("the file is {got} bytes, not the {want} announced")]
    Length { got: u64, want: u64 },
    #[error("the server sent the file encoded ({0})")]
    Encoded(String),
    #[error("the checksum does not match")]
    Checksum,
    #[error("timed out")]
    Timeout,
    #[error("cannot write the file: {0}")]
    Write(std::io::Error),
    #[error("no trusted certificate authorities")]
    NoRoots,
}

/// Whether a download may reach `ip`.
pub fn allowed(ip: IpAddr, reach: Reach) -> bool {
    match ip {
        IpAddr::V4(v4) => allowed_v4(v4, reach),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => allowed_v4(v4, reach),
            None => allowed_v6(v6, reach),
        },
    }
}

fn in_v4(ip: Ipv4Addr, net: [u8; 4], len: u32) -> bool {
    let mask = u32::MAX.checked_shl(32 - len).unwrap_or(0);
    u32::from(ip) & mask == u32::from(Ipv4Addr::from(net)) & mask
}

fn allowed_v4(ip: Ipv4Addr, reach: Reach) -> bool {
    #[cfg(test)]
    if reach == Reach::Loopback {
        return !ip.is_unspecified();
    }
    const NEVER: &[([u8; 4], u32)] = &[
        ([0, 0, 0, 0], 8),       // "this network"
        ([127, 0, 0, 0], 8),     // loopback
        ([169, 254, 0, 0], 16),  // link-local, cloud metadata
        ([192, 0, 0, 0], 24),    // IETF protocol assignments
        ([192, 0, 2, 0], 24),    // documentation
        ([192, 88, 99, 0], 24),  // 6to4 relays
        ([198, 18, 0, 0], 15),   // benchmarking
        ([198, 51, 100, 0], 24), // documentation
        ([203, 0, 113, 0], 24),  // documentation
        ([224, 0, 0, 0], 4),     // multicast
        ([240, 0, 0, 0], 4),     // reserved, broadcast
    ];
    const PRIVATE: &[([u8; 4], u32)] = &[
        ([10, 0, 0, 0], 8),
        ([100, 64, 0, 0], 10), // shared (CGNAT)
        ([172, 16, 0, 0], 12),
        ([192, 168, 0, 0], 16),
    ];
    if NEVER.iter().any(|(n, l)| in_v4(ip, *n, *l)) {
        return false;
    }
    reach == Reach::Private || !PRIVATE.iter().any(|(n, l)| in_v4(ip, *n, *l))
}

fn in_v6(ip: Ipv6Addr, net: [u16; 8], len: u32) -> bool {
    let mask = u128::MAX.checked_shl(128 - len).unwrap_or(0);
    u128::from(ip) & mask == u128::from(Ipv6Addr::from(net)) & mask
}

fn allowed_v6(ip: Ipv6Addr, reach: Reach) -> bool {
    #[cfg(test)]
    if reach == Reach::Loopback {
        return !ip.is_unspecified();
    }
    // Only global unicast (2000::/3) can be public.
    if !in_v6(ip, [0x2000, 0, 0, 0, 0, 0, 0, 0], 3) {
        return reach == Reach::Private && in_v6(ip, [0xfc00, 0, 0, 0, 0, 0, 0, 0], 7);
    }
    const NEVER: &[([u16; 8], u32)] = &[
        ([0x2001, 0, 0, 0, 0, 0, 0, 0], 23), // IETF protocol assignments, Teredo
        ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32), // documentation
        ([0x2002, 0, 0, 0, 0, 0, 0, 0], 16), // 6to4: an IPv4 address inside
        ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20), // documentation
    ];
    !NEVER.iter().any(|(n, l)| in_v6(ip, *n, *l))
}

enum Hasher {
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
}

impl Hasher {
    fn new(c: &Checksum) -> Self {
        match c {
            Checksum::Sha256(_) => Hasher::Sha256(sha2::Sha256::new()),
            Checksum::Sha512(_) => Hasher::Sha512(sha2::Sha512::new()),
        }
    }

    fn update(&mut self, b: &[u8]) {
        match self {
            Hasher::Sha256(h) => h.update(b),
            Hasher::Sha512(h) => h.update(b),
        }
    }

    fn matches(self, c: &Checksum) -> bool {
        let (got, want) = match (self, c) {
            (Hasher::Sha256(h), Checksum::Sha256(w)) => (torngat_pki::hex(&h.finalize()), w),
            (Hasher::Sha512(h), Checksum::Sha512(w)) => (torngat_pki::hex(&h.finalize()), w),
            _ => return false,
        };
        got == *want
    }
}

/// The https URI of `url`, if it passes the same checks as the API's.
fn parse(url: &str) -> Result<Uri, FetchError> {
    if !valid_url(url) {
        return Err(FetchError::Url);
    }
    let uri: Uri = url.parse().map_err(|_| FetchError::Url)?;
    if uri.scheme_str() != Some("https") || uri.host().is_none() {
        return Err(FetchError::Url);
    }
    Ok(uri)
}

/// Where a redirect from `base` to `location` goes: absolute https URLs and absolute paths only.
fn follow(base: &Uri, location: &str) -> Result<Uri, FetchError> {
    let url = if location.starts_with("https://") {
        location.to_owned()
    } else if let Some(rest) = location.strip_prefix("//") {
        format!("https://{rest}")
    } else if location.starts_with('/') {
        let authority = base.authority().ok_or(FetchError::Redirect)?;
        format!("https://{authority}{location}")
    } else {
        return Err(FetchError::Redirect);
    };
    parse(&url).map_err(|_| FetchError::Redirect)
}

#[derive(Debug, Clone)]
pub struct Fetcher {
    tls: Arc<rustls::ClientConfig>,
    reach: Reach,
    limits: Limits,
}

impl Fetcher {
    /// Trusts the system's certificate authorities (with the operator's own, if added there).
    pub fn new(reach: Reach, limits: Limits) -> Result<Self, FetchError> {
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_native_certs::load_native_certs().certs {
            let _ = roots.add(c);
        }
        Self::with_roots(roots, reach, limits)
    }

    pub fn with_roots(
        roots: rustls::RootCertStore,
        reach: Reach,
        limits: Limits,
    ) -> Result<Self, FetchError> {
        if roots.is_empty() {
            return Err(FetchError::NoRoots);
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| FetchError::Tls(String::new(), e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            tls: Arc::new(tls),
            reach,
            limits,
        })
    }

    /// The length of the file at `url`, as its server announces it.
    pub async fn length(&self, url: &str) -> Result<u64, FetchError> {
        let resp = self.get(url).await?;
        self.length_of(&resp)
    }

    /// Writes the file at `url` to `out`: exactly `length` bytes, which must match `checksum`.
    /// On error, `out` may hold part of it.
    pub async fn download(
        &self,
        url: &str,
        length: u64,
        checksum: &Checksum,
        out: &mut (impl AsyncWrite + Unpin),
    ) -> Result<(), FetchError> {
        let resp = self.get(url).await?;
        let announced = self.length_of(&resp)?;
        if announced != length {
            return Err(FetchError::Length {
                got: announced,
                want: length,
            });
        }
        let mut body = resp.into_body();
        let mut hash = Hasher::new(checksum);
        let mut got: u64 = 0;
        while let Some(frame) = timeout(self.limits.idle, body.frame())
            .await
            .map_err(|_| FetchError::Timeout)?
        {
            let frame = frame.map_err(|e| FetchError::Http(e.to_string()))?;
            let Ok(data) = frame.into_data() else {
                continue;
            };
            got = got.saturating_add(data.len() as u64);
            if got > length {
                return Err(FetchError::Length { got, want: length });
            }
            hash.update(&data);
            out.write_all(&data).await.map_err(FetchError::Write)?;
        }
        if got != length {
            return Err(FetchError::Length { got, want: length });
        }
        out.flush().await.map_err(FetchError::Write)?;
        if !hash.matches(checksum) {
            return Err(FetchError::Checksum);
        }
        Ok(())
    }

    fn length_of(&self, resp: &Response<Incoming>) -> Result<u64, FetchError> {
        if let Some(e) = resp.headers().get(header::CONTENT_ENCODING) {
            let e = e.to_str().unwrap_or("?");
            if !e.eq_ignore_ascii_case("identity") {
                return Err(FetchError::Encoded(e.chars().take(32).collect()));
            }
        }
        let n: u64 = resp
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .ok_or(FetchError::NoLength)?;
        if n > self.limits.max_bytes {
            return Err(FetchError::TooLarge(self.limits.max_bytes));
        }
        Ok(n)
    }

    /// The answer to a GET of `url`, after redirects: always 200.
    async fn get(&self, url: &str) -> Result<Response<Incoming>, FetchError> {
        let mut uri = parse(url)?;
        for hop in 0..=self.limits.max_redirects {
            let resp = timeout(self.limits.response, self.request(&uri))
                .await
                .map_err(|_| FetchError::Timeout)??;
            let status = resp.status();
            let redirect = matches!(
                status,
                StatusCode::MOVED_PERMANENTLY
                    | StatusCode::FOUND
                    | StatusCode::SEE_OTHER
                    | StatusCode::TEMPORARY_REDIRECT
                    | StatusCode::PERMANENT_REDIRECT
            );
            if redirect {
                if hop == self.limits.max_redirects {
                    break;
                }
                let location = resp
                    .headers()
                    .get(header::LOCATION)
                    .and_then(|l| l.to_str().ok())
                    .ok_or(FetchError::Redirect)?;
                uri = follow(&uri, location)?;
                continue;
            }
            if status != StatusCode::OK {
                return Err(FetchError::Status(status.as_u16()));
            }
            return Ok(resp);
        }
        Err(FetchError::Redirects(self.limits.max_redirects))
    }

    /// The addresses of `uri`'s host, if the download may reach all of them.
    async fn addresses(&self, uri: &Uri) -> Result<(String, Vec<SocketAddr>), FetchError> {
        let host = uri.host().ok_or(FetchError::Url)?;
        let port = uri.port_u16().unwrap_or(443);
        // An IPv6 literal comes in brackets.
        let bare = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let addrs: Vec<SocketAddr> = match bare.parse::<IpAddr>() {
            Ok(ip) => vec![SocketAddr::new(ip, port)],
            Err(_) => timeout(
                self.limits.connect,
                tokio::net::lookup_host((bare.as_str(), port)),
            )
            .await
            .map_err(|_| FetchError::Timeout)?
            .map_err(|_| FetchError::NoAddress(bare.clone()))?
            .collect(),
        };
        if addrs.is_empty() {
            return Err(FetchError::NoAddress(bare));
        }
        // All of them: which one a later connection gets is not ours to choose.
        if !addrs.iter().all(|a| allowed(a.ip(), self.reach)) {
            return Err(FetchError::NotAllowed(bare));
        }
        Ok((bare, addrs))
    }

    async fn request(&self, uri: &Uri) -> Result<Response<Incoming>, FetchError> {
        let (host, addrs) = self.addresses(uri).await?;
        let mut tcp = None;
        for a in &addrs {
            if let Ok(Ok(s)) = timeout(self.limits.connect, tokio::net::TcpStream::connect(a)).await
            {
                tcp = Some(s);
                break;
            }
        }
        let tcp = tcp.ok_or_else(|| FetchError::Connect(host.clone()))?;
        let name = ServerName::try_from(host.clone()).map_err(|_| FetchError::Url)?;
        let tls = timeout(
            self.limits.connect,
            tokio_rustls::TlsConnector::from(self.tls.clone()).connect(name, tcp),
        )
        .await
        .map_err(|_| FetchError::Timeout)?
        .map_err(|e| FetchError::Tls(host.clone(), e.to_string()))?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| FetchError::Http(e.to_string()))?;
        // Ends when the answer and the sender are dropped.
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let authority = uri.authority().map(|a| a.as_str()).unwrap_or(&host);
        let path = uri.path_and_query().map_or("/", |p| p.as_str());
        let req = Request::get(path)
            .header(header::HOST, authority)
            .header(header::USER_AGENT, "torngat")
            .header(header::ACCEPT_ENCODING, "identity")
            .body(Empty::<Bytes>::new())
            .map_err(|e| FetchError::Http(e.to_string()))?;
        sender
            .send_request(req)
            .await
            .map_err(|e| FetchError::Http(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader};

    #[test]
    fn addresses() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for public in [
            "1.1.1.1",
            "8.8.8.8",
            "2606:4700::1111",
            "::ffff:1.1.1.1",
            "100.128.0.1",
        ] {
            assert!(allowed(ip(public), Reach::Public), "{public}");
            assert!(allowed(ip(public), Reach::Private), "{public}");
        }
        for private in [
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "100.64.0.1",
            "fd00::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!allowed(ip(private), Reach::Public), "{private}");
            assert!(allowed(ip(private), Reach::Private), "{private}");
        }
        for never in [
            "0.0.0.0",
            "127.0.0.1",
            "169.254.169.254",
            "224.0.0.1",
            "255.255.255.255",
            "192.0.2.1",
            "198.18.0.1",
            "::",
            "::1",
            "fe80::1",
            "ff02::1",
            "fec0::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a00:1",
            "2001::1",
            "2001:db8::1",
            "2002:a00:1::",
            "::127.0.0.1",
            "100::1",
        ] {
            assert!(!allowed(ip(never), Reach::Public), "{never}");
            assert!(!allowed(ip(never), Reach::Private), "{never}");
        }
        // Just outside 172.16.0.0/12.
        assert!(allowed(ip("172.32.0.1"), Reach::Public));
    }

    #[test]
    fn redirects() {
        let base: Uri = "https://a.example:8443/x/y?z".parse().unwrap();
        let to = |l: &str| follow(&base, l).map(|u| u.to_string());
        assert_eq!(to("https://b.example/f").unwrap(), "https://b.example/f");
        assert_eq!(to("//b.example/f").unwrap(), "https://b.example/f");
        assert_eq!(to("/f?g").unwrap(), "https://a.example:8443/f?g");
        for bad in [
            "http://b.example/f",
            "f",
            "../f",
            "file:///etc",
            "https://u:p@b/f",
            "",
        ] {
            assert!(to(bad).is_err(), "{bad}");
        }
    }

    /// A TLS server for `localhost` on loopback, answering each connection with `answer(path)`.
    async fn server(
        answer: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static,
    ) -> (u16, rustls::RootCertStore) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ck.cert.der().clone()).unwrap();
        let key =
            rustls::pki_types::PrivateKeyDer::try_from(ck.signing_key.serialize_der()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![ck.cert.der().clone()], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let answer = Arc::new(answer);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let (acceptor, answer) = (acceptor.clone(), answer.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut r = BufReader::new(tls);
                    let mut line = String::new();
                    if r.read_line(&mut line).await.is_err() {
                        return;
                    }
                    let path = line.split(' ').nth(1).unwrap_or("/").to_owned();
                    loop {
                        let mut h = String::new();
                        if r.read_line(&mut h).await.unwrap_or(0) <= 2 {
                            break;
                        }
                    }
                    let _ = r.get_mut().write_all(&answer(&path)).await;
                    let _ = r.get_mut().shutdown().await;
                });
            }
        });
        (port, roots)
    }

    fn ok(body: &[u8], length: usize) -> Vec<u8> {
        let mut v =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n")
                .into_bytes();
        v.extend_from_slice(body);
        v
    }

    fn redirect(to: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 302 Found\r\nLocation: {to}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes()
    }

    fn sha256(b: &[u8]) -> Checksum {
        Checksum::Sha256(torngat_pki::hex(&sha2::Sha256::digest(b)))
    }

    #[tokio::test]
    async fn downloads() {
        let file = b"QFI\xfb hello image".repeat(1000);
        let body = file.clone();
        let (port, roots) = server(move |path| match path {
            "/file" => ok(&body, body.len()),
            "/short" => ok(&body[..10], body.len()),
            "/long" => ok(&body, 10),
            "/again" => redirect("/file"),
            "/loop" => redirect("/loop"),
            "/http" => redirect("http://localhost/file"),
            "/gzip" => b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 3\r\n\r\nabc"
                .to_vec(),
            "/chunked" => {
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
                    .to_vec()
            }
            _ => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
        })
        .await;
        let limits = Limits {
            max_bytes: 1 << 20,
            idle: Duration::from_secs(5),
            ..Default::default()
        };
        let f = Fetcher::with_roots(roots.clone(), Reach::Loopback, limits.clone()).unwrap();
        let url = |p: &str| format!("https://localhost:{port}{p}");
        let n = file.len() as u64;

        assert_eq!(f.length(&url("/file")).await.unwrap(), n);
        assert_eq!(f.length(&url("/again")).await.unwrap(), n);
        let mut out = Vec::new();
        f.download(&url("/again"), n, &sha256(&file), &mut out)
            .await
            .unwrap();
        assert_eq!(out, file);

        let mut out = Vec::new();
        let wrong = sha256(b"other");
        assert!(matches!(
            f.download(&url("/file"), n, &wrong, &mut out).await,
            Err(FetchError::Checksum)
        ));
        assert!(matches!(
            f.download(&url("/file"), n + 1, &sha256(&file), &mut Vec::new())
                .await,
            Err(FetchError::Length { .. })
        ));
        assert!(matches!(
            f.download(&url("/short"), n, &sha256(&file), &mut Vec::new())
                .await,
            Err(FetchError::Length { .. } | FetchError::Http(_))
        ));
        assert!(matches!(
            f.download(&url("/long"), 10, &sha256(&file), &mut Vec::new())
                .await,
            Err(FetchError::Checksum)
        ));
        assert!(matches!(
            f.length(&url("/loop")).await,
            Err(FetchError::Redirects(5))
        ));
        assert!(matches!(
            f.length(&url("/http")).await,
            Err(FetchError::Redirect)
        ));
        assert!(matches!(
            f.length(&url("/gzip")).await,
            Err(FetchError::Encoded(_))
        ));
        assert!(matches!(
            f.length(&url("/chunked")).await,
            Err(FetchError::NoLength)
        ));
        assert!(matches!(
            f.length(&url("/nope")).await,
            Err(FetchError::Status(404))
        ));
        assert!(matches!(
            f.length("http://localhost/x").await,
            Err(FetchError::Url)
        ));

        // Too large for the limit.
        let small = Fetcher::with_roots(
            roots.clone(),
            Reach::Loopback,
            Limits {
                max_bytes: 100,
                ..limits.clone()
            },
        )
        .unwrap();
        assert!(matches!(
            small.length(&url("/file")).await,
            Err(FetchError::TooLarge(100))
        ));

        // Loopback is never reached for real, by name or by address.
        for reach in [Reach::Public, Reach::Private] {
            let f = Fetcher::with_roots(roots.clone(), reach, limits.clone()).unwrap();
            assert!(matches!(
                f.length(&url("/file")).await,
                Err(FetchError::NotAllowed(_))
            ));
            let by_ip = format!("https://127.0.0.1:{port}/file");
            assert!(matches!(
                f.length(&by_ip).await,
                Err(FetchError::NotAllowed(_))
            ));
            let v6 = format!("https://[::1]:{port}/file");
            assert!(matches!(
                f.length(&v6).await,
                Err(FetchError::NotAllowed(_))
            ));
        }

        // A certificate that is not trusted.
        let mut other = rustls::RootCertStore::empty();
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        other.add(ck.cert.der().clone()).unwrap();
        let f = Fetcher::with_roots(other, Reach::Loopback, limits).unwrap();
        assert!(matches!(
            f.length(&url("/file")).await,
            Err(FetchError::Tls(..))
        ));
    }
}
