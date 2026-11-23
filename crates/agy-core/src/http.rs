//! Synchronous HTTP/1.1 client over nagoya, nago-http, and nago-rustls.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::sync::atomic::{AtomicI64, Ordering};
use core::time::Duration;

use nago_rustls::rustls_pki_types::CertificateDer;
use serde::Deserialize;

use crate::{Error, Result};

const DEFAULT_TIMEOUT_SECS: u64 = 20;
const DOH_TIMEOUT_SECS: u64 = 10;
const CLOCK_SKEW_FLOOR_SECS: i64 = 5;
const CLOUD_CLIENT_VERSION: &str = "2.23.0";

fn default_cloud_user_agent() -> String {
    #[cfg(target_os = "macos")]
    let os = "darwin";
    #[cfg(target_os = "linux")]
    let os = "linux";
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let os = "unix";

    #[cfg(target_arch = "aarch64")]
    let arch = "arm64";
    #[cfg(target_arch = "x86_64")]
    let arch = "amd64";
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    let arch = "unknown";

    format!("antigravity/hub/{CLOUD_CLIENT_VERSION} {os}/{arch}")
}

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> Result<&str> {
        core::str::from_utf8(&self.body)
            .map_err(|e| Error::Network(format!("response body is not valid UTF-8: {e}")))
    }

    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(|e| Error::Json(e.to_string()))
    }
}

pub struct HttpClient {
    client: nago_http::Client,
    reactor: nagoya::reactor::Reactor,
    tls_config: Arc<nago_rustls::rustls::ClientConfig>,
    default_tls: Arc<nago_rustls::rustls::ClientConfig>,
    has_custom_ca: bool,
    user_agent: String,
    clock_skew: AtomicI64,
}

impl fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpClient")
            .field("user_agent", &self.user_agent)
            .field("clock_skew_secs", &self.clock_skew_secs())
            .finish()
    }
}

impl HttpClient {
    pub fn new() -> Result<Self> {
        if nago_rustls::rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = ps_rustcrypto::provider_with_rsa_pss().install_default();
        }
        let default_tls = nago_rustls::default_client_config();
        let custom_tls = load_custom_ca_tls_config()?;
        let has_custom_ca = custom_tls.is_some();
        let tls_config = custom_tls.unwrap_or_else(|| default_tls.clone());
        let client = nago_http::Client::with_tls_config(tls_config.clone())
            .map_err(|e| Error::Network(e.to_string()))?
            .with_timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS));
        let reactor = nagoya::reactor::Reactor::start()
            .map_err(|e| Error::Network(format!("reactor start failed: {e:?}")))?;
        let user_agent = eko::env::var("AGY_SWAP_USER_AGENT")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(default_cloud_user_agent);
        Ok(Self {
            client,
            reactor,
            tls_config,
            default_tls,
            has_custom_ca,
            user_agent,
            clock_skew: AtomicI64::new(0),
        })
    }

    pub fn clock_skew_secs(&self) -> i64 {
        let skew = self.clock_skew.load(Ordering::Relaxed);
        if skew.abs() < CLOCK_SKEW_FLOOR_SECS { 0 } else { skew }
    }

    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    pub fn get(&self, url: &str, headers: &[(&str, &str)]) -> Result<HttpResponse> {
        self.send_request("GET", url, headers, None)
    }

    pub fn post_form(
        &self,
        url: &str,
        form: &[(&str, &str)],
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse> {
        let mut encoded = String::new();
        for (idx, &(k, v)) in form.iter().enumerate() {
            if idx > 0 {
                encoded.push('&');
            }
            encoded.push_str(&url_encode_component(k));
            encoded.push('=');
            encoded.push_str(&url_encode_component(v));
        }
        self.send_request(
            "POST",
            url,
            headers,
            Some(("application/x-www-form-urlencoded", encoded.as_bytes())),
        )
    }

    pub fn post_json(
        &self,
        url: &str,
        body: &[u8],
        headers: &[(&str, &str)],
    ) -> Result<HttpResponse> {
        self.send_request("POST", url, headers, Some(("application/json", body)))
    }

    fn send_request(
        &self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<(&str, &[u8])>,
    ) -> Result<HttpResponse> {
        let has_body = body.is_some();
        let mut filtered: Vec<(&str, &str)> = Vec::with_capacity(headers.len() + 1);
        let mut has_ua = false;
        for &(k, v) in headers {
            if k.eq_ignore_ascii_case("user-agent") {
                has_ua = true;
            }
            if is_reserved_header(k, has_body) {
                continue;
            }
            filtered.push((k, v));
        }
        if !has_ua {
            filtered.push(("User-Agent", self.user_agent.as_str()));
        }
        match nagoya::block_on(self.client.send(method, url, &filtered, body)) {
            Ok(resp) => self.finish_response(resp),
            Err(err) => {
                if let Ok(parsed) = ParsedUrl::parse(url) {
                    if self.has_custom_ca && parsed.tls && matches!(err, nago_http::Error::Tls(_)) {
                        if let Ok(target) = nago_http::Target::resolve(parsed.host, parsed.port) {
                            if let Ok(resp) = self.send_to_target(method, &parsed, &target, &filtered, body, &self.default_tls) {
                                return self.finish_response(resp);
                            }
                        }
                    }
                    if should_retry_via_doh(&parsed, &err) {
                        if let Ok(ips) = self.resolve_via_doh(parsed.host) {
                            if let Ok(target) = nago_http::Target::pinned(parsed.host, parsed.port, &ips, parsed.tls) {
                                if let Ok(resp) = self.send_to_target(method, &parsed, &target, &filtered, body, &self.tls_config) {
                                    return self.finish_response(resp);
                                }
                            }
                        }
                    }
                }
                Err(Error::Network(err.to_string()))
            }
        }
    }

    fn send_to_target(
        &self,
        method: &str,
        parsed: &ParsedUrl<'_>,
        target: &nago_http::Target,
        headers: &[(&str, &str)],
        body: Option<(&str, &[u8])>,
        tls_cfg: &Arc<nago_rustls::rustls::ClientConfig>,
    ) -> Result<nago_http::Response> {
        let mut req = nago_http::Request::new(method, parsed.path_and_query);
        for &(k, v) in headers {
            req = req.header(k, v);
        }
        if let Some((ct, payload)) = body {
            req = req.body(ct, payload);
        }
        let handle = self.reactor.handle();
        let tls = Some(tls_cfg.clone());
        let outcome = nagoya::block_on(nagoya::timeout(
            Duration::from_secs(DOH_TIMEOUT_SECS),
            async move {
                let conn = nago_http::open_with_tls_config(target, &handle, tls).await?;
                conn.send(req).await
            },
        ));
        match outcome {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(Error::Network(e.to_string())),
            Err(_) => Err(Error::Network(format!("request to {} timed out", parsed.host))),
        }
    }

    fn finish_response(&self, resp: nago_http::Response) -> Result<HttpResponse> {
        if let Some(date_hdr) = resp.header("Date") {
            if let Some(server_unix) = parse_http_date_unix(date_hdr) {
                let local_unix = eko::time::epoch_secs();
                self.clock_skew.store(server_unix - local_unix, Ordering::Relaxed);
            }
        }
        Ok(HttpResponse {
            status: resp.status,
            headers: resp.headers,
            body: resp.body,
        })
    }

    fn resolve_via_doh(&self, host: &str) -> Result<Vec<IpAddr>> {
        let endpoints = doh_endpoints();
        let ua = self.user_agent.as_str();
        for endpoint in &endpoints {
            let sep = if endpoint.contains('?') { '&' } else { '?' };
            let json_url = format!("{endpoint}{sep}name={}&type=A", url_encode_component(host));
            let json_hdrs = [("Accept", "application/dns-json"), ("User-Agent", ua)];
            if let Ok(resp) = nagoya::block_on(self.client.get(&json_url, &json_hdrs)) {
                if resp.status == 200 {
                    if let Ok(parsed) = serde_json::from_slice::<DohJsonResponse>(&resp.body) {
                        let ips = filter_public_doh_answers(&parsed.answer);
                        if !ips.is_empty() {
                            return Ok(ips);
                        }
                    }
                }
            }
            if let Some(wire_q) = build_dns_wire_query(host) {
                let dns_param = base64_encode_url_nopad(&wire_q);
                let wire_url = format!("{endpoint}{sep}dns={dns_param}");
                let wire_hdrs = [("Accept", "application/dns-message"), ("User-Agent", ua)];
                if let Ok(resp) = nagoya::block_on(self.client.get(&wire_url, &wire_hdrs)) {
                    if resp.status == 200 {
                        let ips = parse_dns_wire_answers(&resp.body);
                        if !ips.is_empty() {
                            return Ok(ips);
                        }
                    }
                }
            }
        }
        Err(Error::Network(format!("DoH lookup returned no public addresses for {host}")))
    }
}

fn is_reserved_header(name: &str, has_body: bool) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || (has_body && name.eq_ignore_ascii_case("content-type"))
}

fn load_custom_ca_tls_config() -> Result<Option<Arc<nago_rustls::rustls::ClientConfig>>> {
    let ca_path = eko::env::var("AGY_SWAP_CA_BUNDLE")
        .or_else(|| eko::env::var("CURL_CA_BUNDLE"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let Some(path) = ca_path else {
        return Ok(None);
    };
    let pem_bytes = eko::file::read(&path)?;
    let certs = parse_pem_certificates(&pem_bytes);
    if certs.is_empty() {
        return Err(Error::Crypto(format!("no valid PEM certificates in {path}")));
    }
    let mut roots = nago_rustls::rustls::RootCertStore::empty();
    let mut added = 0usize;
    for der in &certs {
        if roots.add(CertificateDer::from(der.as_slice())).is_ok() {
            added += 1;
        }
    }
    if added == 0 {
        return Err(Error::Crypto(format!("no usable root certificates in {path}")));
    }
    let cfg = nago_rustls::rustls::ClientConfig::builder_with_details(
        Arc::new(ps_rustcrypto::provider_with_rsa_pss()),
        Arc::new(nago_rustls::EkoTimeProvider),
    )
    .with_safe_default_protocol_versions()
    .map_err(|e| Error::Crypto(e.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Some(Arc::new(cfg)))
}

fn parse_pem_certificates(pem: &[u8]) -> Vec<Vec<u8>> {
    let Ok(text) = core::str::from_utf8(pem) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut in_cert = false;
    let mut b64 = String::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line == "-----BEGIN CERTIFICATE-----" {
            in_cert = true;
            b64.clear();
        } else if line == "-----END CERTIFICATE-----" {
            if in_cert {
                if let Some(der) = base64_decode_any(&b64) {
                    if !der.is_empty() {
                        out.push(der);
                    }
                }
            }
            in_cert = false;
            b64.clear();
        } else if in_cert {
            b64.push_str(line);
        }
    }
    out
}

struct ParsedUrl<'a> {
    tls: bool,
    host: &'a str,
    port: u16,
    path_and_query: &'a str,
}

impl<'a> ParsedUrl<'a> {
    fn parse(url: &'a str) -> core::result::Result<Self, ()> {
        if url.contains('#') || url.bytes().any(|b| b <= 0x20 || b == 0x7f) {
            return Err(());
        }
        let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(());
        };
        let auth_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(auth_end);
        let path_and_query = if tail.is_empty() {
            "/"
        } else if tail.starts_with('?') {
            return Err(())
        } else {
            tail
        };
        if authority.contains('@') {
            return Err(());
        }
        let default_port = if tls { 443 } else { 80 };
        let (host, port) = if let Some(b) = authority.strip_prefix('[') {
            let (h, after) = b.split_once(']').ok_or(())?;
            let p = match after.strip_prefix(':') {
                Some(ps) => ps.parse::<u16>().map_err(|_| ())?,
                None if after.is_empty() => default_port,
                None => return Err(()),
            };
            (h, p)
        } else if let Some((h, ps)) = authority.rsplit_once(':') {
            (h, ps.parse::<u16>().map_err(|_| ())?)
        } else {
            (authority, default_port)
        };
        if host.is_empty() || port == 0 {
            return Err(());
        }
        Ok(Self {
            tls,
            host,
            port,
            path_and_query,
        })
    }
}

#[derive(Deserialize)]
struct DohJsonAnswer {
    #[serde(rename = "type", default)]
    record_type: u16,
    #[serde(default)]
    data: String,
}

#[derive(Deserialize)]
struct DohJsonResponse {
    #[serde(rename = "Answer", default)]
    answer: Vec<DohJsonAnswer>,
}

fn doh_endpoints() -> Vec<String> {
    if let Some(custom) = eko::env::var("AGY_SWAP_DOH_URL") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return trimmed
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
    }
    let mut out = Vec::with_capacity(2);
    out.push("https://1.1.1.1/dns-query".to_string());
    out.push("https://8.8.8.8/resolve".to_string());
    out
}

fn should_retry_via_doh(parsed: &ParsedUrl<'_>, err: &nago_http::Error) -> bool {
    is_public_lookup_host(parsed.host)
        && matches!(
            err,
            nago_http::Error::Resolve(_)
                | nago_http::Error::Tls(_)
                | nago_http::Error::Connect(_)
                | nago_http::Error::Timeout(_)
        )
}

pub fn is_public_lookup_host(host: &str) -> bool {
    let h = host.trim();
    if h.is_empty()
        || h.eq_ignore_ascii_case("localhost")
        || h.len() > 253
        || h.parse::<IpAddr>().is_ok()
    {
        return false;
    }
    let lower = h.to_ascii_lowercase();
    !lower.ends_with(".localhost") && !lower.ends_with(".local")
}

pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            let s0 = v6.segments()[0];
            !v6.is_unspecified()
                && !v6.is_loopback()
                && !v6.is_multicast()
                && (s0 & 0xfe00) != 0xfc00
                && (s0 & 0xffc0) != 0xfe80
        }
    }
}

fn is_public_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    if o[0] == 0
        || o[0] == 10
        || o[0] == 127
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || o[0] >= 224
    {
        return false;
    }
    true
}

fn filter_public_doh_answers(answers: &[DohJsonAnswer]) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for ans in answers {
        if ans.record_type != 1 && ans.record_type != 28 {
            continue;
        }
        if let Ok(ip) = ans.data.trim().parse::<IpAddr>() {
            if is_public_ip(ip) && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

fn build_dns_wire_query(host: &str) -> Option<Vec<u8>> {
    let trimmed = host.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    let mut msg = Vec::with_capacity(64);
    msg.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    Some(msg)
}

fn skip_dns_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0usize;
    loop {
        let b = *packet.get(pos)?;
        if b == 0 {
            return Some(pos + 1);
        }
        if (b & 0xc0) == 0xc0 {
            let _ = *packet.get(pos + 1)?;
            return Some(pos + 2);
        }
        if (b & 0xc0) != 0 {
            return None;
        }
        pos = pos.checked_add(1 + b as usize)?;
        jumps += 1;
        if jumps > 128 {
            return None;
        }
    }
}

fn parse_dns_wire_answers(packet: &[u8]) -> Vec<IpAddr> {
    if packet.len() < 12 || (packet[3] & 0x0f) != 0 {
        return Vec::new();
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qdcount {
        let Some(next) = skip_dns_name(packet, pos) else { return Vec::new() };
        if next + 4 > packet.len() {
            return Vec::new();
        }
        pos = next + 4;
    }
    let mut out = Vec::new();
    for _ in 0..ancount {
        let Some(next) = skip_dns_name(packet, pos) else { break };
        if next + 10 > packet.len() {
            break;
        }
        let rtype = u16::from_be_bytes([packet[next], packet[next + 1]]);
        let rclass = u16::from_be_bytes([packet[next + 2], packet[next + 3]]);
        let rdlen = u16::from_be_bytes([packet[next + 8], packet[next + 9]]) as usize;
        let rdata_start = next + 10;
        let Some(rdata_end) = rdata_start.checked_add(rdlen) else { break };
        if rdata_end > packet.len() {
            break;
        }
        if rclass == 1 {
            if rtype == 1 && rdlen == 4 {
                let ip = IpAddr::V4(Ipv4Addr::new(
                    packet[rdata_start],
                    packet[rdata_start + 1],
                    packet[rdata_start + 2],
                    packet[rdata_start + 3],
                ));
                if is_public_ip(ip) && !out.contains(&ip) {
                    out.push(ip);
                }
            } else if rtype == 28 && rdlen == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&packet[rdata_start..rdata_end]);
                let ip = IpAddr::V6(Ipv6Addr::from(octets));
                if is_public_ip(ip) && !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
        pos = rdata_end;
    }
    out
}

pub(crate) fn url_encode_component(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
    out
}

pub(crate) fn parse_http_date_unix(value: &str) -> Option<i64> {
    let s = value.trim();
    let after_comma = match s.split_once(',') {
        Some((_, rest)) => rest.trim(),
        None => {
            let mut parts = s.split_whitespace();
            let _wday = parts.next()?;
            let mon = month_from_abbrev(parts.next()?)?;
            let day = parts.next()?.parse::<u32>().ok()?;
            let hms = parts.next()?;
            let year = parts.next()?.parse::<i32>().ok()?;
            let (hh, mm, ss) = parse_hms(hms)?;
            return unix_from_ymdhms(year, mon, day, hh, mm, ss);
        }
    };
    let mut parts = after_comma.split_whitespace();
    let first = parts.next()?;
    if let Some((d_str, rest_dmy)) = first.split_once('-') {
        let (mon_str, yr_str) = rest_dmy.split_once('-')?;
        let day = d_str.parse::<u32>().ok()?;
        let mon = month_from_abbrev(mon_str)?;
        let yr_raw = yr_str.parse::<i32>().ok()?;
        let year = if yr_raw < 70 {
            2000 + yr_raw
        } else if yr_raw < 100 {
            1900 + yr_raw
        } else {
            yr_raw
        };
        let (hh, mm, ss) = parse_hms(parts.next()?)?;
        let tz = parts.next()?;
        if tz != "GMT" && tz != "UTC" {
            return None;
        }
        return unix_from_ymdhms(year, mon, day, hh, mm, ss);
    }
    let day = first.parse::<u32>().ok()?;
    let mon = month_from_abbrev(parts.next()?)?;
    let year = parts.next()?.parse::<i32>().ok()?;
    let (hh, mm, ss) = parse_hms(parts.next()?)?;
    let tz = parts.next()?;
    if tz != "GMT" && tz != "UTC" {
        return None;
    }
    unix_from_ymdhms(year, mon, day, hh, mm, ss)
}

fn month_from_abbrev(mon: &str) -> Option<u32> {
    match mon {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

fn parse_hms(s: &str) -> Option<(u32, u32, u32)> {
    let mut it = s.split(':');
    let hh = it.next()?.parse::<u32>().ok()?;
    let mm = it.next()?.parse::<u32>().ok()?;
    let ss = it.next()?.parse::<u32>().ok()?;
    if it.next().is_some() || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    Some((hh, mm, ss.min(59)))
}

pub(crate) fn parse_rfc3339_unix(value: &str) -> Option<i64> {
    let s = value.trim();
    if s.len() < 19 {
        return None;
    }
    let b = s.as_bytes();
    if b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let year = s.get(0..4)?.parse::<i32>().ok()?;
    let month = s.get(5..7)?.parse::<u32>().ok()?;
    let day = s.get(8..10)?.parse::<u32>().ok()?;
    let rest = s.get(11..)?;
    let tz_pos = rest
        .bytes()
        .position(|c| matches!(c, b'Z' | b'z' | b'+' | b'-'));
    let (time_part, tz_offset_secs) = match tz_pos {
        Some(idx) => {
            let tz = &rest[idx..];
            let offset = if tz.eq_ignore_ascii_case("Z") {
                0i64
            } else {
                let sign = if tz.starts_with('-') { -1i64 } else { 1i64 };
                let off = &tz[1..];
                let (oh, om) = match off.split_once(':') {
                    Some((h, m)) => (h.parse::<i64>().ok()?, m.parse::<i64>().ok()?),
                    None if off.len() == 4 => (
                        off[0..2].parse::<i64>().ok()?,
                        off[2..4].parse::<i64>().ok()?,
                    ),
                    None => return None,
                };
                if oh > 23 || om > 59 {
                    return None;
                }
                sign * (oh * 3600 + om * 60)
            };
            (&rest[..idx], offset)
        }
        None => (rest, 0i64),
    };
    let hms_str = match time_part.split_once('.') {
        Some((hms, frac)) => {
            if frac.is_empty() || !frac.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            hms
        }
        None => time_part,
    };
    let (hh, mm, ss) = parse_hms(hms_str)?;
    let base = unix_from_ymdhms(year, month, day, hh, mm, ss)?;
    Some(base - tz_offset_secs)
}

fn unix_from_ymdhms(year: i32, month: u32, day: u32, hh: u32, mm: u32, ss: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let (cy, cm, cd) = civil_from_days(days);
    if cy != year || cm != month || cd != day {
        return None;
    }
    Some(days * 86_400 + (hh as i64) * 3600 + (mm as i64) * 60 + (ss as i64))
}

pub(crate) fn format_rfc3339_utc(unix_secs: i64) -> String {
    let days = unix_secs.div_euclid(86_400);
    let secs = unix_secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = secs / 3600;
    let mm = (secs % 3600) / 60;
    let ss = secs % 60;
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let y = year as i64 - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64;
    let m = month as u64;
    let d = day as u64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + (doe as i64) - 719_468
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

pub(crate) fn base64_encode_std(input: &[u8]) -> String {
    base64_encode_with(input, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", true)
}

pub(crate) fn base64_encode_url_nopad(input: &[u8]) -> String {
    base64_encode_with(input, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", false)
}

fn base64_encode_with(input: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0usize;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(alphabet[((n >> 18) & 0x3f) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3f) as usize] as char);
        out.push(alphabet[((n >> 6) & 0x3f) as usize] as char);
        out.push(alphabet[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out.push(alphabet[((n >> 18) & 0x3f) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3f) as usize] as char);
        if pad {
            out.push_str("==");
        }
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(alphabet[((n >> 18) & 0x3f) as usize] as char);
        out.push(alphabet[((n >> 12) & 0x3f) as usize] as char);
        out.push(alphabet[((n >> 6) & 0x3f) as usize] as char);
        if pad {
            out.push('=');
        }
    }
    out
}

pub(crate) fn base64_decode_any(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity((input.len() / 4) * 3);
    let mut buf = 0u32;
    let mut bits = 0u32;
    let mut seen_pad = false;
    for b in input.bytes() {
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
            continue;
        }
        if b == b'=' {
            seen_pad = true;
            continue;
        }
        if seen_pad {
            return None;
        }
        let val = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    if bits >= 6 || (bits > 0 && (buf & ((1 << bits) - 1)) != 0) {
        return None;
    }
    Some(out)
}
