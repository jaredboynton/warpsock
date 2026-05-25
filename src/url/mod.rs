//! RFC 3986 URL helper backed by [`http::Uri`].

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use http::Uri;

/// URL parse failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    message: String,
}

impl ParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ParseError {}

/// Parsed authority host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Domain(domain) => f.write_str(domain),
            Host::Ipv4(addr) => write!(f, "{addr}"),
            Host::Ipv6(addr) => write!(f, "{addr}"),
        }
    }
}

/// Absolute URL with normalized string storage.
#[derive(Clone, PartialEq, Eq)]
pub struct Url {
    inner: String,
    uri: Uri,
    host_str: Option<String>,
}

impl fmt::Debug for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Url").field(&self.inner).finish()
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Url {
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let without_fragment = input.split('#').next().unwrap_or(input);
        if let Some(authority) = extract_authority(without_fragment) {
            validate_authority(authority)?;
        }
        let uri = Uri::try_from(without_fragment)
            .map_err(|err| ParseError::new(format!("invalid URI: {err}")))?;
        if uri.scheme().is_none() {
            return Err(ParseError::new("relative URL without a base"));
        }
        let host_str = uri
            .authority()
            .and_then(|authority| host_str_from_authority(authority.as_str()).ok());
        Ok(Self {
            inner: without_fragment.to_string(),
            uri,
            host_str,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.inner
    }

    pub fn scheme(&self) -> &str {
        self.uri.scheme_str().unwrap_or("")
    }

    pub fn path(&self) -> &str {
        self.uri.path()
    }

    pub fn query(&self) -> Option<&str> {
        self.uri.query()
    }

    pub fn port(&self) -> Option<u16> {
        self.uri.port_u16()
    }

    pub fn port_or_known_default(&self) -> Option<u16> {
        self.port().or_else(|| known_default_port(self.scheme()))
    }

    pub fn host(&self) -> Option<Host> {
        let authority = self.uri.authority()?.as_str();
        parse_host_port(authority).ok().map(|(host, _)| host)
    }

    pub fn host_str(&self) -> Option<&str> {
        self.host_str.as_deref()
    }

    pub fn set_scheme(&mut self, scheme: &str) -> Result<(), ParseError> {
        if scheme.is_empty() || !scheme.bytes().all(is_scheme_byte) {
            return Err(ParseError::new("invalid URL scheme"));
        }
        let authority = self
            .uri
            .authority()
            .map(|a| a.as_str())
            .unwrap_or("")
            .to_string();
        let path_and_query = path_and_query_of(&self.uri);
        *self = Self::assemble(scheme, &authority, &path_and_query)?;
        Ok(())
    }

    pub fn set_port(&mut self, port: Option<u16>) -> Result<(), ParseError> {
        let scheme = self.scheme();
        let authority = format_authority_host(self.host(), port)?;
        let path_and_query = path_and_query_of(&self.uri);
        *self = Self::assemble(scheme, &authority, &path_and_query)?;
        Ok(())
    }

    pub fn set_host(&mut self, host: Option<&str>) -> Result<(), ParseError> {
        let host = host.ok_or_else(|| ParseError::new("missing URL host"))?;
        validate_authority(host)?;
        let scheme = self.scheme();
        let host = parse_host_label(host)?;
        let authority = format_authority_host(Some(host), self.port())?;
        let path_and_query = path_and_query_of(&self.uri);
        *self = Self::assemble(scheme, &authority, &path_and_query)?;
        Ok(())
    }

    pub fn set_query(&mut self, query: Option<&str>) -> Result<(), ParseError> {
        let scheme = self.scheme();
        let authority = self
            .uri
            .authority()
            .map(|a| a.as_str())
            .unwrap_or("")
            .to_string();
        let mut path_and_query = self.path().to_string();
        match query {
            Some(q) => {
                path_and_query.push('?');
                path_and_query.push_str(q);
            }
            None => {}
        }
        *self = Self::assemble(scheme, &authority, &path_and_query)?;
        Ok(())
    }

    /// RFC 3986 section 5.2 reference resolution against this base URL.
    pub fn join(&self, reference: &str) -> Result<Self, ParseError> {
        let reference = reference.split('#').next().unwrap_or(reference);
        if scheme_end(reference).is_some() {
            return Self::parse(reference);
        }

        let base_scheme = self.scheme();
        let base_authority = self.uri.authority().map(|a| a.as_str()).unwrap_or("");
        let base_path = self.path();
        let base_query = self.query();

        if reference.starts_with("//") {
            let rest = &reference[2..];
            let (authority, path, query) = split_authority_reference(rest)?;
            let path = normalize_path(&path);
            return Self::assemble_with_query(base_scheme, &authority, &path, query.as_deref());
        }

        if reference.starts_with('/') {
            let (path, query) = split_path_query(reference);
            let path = normalize_path(path);
            return Self::assemble_with_query(base_scheme, base_authority, &path, query.as_deref());
        }

        if reference.starts_with('?') {
            return Self::assemble_with_query(
                base_scheme,
                base_authority,
                base_path,
                Some(&reference[1..]),
            );
        }

        if reference.is_empty() {
            return Self::assemble_with_query(base_scheme, base_authority, base_path, base_query);
        }

        let (ref_path, ref_query) = split_path_query(reference);
        let merged_path = normalize_path(&merge_paths(base_path, ref_path));
        Self::assemble_with_query(
            base_scheme,
            base_authority,
            &merged_path,
            ref_query.as_deref(),
        )
    }

    fn assemble(scheme: &str, authority: &str, path_and_query: &str) -> Result<Self, ParseError> {
        let (path, query) = split_path_query(path_and_query);
        Self::assemble_with_query(scheme, authority, path, query.as_deref())
    }

    fn assemble_with_query(
        scheme: &str,
        authority: &str,
        path: &str,
        query: Option<&str>,
    ) -> Result<Self, ParseError> {
        let path = if path.is_empty() { "/" } else { path };
        let mut inner = format!("{scheme}://");
        if !authority.is_empty() {
            inner.push_str(authority);
        }
        inner.push_str(path);
        if let Some(query) = query {
            inner.push('?');
            inner.push_str(query);
        }
        Self::parse(&inner)
    }
}

fn path_and_query_of(uri: &Uri) -> String {
    match uri.path_and_query() {
        Some(pq) => pq.as_str().to_string(),
        None => "/".to_string(),
    }
}

fn known_default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        _ => None,
    }
}

fn is_scheme_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
}

fn scheme_end(input: &str) -> Option<usize> {
    if !input
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
    {
        return None;
    }
    let mut end = 0;
    for (idx, ch) in input.char_indices().skip(1) {
        if is_scheme_byte(ch as u8) {
            end = idx + ch.len_utf8();
        } else if ch == ':' {
            return Some(end);
        } else {
            return None;
        }
    }
    None
}

fn extract_authority(input: &str) -> Option<&str> {
    let scheme_sep = input.find("://")?;
    let after_scheme = &input[scheme_sep + 3..];
    after_scheme
        .split(&['/', '?'][..])
        .next()
        .filter(|part| !part.is_empty())
}

fn validate_authority(authority: &str) -> Result<(), ParseError> {
    if authority.contains('@') {
        return Err(ParseError::new(
            "userinfo in URL authority is not supported",
        ));
    }
    if !authority.is_ascii() {
        return Err(ParseError::new("non-ASCII host requires explicit punycode"));
    }
    Ok(())
}

fn host_str_from_authority(authority: &str) -> Result<String, ParseError> {
    let (host, _) = parse_host_port(authority)?;
    Ok(match host {
        Host::Domain(domain) => domain,
        Host::Ipv4(addr) => addr.to_string(),
        Host::Ipv6(addr) => addr.to_string(),
    })
}

fn parse_host_port(authority: &str) -> Result<(Host, Option<u16>), ParseError> {
    if authority.is_empty() {
        return Err(ParseError::new("missing URL host"));
    }

    if authority.starts_with('[') {
        let end = authority
            .find(']')
            .ok_or_else(|| ParseError::new("invalid IPv6 authority"))?;
        let ip = Ipv6Addr::from_str(&authority[1..end])
            .map_err(|_| ParseError::new("invalid IPv6 address"))?;
        let port = parse_port_suffix(&authority[end + 1..])?;
        return Ok((Host::Ipv6(ip), port));
    }

    if let Some((host, port)) = authority.rsplit_once(':') {
        if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            let port = port
                .parse::<u16>()
                .map_err(|_| ParseError::new("invalid port"))?;
            return Ok((parse_host_label(host)?, Some(port)));
        }
    }

    Ok((parse_host_label(authority)?, None))
}

fn parse_host_label(host: &str) -> Result<Host, ParseError> {
    if let Ok(ip) = Ipv4Addr::from_str(host) {
        return Ok(Host::Ipv4(ip));
    }
    Ok(Host::Domain(host.to_ascii_lowercase()))
}

fn parse_port_suffix(suffix: &str) -> Result<Option<u16>, ParseError> {
    if suffix.is_empty() {
        return Ok(None);
    }
    if !suffix.starts_with(':') {
        return Err(ParseError::new("invalid port suffix"));
    }
    suffix[1..]
        .parse::<u16>()
        .map(Some)
        .map_err(|_| ParseError::new("invalid port"))
}

fn format_authority_host(host: Option<Host>, port: Option<u16>) -> Result<String, ParseError> {
    let host = host.ok_or_else(|| ParseError::new("missing URL host"))?;
    let mut authority = match host {
        Host::Domain(domain) => domain,
        Host::Ipv4(addr) => addr.to_string(),
        Host::Ipv6(addr) => format!("[{addr}]"),
    };
    if let Some(port) = port {
        authority.push(':');
        authority.push_str(&port.to_string());
    }
    Ok(authority)
}

fn split_path_query(input: &str) -> (&str, Option<String>) {
    match input.split_once('?') {
        Some((path, query)) => (path, Some(query.to_string())),
        None => (input, None),
    }
}

fn split_authority_reference(input: &str) -> Result<(String, String, Option<String>), ParseError> {
    let authority_end = input
        .find('/')
        .or_else(|| input.find('?'))
        .unwrap_or(input.len());
    let authority = &input[..authority_end];
    let rest = &input[authority_end..];

    if authority.is_empty() {
        return Err(ParseError::new("missing authority in reference"));
    }

    let (path, query) = if rest.is_empty() {
        ("/".to_string(), None)
    } else if rest.starts_with('?') {
        ("/".to_string(), Some(rest[1..].to_string()))
    } else {
        let (path, query) = split_path_query(&rest[1..]);
        let path = if path.is_empty() {
            "/".to_string()
        } else {
            format!("/{path}")
        };
        (path, query)
    };

    Ok((authority.to_string(), path, query))
}

fn merge_paths(base_path: &str, reference_path: &str) -> String {
    let prefix = if let Some(idx) = base_path.rfind('/') {
        &base_path[..=idx]
    } else {
        ""
    };
    format!("{prefix}{reference_path}")
}

fn normalize_path(path: &str) -> String {
    let (path_only, query) = split_path_query(path);
    let normalized = remove_dot_segments(path_only);
    match query {
        Some(query) => format!("{normalized}?{query}"),
        None => normalized,
    }
}

fn remove_dot_segments(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut output: Vec<&str> = Vec::new();

    for segment in path.split('/') {
        match segment {
            "" | "." => continue,
            ".." => {
                if !output.is_empty() {
                    output.pop();
                }
            }
            _ => output.push(segment),
        }
    }

    if absolute {
        if output.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", output.join("/"))
        }
    } else if output.is_empty() {
        String::new()
    } else {
        output.join("/")
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn rejects_non_ascii_authority() {
        let err = Url::parse("https://exämple.com/").unwrap_err();
        assert!(err.to_string().contains("non-ASCII"));
    }

    #[test]
    fn rejects_userinfo() {
        let err = Url::parse("http://user:pass@host/").unwrap_err();
        assert!(err.to_string().contains("userinfo"));
    }
}
