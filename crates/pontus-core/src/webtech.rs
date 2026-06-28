//! HTTP technology fingerprinting (F-017): Wappalyzer-style stack identification
//! from response headers and markup.
//!
//! Clean-room (C-001): the signature set below is written from first-principles
//! and public protocol/product knowledge — it is **not** derived from
//! Wappalyzer's dataset or any other fingerprint database. It reuses the existing
//! `ureq` client (which already speaks HTTPS for the intelligence feeds), so no
//! new HTTP dependency is added.
//!
//! Detection draws on three evidence sources: response headers (`Server`,
//! `X-Powered-By`, `Set-Cookie` names, CDN markers), the `<meta name="generator">`
//! tag, and tell-tale paths/scripts in the body (`/wp-content/`, `jquery-3.x.js`).

use crate::error::{Error, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::time::Duration;

/// What kind of technology a finding is. The serde names (kebab-case) match
/// [`Category::as_str`], so a corpus file writes `"js-library"`, `"cms"`, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Server,
    Language,
    Framework,
    Cms,
    JsLibrary,
    Cdn,
    Analytics,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Server => "server",
            Category::Language => "language",
            Category::Framework => "framework",
            Category::Cms => "cms",
            Category::JsLibrary => "js-library",
            Category::Cdn => "cdn",
            Category::Analytics => "analytics",
        }
    }
}

/// One identified technology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tech {
    pub name: String,
    pub version: Option<String>,
    pub category: Category,
    /// Where it was found, e.g. `Server header` or `meta generator`.
    pub evidence: String,
}

/// The result of fingerprinting one URL.
#[derive(Debug, Clone)]
pub struct WebFingerprint {
    pub url: String,
    pub status: u16,
    pub techs: Vec<Tech>,
}

/// The HTTP signals we extract before consuming the response body.
struct Response {
    status: u16,
    /// Lower-cased header name → value (last wins; fine for our markers).
    headers: BTreeMap<String, String>,
    /// All `Set-Cookie` values (cookies are multi-valued).
    cookies: Vec<String>,
    body: String,
}

/// Fetch `url` and identify the technologies behind it against `corpus` (F-017).
pub fn fingerprint(url: &str, corpus: &WebCorpus, timeout: Duration) -> Result<WebFingerprint> {
    let resp = fetch(url, timeout)?;
    let mut techs = Vec::new();
    detect_from_headers(&resp, &corpus.headers, &mut techs);
    detect_from_cookies(&resp, &corpus.cookies, &mut techs);
    detect_from_body(&resp.body, &corpus.body, &corpus.scripts, &mut techs);
    dedup(&mut techs);
    Ok(WebFingerprint { url: url.to_string(), status: resp.status, techs })
}

fn fetch(url: &str, timeout: Duration) -> Result<Response> {
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    let resp = agent.get(url).call().map_err(|e| Error::Http(e.to_string()))?;
    let status = resp.status();
    let mut headers = BTreeMap::new();
    for name in resp.headers_names() {
        if let Some(v) = resp.header(&name) {
            headers.insert(name.to_lowercase(), v.to_string());
        }
    }
    let cookies = resp.all("set-cookie").iter().map(|s| s.to_string()).collect();
    // Cap the body so a huge page can't blow memory; the head holds the markers.
    let body = resp.into_string().map_err(|e| Error::Http(e.to_string()))?;
    let body = body.chars().take(512 * 1024).collect();
    Ok(Response { status, headers, cookies, body })
}

// ---- header detection ------------------------------------------------------

/// `Set-Cookie` name → (technology, category). The session-cookie name a stack
/// sets is a strong, public tell.
/// A header-based signature: when `header` is present and its value contains
/// `needle` (empty = presence alone), attribute `name`/`category`.
#[derive(Debug, Clone, Deserialize)]
pub struct HeaderRule {
    pub header: String,
    #[serde(default)]
    pub needle: String,
    pub name: String,
    pub category: Category,
}

/// A `Set-Cookie`-name / body substring → technology signature.
#[derive(Debug, Clone, Deserialize)]
pub struct MarkerRule {
    pub needle: String,
    pub name: String,
    pub category: Category,
}

/// A JavaScript library matched by a script-src token, with version extraction.
#[derive(Debug, Clone, Deserialize)]
pub struct ScriptRule {
    pub needle: String,
    pub name: String,
}

/// The web-tech signature set: built-in clean-room defaults, extensible by a user
/// JSON file at runtime (mirrors `OsCorpus`, so coverage grows without a rebuild —
/// IMP-011, C-001). The `Server` header, `<meta generator>` and `X-Powered-By`
/// version parsing remain in code; these lists are the data that drives the rest.
#[derive(Debug, Clone, Deserialize)]
pub struct WebCorpus {
    #[serde(default)]
    pub headers: Vec<HeaderRule>,
    #[serde(default)]
    pub cookies: Vec<MarkerRule>,
    #[serde(default)]
    pub body: Vec<MarkerRule>,
    #[serde(default)]
    pub scripts: Vec<ScriptRule>,
}

impl WebCorpus {
    /// The built-in clean-room signature set.
    pub fn builtin() -> Self {
        let header = |h: &str, n: &str, t: &str, c: Category| HeaderRule {
            header: h.to_string(),
            needle: n.to_string(),
            name: t.to_string(),
            category: c,
        };
        let marker = |needle: &str, name: &str, c: Category| MarkerRule {
            needle: needle.to_string(),
            name: name.to_string(),
            category: c,
        };
        let script = |needle: &str, name: &str| ScriptRule {
            needle: needle.to_string(),
            name: name.to_string(),
        };
        WebCorpus {
            headers: vec![
                header("x-drupal-cache", "", "Drupal", Category::Cms),
                header("x-drupal-dynamic-cache", "", "Drupal", Category::Cms),
                header("x-generator", "drupal", "Drupal", Category::Cms),
                header("x-powered-by", "express", "Express", Category::Framework),
                header("x-powered-by", "next.js", "Next.js", Category::Framework),
                header("x-powered-by", "asp.net", "ASP.NET", Category::Framework),
                header("x-aspnet-version", "", "ASP.NET", Category::Framework),
                header("cf-ray", "", "Cloudflare", Category::Cdn),
                header("x-served-by", "", "Fastly", Category::Cdn),
                header("x-amz-cf-id", "", "Amazon CloudFront", Category::Cdn),
                header("x-shopify-stage", "", "Shopify", Category::Cms),
            ],
            cookies: vec![
                marker("phpsessid", "PHP", Category::Language),
                marker("jsessionid", "Java", Category::Language),
                marker("asp.net_sessionid", "ASP.NET", Category::Framework),
                marker("aspsessionid", "ASP", Category::Framework),
                marker("laravel_session", "Laravel", Category::Framework),
                marker("ci_session", "CodeIgniter", Category::Framework),
                marker("csrftoken", "Django", Category::Framework),
                marker("django", "Django", Category::Framework),
                marker("_rails", "Ruby on Rails", Category::Framework),
                marker("wordpress_", "WordPress", Category::Cms),
                marker("wp-settings", "WordPress", Category::Cms),
            ],
            body: vec![
                marker("/wp-content/", "WordPress", Category::Cms),
                marker("/wp-includes/", "WordPress", Category::Cms),
                marker("/wp-json/", "WordPress", Category::Cms),
                marker("drupal.settings", "Drupal", Category::Cms),
                marker("/sites/default/files", "Drupal", Category::Cms),
                marker("/media/jui/", "Joomla", Category::Cms),
                marker("com_content", "Joomla", Category::Cms),
                marker("/_next/static/", "Next.js", Category::Framework),
                marker("__nuxt", "Nuxt.js", Category::Framework),
                marker("ng-version", "Angular", Category::JsLibrary),
                marker("data-reactroot", "React", Category::JsLibrary),
                marker("csrf-param", "Ruby on Rails", Category::Framework),
                marker("google-analytics.com/analytics.js", "Google Analytics", Category::Analytics),
                marker("googletagmanager.com/gtag", "Google Analytics", Category::Analytics),
            ],
            scripts: vec![
                script("jquery", "jQuery"),
                script("bootstrap", "Bootstrap"),
                script("vue", "Vue.js"),
                script("react", "React"),
                script("angular", "Angular"),
            ],
        }
    }

    /// Parse a corpus from JSON (any of the four lists may be present).
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| Error::Http(e.to_string()))
    }

    /// Append another corpus's rules (user rules layer over the built-ins).
    pub fn extend(&mut self, other: WebCorpus) {
        self.headers.extend(other.headers);
        self.cookies.extend(other.cookies);
        self.body.extend(other.body);
        self.scripts.extend(other.scripts);
    }

    /// The built-in corpus with the JSON file at `path` layered on top.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let mut corpus = Self::builtin();
        corpus.extend(Self::from_json(&std::fs::read_to_string(path)?)?);
        Ok(corpus)
    }
}

fn detect_from_headers(resp: &Response, headers: &[HeaderRule], out: &mut Vec<Tech>) {
    // Server header: "nginx/1.18.0", "Apache/2.4.41", "Microsoft-IIS/10.0".
    if let Some(server) = resp.headers.get("server") {
        let (name, version) = split_name_version(server);
        let canon = canonical_server(&name);
        if let Some(canon) = canon {
            out.push(Tech {
                name: canon.to_string(),
                version,
                category: Category::Server,
                evidence: "Server header".to_string(),
            });
        } else if !name.is_empty() {
            out.push(Tech { name, version, category: Category::Server, evidence: "Server header".to_string() });
        }
    }
    // X-Powered-By can carry a language with a version, e.g. "PHP/8.1.2".
    if let Some(xpb) = resp.headers.get("x-powered-by") {
        if xpb.to_lowercase().starts_with("php") {
            let (_, version) = split_name_version(xpb);
            out.push(Tech { name: "PHP".to_string(), version, category: Category::Language, evidence: "X-Powered-By".to_string() });
        }
    }
    for rule in headers {
        if let Some(value) = resp.headers.get(&rule.header) {
            if rule.needle.is_empty() || value.to_lowercase().contains(&rule.needle) {
                let version = (rule.header == "x-aspnet-version").then(|| value.clone());
                out.push(Tech {
                    name: rule.name.clone(),
                    version,
                    category: rule.category,
                    evidence: format!("{} header", rule.header),
                });
            }
        }
    }
}

fn detect_from_cookies(resp: &Response, cookies: &[MarkerRule], out: &mut Vec<Tech>) {
    for cookie in &resp.cookies {
        // The cookie's name is everything before '='.
        let name = cookie.split('=').next().unwrap_or("").trim().to_lowercase();
        for rule in cookies {
            if name.contains(&rule.needle) {
                out.push(Tech {
                    name: rule.name.clone(),
                    version: None,
                    category: rule.category,
                    evidence: "Set-Cookie".to_string(),
                });
            }
        }
    }
}

// ---- body detection --------------------------------------------------------

fn detect_from_body(body: &str, markers: &[MarkerRule], scripts: &[ScriptRule], out: &mut Vec<Tech>) {
    let lower = body.to_lowercase();

    // <meta name="generator" content="WordPress 6.4.2"> — name + version. Read
    // from the original body so the product casing ("WordPress") is preserved.
    if let Some(content) = meta_generator(body) {
        let (name, version) = split_name_version_spaced(&content);
        let cat = if name.eq_ignore_ascii_case("wordpress")
            || name.eq_ignore_ascii_case("drupal")
            || name.eq_ignore_ascii_case("joomla")
            || name.eq_ignore_ascii_case("ghost")
        {
            Category::Cms
        } else {
            Category::Framework
        };
        if !name.is_empty() {
            out.push(Tech { name: titlecase(&name), version, category: cat, evidence: "meta generator".to_string() });
        }
    }

    for rule in markers {
        if lower.contains(&rule.needle) {
            out.push(Tech {
                name: rule.name.clone(),
                version: None,
                category: rule.category,
                evidence: "page markup".to_string(),
            });
        }
    }

    // JavaScript libraries from script filenames, with a version where present.
    for rule in scripts {
        if let Some(version) = script_version(&lower, &rule.needle) {
            out.push(Tech {
                name: rule.name.clone(),
                version,
                category: Category::JsLibrary,
                evidence: "script src".to_string(),
            });
        }
    }
}

// ---- parsing helpers -------------------------------------------------------

/// Split "nginx/1.18.0" into ("nginx", Some("1.18.0")).
fn split_name_version(s: &str) -> (String, Option<String>) {
    match s.split_once('/') {
        Some((name, rest)) => (name.trim().to_string(), version_prefix(rest)),
        None => (s.trim().to_string(), None),
    }
}

/// Split "WordPress 6.4.2" into ("WordPress", Some("6.4.2")).
fn split_name_version_spaced(s: &str) -> (String, Option<String>) {
    let s = s.trim();
    match s.split_once(' ') {
        Some((name, rest)) => (name.trim().to_string(), version_prefix(rest.trim())),
        None => (s.to_string(), None),
    }
}

/// Take the leading version run (digits and dots) from `s`, if any.
fn version_prefix(s: &str) -> Option<String> {
    let v: String = s.trim().chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    let v = v.trim_matches('.');
    (!v.is_empty() && v.contains(|c: char| c.is_ascii_digit())).then(|| v.to_string())
}

/// Canonicalise common Server-header product names.
fn canonical_server(name: &str) -> Option<&'static str> {
    match name.to_lowercase().as_str() {
        "nginx" => Some("nginx"),
        "apache" => Some("Apache"),
        "microsoft-iis" => Some("Microsoft IIS"),
        "litespeed" => Some("LiteSpeed"),
        "caddy" => Some("Caddy"),
        "lighttpd" => Some("lighttpd"),
        "openresty" => Some("OpenResty"),
        "cloudflare" => Some("Cloudflare"),
        _ => None,
    }
}

/// Case-insensitive byte-index search for an ASCII-lowercase `needle` in `hay`,
/// returning the offset into the *original* string (so casing is preserved).
fn find_ci(hay: &str, needle: &str) -> Option<usize> {
    let (h, n) = (hay.as_bytes(), needle.as_bytes());
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    (0..=h.len() - n.len()).find(|&i| h[i..i + n.len()].iter().zip(n).all(|(a, b)| a.to_ascii_lowercase() == *b))
}

/// Extract the content of a `<meta name="generator" content="…">` tag, preserving
/// the original casing of the value (e.g. "WordPress 6.4.2").
fn meta_generator(body: &str) -> Option<String> {
    let i = find_ci(body, "name=\"generator\"").or_else(|| find_ci(body, "name='generator'"))?;
    let rest = &body[i..];
    let c = find_ci(rest, "content=")?;
    let after = &rest[c + "content=".len()..];
    let quote = after.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let inner = &after[1..];
    let end = inner.find(quote)?;
    Some(inner[..end].to_string())
}

/// Find a version next to a script name, e.g. "jquery-3.6.0.min.js" or
/// "jquery/3.6.0/" → Some("3.6.0"); returns Some(None) presence without version.
fn script_version(lower_body: &str, lib: &str) -> Option<Option<String>> {
    let i = lower_body.find(lib)?;
    let after = &lower_body[i + lib.len()..];
    // Skip one separator (- _ / . @ or space) then read a version run.
    let trimmed = after.trim_start_matches(['-', '_', '/', '.', '@', ' ', 'v']);
    Some(version_prefix(trimmed))
}

fn titlecase(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

/// Drop duplicate `(name)` findings, preferring the entry that carries a version.
fn dedup(techs: &mut Vec<Tech>) {
    techs.sort_by(|a, b| {
        a.name.to_lowercase().cmp(&b.name.to_lowercase()).then(b.version.is_some().cmp(&a.version.is_some()))
    });
    techs.dedup_by(|a, b| a.name.eq_ignore_ascii_case(&b.name));
    techs.sort_by_key(|t| t.category as u8);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(headers: &[(&str, &str)], cookies: &[&str], body: &str) -> Response {
        Response {
            status: 200,
            headers: headers.iter().map(|(k, v)| (k.to_lowercase(), v.to_string())).collect(),
            cookies: cookies.iter().map(|s| s.to_string()).collect(),
            body: body.to_string(),
        }
    }

    fn run(r: &Response) -> Vec<Tech> {
        let c = WebCorpus::builtin();
        let mut t = Vec::new();
        detect_from_headers(r, &c.headers, &mut t);
        detect_from_cookies(r, &c.cookies, &mut t);
        detect_from_body(&r.body, &c.body, &c.scripts, &mut t);
        dedup(&mut t);
        t
    }

    fn find<'a>(t: &'a [Tech], name: &str) -> Option<&'a Tech> {
        t.iter().find(|x| x.name.eq_ignore_ascii_case(name))
    }

    #[test]
    fn server_header_name_and_version() {
        let (n, v) = split_name_version("nginx/1.18.0");
        assert_eq!(n, "nginx");
        assert_eq!(v.as_deref(), Some("1.18.0"));
        let t = run(&resp(&[("Server", "nginx/1.18.0")], &[], ""));
        let s = find(&t, "nginx").unwrap();
        assert_eq!(s.category, Category::Server);
        assert_eq!(s.version.as_deref(), Some("1.18.0"));
    }

    #[test]
    fn powered_by_php_and_session_cookie() {
        let t = run(&resp(&[("X-Powered-By", "PHP/8.1.2")], &["PHPSESSID=abc; path=/"], ""));
        assert_eq!(find(&t, "PHP").unwrap().version.as_deref(), Some("8.1.2"));
    }

    #[test]
    fn wordpress_from_generator_and_markup() {
        let body = r#"<meta name="generator" content="WordPress 6.4.2" /><link href="/wp-content/themes/x/style.css">"#;
        let t = run(&resp(&[], &[], body));
        let wp = find(&t, "WordPress").unwrap();
        assert_eq!(wp.category, Category::Cms);
        assert_eq!(wp.version.as_deref(), Some("6.4.2"));
        // The generator + two markup markers collapse to one WordPress finding.
        assert_eq!(t.iter().filter(|x| x.name == "WordPress").count(), 1);
    }

    #[test]
    fn jquery_version_from_script_src() {
        let body = r#"<script src="/assets/jquery-3.6.0.min.js"></script>"#;
        let t = run(&resp(&[], &[], body));
        assert_eq!(find(&t, "jQuery").unwrap().version.as_deref(), Some("3.6.0"));
    }

    #[test]
    fn cloudflare_and_drupal_headers() {
        let t = run(&resp(&[("CF-Ray", "abc-LHR"), ("X-Drupal-Cache", "HIT")], &[], ""));
        assert!(find(&t, "Cloudflare").is_some());
        assert!(find(&t, "Drupal").is_some());
    }

    #[test]
    fn nothing_detected_is_empty() {
        assert!(run(&resp(&[], &[], "<html></html>")).is_empty());
    }

    #[test]
    fn user_corpus_layers_over_builtin_without_a_rebuild() {
        let mut c = WebCorpus::builtin();
        c.extend(
            WebCorpus::from_json(
                r#"{ "headers": [{ "header": "x-bespoke", "name": "Bespoke", "category": "framework" }],
                     "body": [{ "needle": "/acme-cms/", "name": "AcmeCMS", "category": "cms" }] }"#,
            )
            .unwrap(),
        );
        let r = resp(&[("X-Bespoke", "1")], &[], "<link href=\"/acme-cms/x.css\">");
        let mut t = Vec::new();
        detect_from_headers(&r, &c.headers, &mut t);
        detect_from_body(&r.body, &c.body, &c.scripts, &mut t);
        assert!(t.iter().any(|x| x.name == "Bespoke"), "user header rule fired");
        assert!(t.iter().any(|x| x.name == "AcmeCMS"), "user body rule fired");
    }
}
