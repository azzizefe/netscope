use std::collections::HashMap;

use serde::Deserialize;

use crate::pqc_handshake::{KemId, PqcHandshakeRecord, SigAlgorithm, TlsVersion};
use crate::pqc_wizard::{Severity, VulnerabilityFinding};

/// A single PQC vulnerability/risk rule loaded from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct PqcRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub condition: String,
    pub severity: String,
    #[serde(default)]
    pub impact: String,
    #[serde(default)]
    pub cvss_vector: Option<String>,
    #[serde(default)]
    pub fix: Option<String>,
    #[serde(default)]
    pub suggestion: Option<String>,
    #[serde(default)]
    pub harvest_now_risk: Option<String>,
}

/// A set of PQC rules loaded from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct PqcRuleSet {
    pub rules: Vec<PqcRule>,
}

impl PqcRuleSet {
    /// Parse rules from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    /// Return the built-in default rule set.
    pub fn default_set() -> Self {
        PqcRuleSet::from_yaml(DEFAULT_RULES_YAML).expect("built-in PQC rules are valid YAML")
    }
}

const DEFAULT_RULES_YAML: &str = r#"
rules:
  - id: "PQC-001"
    name: "Weak PQC Parameters"
    description: "Non-NIST-approved or legacy round-3 parameters in use"
    condition: "pqc_kem IN ['Kyber-512', 'NTRU-HPS-2048-509', 'SIKE-p434']"
    severity: critical
    impact: "These parameter sets are not NIST-standardized or have been broken. Use ML-KEM-768/1024."
    cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    fix: "Upgrade to ML-KEM-768 or ML-KEM-1024."

  - id: "PQC-002"
    name: "Classic-only Key Exchange"
    description: "TLS 1.3 connection uses only ECDH; no PQC KEM offered"
    condition: "pqc_kem == None AND tls_version == '1.3'"
    severity: medium
    impact: "Unprotected against Harvest Now, Decrypt Later (HNDL) attacks."
    suggestion: "Enable at least hybrid ECDH + PQC KEM."
    harvest_now_risk: "Critical if 10+ year data protection is required."

  - id: "PQC-003"
    name: "TLS 1.2 Fallback (No PQC)"
    description: "Fallback to TLS 1.2 which lacks PQC support"
    condition: "tls_version == '1.2' AND prev_connection_had_pqc == true"
    severity: high
    impact: "Possible downgrade attack or misconfigured load balancer."
    suggestion: "Disable TLS 1.2 or add PQC cipher suites to TLS 1.2."

  - id: "PQC-004"
    name: "Weak Classic Signature in Composite Cert"
    description: "Composite hybrid certificate has weak classic signature"
    condition: "is_composite_cert == true AND (cert_sig_hash == 'SHA-1' OR rsa_key_size < 2048)"
    severity: critical
    impact: "Weakest link breaks the chain. PQC signatures are strong but the classic side is weak."
    suggestion: "Use at least RSA-3072 + SHA-384 or ECDSA-P384 + SHA-384 in composite certs."

  - id: "PQC-005"
    name: "Self-Signed PQC Certificate"
    description: "Certificate signed with PQC algorithm is self-signed"
    condition: "is_pqc_signature == true AND cert_chain_length == 1"
    severity: info
    impact: "May be a test/dev environment. Obtain CA-signed PQC certificates for production."
    suggestion: "Request PQC certificates from a trusted CA."

  - id: "PQC-006"
    name: "Excessive ClientHello Bloat"
    description: "PQC KEM offers have inflated the ClientHello beyond 10 KB"
    condition: "client_hello_size > 10240"
    severity: warning
    impact: "TCP fragmentation, MTU issues, memory pressure on embedded devices."
    suggestion: "Limit KEM offers to the strongest 2-3. Remove unnecessary NTRU/SIKE offers."

  - id: "PQC-007"
    name: "Slow PQC Handshake"
    description: "PQC handshake overhead exceeds 100 ms threshold"
    condition: "pqc_overhead_ms > 100"
    severity: warning
    impact: "Poor UX; connection timeout risk on mobile/IoT devices."
    suggestion: "Use faster KEM (Kyber-768, BIKE-L1) or enable session resumption (PSK)."

  - id: "PQC-008"
    name: "0-RTT Early Data + PQC"
    description: "0-RTT early data replayed with PQC key exchange"
    condition: "is_0rtt == true AND pqc_kem != None"
    severity: high
    impact: "0-RTT early data is vulnerable to replay attacks."
    suggestion: "Disable 0-RTT on PQC connections or ensure anti-replay via ClientHello.random."

  - id: "PQC-009"
    name: "PQC Offer Strip Attack Indicator"
    description: "Client offered PQC, server did not accept despite having PQC cert — possible MITM strip"
    condition: "client_hello_has_pqc == true AND server_hello_has_pqc == false AND server_cert_has_pqc == true"
    severity: critical
    impact: "Client offered PQC but server did not select it despite having a PQC cert. Possible MITM strip attack."
    suggestion: "Audit network path. Ensure middleboxes are not filtering TLS extensions."

  - id: "PQC-010"
    name: "Expired PQC Certificate"
    description: "PQC certificate has expired or will expire soon"
    condition: "is_pqc_signature == true AND cert_valid_days_left <= 0"
    severity: high
    impact: "PQC certificate has expired. Fallback to classic signature."
    suggestion: "Configure automatic renewal (ACME PQ) for PQC certificates."
"#;

/// A compiled condition expression that can be evaluated against a record.
#[derive(Debug, Clone)]
enum Expr {
    Eq(String, Value),
    Ne(String, Value),
    Gt(String, i64),
    Lt(String, i64),
    In(String, Vec<Value>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Str(String),
    Num(i64),
    Bool(bool),
    None,
}

/// Context provided during rule evaluation.
pub struct RuleContext<'a> {
    pub record: &'a PqcHandshakeRecord,
    pub prev_connection_had_pqc: bool,
}

impl PqcRule {
    /// Evaluate this rule against the given context.
    /// Returns `Some(VulnerabilityFinding)` if the condition matches.
    pub fn evaluate(&self, ctx: &RuleContext) -> Option<VulnerabilityFinding> {
        let expr = parse_condition(&self.condition).ok()?;
        if !eval_expr(&expr, ctx) {
            return None;
        }
        let sev = parse_severity(&self.severity);
        Some(VulnerabilityFinding {
            severity: sev,
            title: self.name.clone(),
            description: self.description.clone(),
            affected_count: 1,
            cve_ref: None,
            cvss_vector: self.cvss_vector.clone(),
            impact: if self.impact.is_empty() {
                self.suggestion.clone().unwrap_or_default()
            } else {
                self.impact.clone()
            },
            fix: self
                .fix
                .clone()
                .or_else(|| self.suggestion.clone())
                .unwrap_or_default(),
        })
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "warning" => Severity::Medium,
        "info" => Severity::Low,
        _ => Severity::Low,
    }
}

/// Tokenizer for the condition mini-language.
#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    String(String),
    Number(i64),
    Bool(bool),
    None,
    Eq,
    Ne,
    Gt,
    Lt,
    In,
    And,
    Or,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }
        match chars[i] {
            '(' => {
                tokens.push(Token::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                i += 1;
            }
            '[' => {
                tokens.push(Token::LBracket);
                i += 1;
            }
            ']' => {
                tokens.push(Token::RBracket);
                i += 1;
            }
            ',' => {
                tokens.push(Token::Comma);
                i += 1;
            }
            '\'' => {
                let mut s = String::new();
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    s.push(chars[i]);
                    i += 1;
                }
                if i >= chars.len() {
                    return Err("Unterminated string".into());
                }
                i += 1;
                tokens.push(Token::String(s));
            }
            '=' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    tokens.push(Token::Eq);
                    i += 2;
                } else {
                    return Err(format!("Unexpected '=' at position {}", i));
                }
            }
            '!' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    tokens.push(Token::Ne);
                    i += 2;
                } else {
                    return Err(format!("Unexpected '!' at position {}", i));
                }
            }
            '>' => {
                tokens.push(Token::Gt);
                i += 1;
            }
            '<' => {
                tokens.push(Token::Lt);
                i += 1;
            }
            c if c.is_ascii_digit()
                || (c == '-' && i + 1 < chars.len() && chars[i + 1].is_ascii_digit()) =>
            {
                let mut num = String::new();
                num.push(c);
                i += 1;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    num.push(chars[i]);
                    i += 1;
                }
                tokens.push(Token::Number(
                    num.parse()
                        .map_err(|_| format!("Invalid number: {}", num))?,
                ));
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let mut ident = String::new();
                ident.push(c);
                i += 1;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    ident.push(chars[i]);
                    i += 1;
                }
                match ident.as_str() {
                    "AND" => tokens.push(Token::And),
                    "OR" => tokens.push(Token::Or),
                    "IN" => tokens.push(Token::In),
                    "true" => tokens.push(Token::Bool(true)),
                    "false" => tokens.push(Token::Bool(false)),
                    "None" => tokens.push(Token::None),
                    _ => tokens.push(Token::Ident(ident)),
                }
            }
            _ => {
                return Err(format!(
                    "Unexpected character '{}' at position {}",
                    chars[i], i
                ))
            }
        }
    }
    Ok(tokens)
}

/// Recursive descent parser for the condition language.
/// Grammar:
///   expr     = or_expr
///   or_expr  = and_expr ("OR" and_expr)*
///   and_expr = primary ("AND" primary)*
///   primary  = "(" expr ")" | comparison
///   comparison = ident "==" value | ident "!=" value | ident ">" number
///              | ident "<" number | ident "IN" "[" value ("," value)* "]"
fn parse_condition(input: &str) -> Result<Expr, String> {
    let tokens = tokenize(input)?;
    let mut pos = 0;
    let expr = parse_or(&tokens, &mut pos)?;
    if pos != tokens.len() {
        return Err(format!("Trailing tokens after position {}", pos));
    }
    Ok(expr)
}

fn parse_or(tokens: &[Token], pos: &mut usize) -> Result<Expr, String> {
    let mut left = parse_and(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == Token::Or {
        *pos += 1;
        let right = parse_and(tokens, pos)?;
        left = Expr::Or(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_and(tokens: &[Token], pos: &mut usize) -> Result<Expr, String> {
    let mut left = parse_primary(tokens, pos)?;
    while *pos < tokens.len() && tokens[*pos] == Token::And {
        *pos += 1;
        let right = parse_primary(tokens, pos)?;
        left = Expr::And(Box::new(left), Box::new(right));
    }
    Ok(left)
}

fn parse_primary(tokens: &[Token], pos: &mut usize) -> Result<Expr, String> {
    if *pos >= tokens.len() {
        return Err("Unexpected end of expression".into());
    }
    if tokens[*pos] == Token::LParen {
        *pos += 1;
        let expr = parse_or(tokens, pos)?;
        if *pos >= tokens.len() || tokens[*pos] != Token::RParen {
            return Err("Missing closing parenthesis".into());
        }
        *pos += 1;
        return Ok(expr);
    }
    parse_comparison(tokens, pos)
}

fn parse_comparison(tokens: &[Token], pos: &mut usize) -> Result<Expr, String> {
    if *pos >= tokens.len() {
        return Err("Unexpected end of expression".into());
    }
    match &tokens[*pos] {
        Token::Ident(field) => {
            let field = field.clone();
            *pos += 1;
            if *pos >= tokens.len() {
                return Err(format!("Unexpected end after field '{}'", field));
            }
            match &tokens[*pos] {
                Token::Eq => {
                    *pos += 1;
                    let val = parse_value(tokens, pos)?;
                    Ok(Expr::Eq(field, val))
                }
                Token::Ne => {
                    *pos += 1;
                    let val = parse_value(tokens, pos)?;
                    Ok(Expr::Ne(field, val))
                }
                Token::Gt => {
                    *pos += 1;
                    let val = parse_value(tokens, pos)?;
                    match val {
                        Value::Num(n) => Ok(Expr::Gt(field, n)),
                        _ => Err("'>' requires numeric value".into()),
                    }
                }
                Token::Lt => {
                    *pos += 1;
                    let val = parse_value(tokens, pos)?;
                    match val {
                        Value::Num(n) => Ok(Expr::Lt(field, n)),
                        _ => Err("'<' requires numeric value".into()),
                    }
                }
                Token::In => {
                    *pos += 1;
                    if *pos >= tokens.len() || tokens[*pos] != Token::LBracket {
                        return Err("Expected '[' after IN".into());
                    }
                    *pos += 1;
                    let mut values = Vec::new();
                    while *pos < tokens.len() && tokens[*pos] != Token::RBracket {
                        if !values.is_empty() {
                            if tokens[*pos] != Token::Comma {
                                return Err("Expected ',' between list items".into());
                            }
                            *pos += 1;
                        }
                        values.push(parse_value(tokens, pos)?);
                    }
                    if *pos >= tokens.len() {
                        return Err("Unterminated list".into());
                    }
                    *pos += 1;
                    Ok(Expr::In(field, values))
                }
                t => Err(format!(
                    "Unexpected operator {:?} after field '{}'",
                    t, field
                )),
            }
        }
        t => Err(format!("Expected identifier, got {:?}", t)),
    }
}

fn parse_value(tokens: &[Token], pos: &mut usize) -> Result<Value, String> {
    if *pos >= tokens.len() {
        return Err("Unexpected end of expression".into());
    }
    match &tokens[*pos] {
        Token::String(s) => {
            let v = Value::Str(s.clone());
            *pos += 1;
            Ok(v)
        }
        Token::Number(n) => {
            let v = Value::Num(*n);
            *pos += 1;
            Ok(v)
        }
        Token::Bool(b) => {
            let v = Value::Bool(*b);
            *pos += 1;
            Ok(v)
        }
        Token::None => {
            *pos += 1;
            Ok(Value::None)
        }
        t => Err(format!("Expected value, got {:?}", t)),
    }
}

/// Evaluate a compiled expression against the rule context.
fn eval_expr(expr: &Expr, ctx: &RuleContext) -> bool {
    match expr {
        Expr::Eq(field, val) => resolve_field(field, ctx)
            .map(|v| values_equal(&v, val))
            .unwrap_or(false),
        Expr::Ne(field, val) => resolve_field(field, ctx)
            .map(|v| !values_equal(&v, val))
            .unwrap_or(true),
        Expr::Gt(field, n) => resolve_field(field, ctx)
            .and_then(|v| value_as_i64(&v))
            .map(|v| v > *n)
            .unwrap_or(false),
        Expr::Lt(field, n) => resolve_field(field, ctx)
            .and_then(|v| value_as_i64(&v))
            .map(|v| v < *n)
            .unwrap_or(false),
        Expr::In(field, list) => resolve_field(field, ctx)
            .map(|v| list.iter().any(|item| values_equal(&v, item)))
            .unwrap_or(false),
        Expr::And(a, b) => eval_expr(a, ctx) && eval_expr(b, ctx),
        Expr::Or(a, b) => eval_expr(a, ctx) || eval_expr(b, ctx),
    }
}

fn values_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Str(a), Value::Str(b)) => a.eq_ignore_ascii_case(b),
        (Value::Num(a), Value::Num(b)) => a == b,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::None, Value::None) => true,
        _ => false,
    }
}

fn value_as_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Num(n) => Some(*n),
        _ => None,
    }
}

/// Resolve a dotted field name from the rule context.
fn resolve_field(field: &str, ctx: &RuleContext) -> Option<Value> {
    let r = ctx.record;
    match field {
        "pqc_kem" => Some(
            r.server_kem_selected
                .map(|k| Value::Str(kem_name(&k)))
                .unwrap_or(Value::None),
        ),
        "tls_version" => Some(Value::Str(tls_version_str(r.tls_version))),
        "is_composite_cert" => Some(Value::Bool(r.is_composite_cert)),
        "is_pqc_signature" => Some(Value::Bool(r.is_pqc_signature)),
        "client_hello_has_pqc" => Some(Value::Bool(!r.client_kem_offers.is_empty())),
        "server_hello_has_pqc" => Some(Value::Bool(r.server_kem_selected.is_some())),
        "server_cert_has_pqc" => Some(Value::Bool(r.is_pqc_signature)),
        "pqc_overhead_ms" => Some(Value::Num(r.pqc_overhead_ms as i64)),
        "client_hello_size" => Some(Value::Num(r.client_hello_size as i64)),
        "cert_sig_hash" => Some(Value::Str(hash_from_sig(r.cert_sig_algorithm))),
        "rsa_key_size" => Some(Value::Num(r.rsa_key_size as i64)),
        "is_0rtt" => Some(Value::Bool(r.is_0rtt)),
        "cert_chain_length" => Some(Value::Num(r.cert_chain_length as i64)),
        "prev_connection_had_pqc" => Some(Value::Bool(ctx.prev_connection_had_pqc)),
        "cert_valid_days_left" => Some(Value::Num(r.cert_valid_days_left as i64)),
        _ => None,
    }
}

fn kem_name(kem: &KemId) -> String {
    match kem {
        KemId::MlKem512 => "Kyber-512".into(),
        KemId::MlKem768 => "Kyber-768".into(),
        KemId::MlKem1024 => "Kyber-1024".into(),
        KemId::FrodoKem640Aes => "FrodoKEM-640-AES".into(),
        KemId::FrodoKem976Aes => "FrodoKEM-976-AES".into(),
        KemId::FrodoKem1344Aes => "FrodoKEM-1344-AES".into(),
        KemId::ClassicMcEliece348864 => "Classic McEliece-348864".into(),
        KemId::ClassicMcEliece460896 => "Classic McEliece-460896".into(),
        KemId::ClassicMcEliece6688128 => "Classic McEliece-6688128".into(),
        KemId::BikeL1 => "BIKE-L1".into(),
        KemId::BikeL3 => "BIKE-L3".into(),
        KemId::BikeL5 => "BIKE-L5".into(),
        KemId::Hqc128 => "HQC-128".into(),
        KemId::Hqc192 => "HQC-192".into(),
        KemId::Hqc256 => "HQC-256".into(),
        KemId::Sntrup761 => "sntrup761".into(),
        _ => "Unknown".into(),
    }
}

fn tls_version_str(v: TlsVersion) -> String {
    match v {
        TlsVersion::TlsV1_0 => "1.0".into(),
        TlsVersion::TlsV1_1 => "1.1".into(),
        TlsVersion::TlsV1_2 => "1.2".into(),
        TlsVersion::TlsV1_3 => "1.3".into(),
        TlsVersion::TlsV1_4 => "1.4".into(),
        TlsVersion::Unknown(_) => "unknown".into(),
    }
}

fn hash_from_sig(sig: SigAlgorithm) -> String {
    use SigAlgorithm::*;
    match sig {
        RsaPkcs1Sha256 | RsaPssRsaeSha256 | EcdsaSecp256r1Sha256 => "SHA-256".into(),
        RsaPkcs1Sha384 | RsaPssRsaeSha384 | EcdsaSecp384r1Sha384 => "SHA-384".into(),
        RsaPkcs1Sha512 | RsaPssRsaeSha512 | EcdsaSecp521r1Sha512 => "SHA-512".into(),
        Ed25519 | Ed448 => "EdDSA".into(),
        _ => "Unknown".into(),
    }
}

/// Run the built-in PQC rule set against all records in the store.
/// Returns vulnerability findings grouped per-record with cross-record context.
pub fn scan_rules(records: &[PqcHandshakeRecord]) -> Vec<VulnerabilityFinding> {
    let rule_set = PqcRuleSet::default_set();
    let mut findings = Vec::new();

    // Build cross-record context: track which servers previously had PQC.
    let mut server_pqc_seen: HashMap<String, bool> = HashMap::new();

    for record in records {
        let prev_had_pqc = *server_pqc_seen.get(&record.server_name).unwrap_or(&false);
        let ctx = RuleContext {
            record,
            prev_connection_had_pqc: prev_had_pqc,
        };
        for rule in &rule_set.rules {
            if let Some(finding) = rule.evaluate(&ctx) {
                findings.push(finding);
            }
        }
        let had_pqc = record.used_pqc();
        server_pqc_seen.insert(record.server_name.clone(), had_pqc);
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pair_correlation::FiveTuple;
    use crate::pqc_handshake::{KemId, PqcKem, SigAlgorithm, TlsVersion};
    use chrono::Utc;

    fn test_record() -> PqcHandshakeRecord {
        PqcHandshakeRecord {
            connection_5tuple: FiveTuple {
                src_ip: "10.0.0.1".parse().unwrap(),
                src_port: 443,
                dst_ip: "10.0.0.2".parse().unwrap(),
                dst_port: 12345,
                protocol: 6,
            },
            tls_version: TlsVersion::TlsV1_3,
            server_name: "example.com".into(),
            client_kem_offers: vec![KemId::MlKem768],
            server_kem_selected: Some(KemId::MlKem768),
            is_hybrid_kem: false,
            classical_group: None,
            pqc_kem: Some(PqcKem {
                algorithm: KemId::MlKem768,
                public_key: None,
                ciphertext: None,
                shared_secret: None,
            }),
            shared_secret_size: 32,
            cert_sig_algorithm: SigAlgorithm::MlDsa65,
            is_pqc_signature: true,
            is_composite_cert: false,
            cert_chain_pqc_count: 2,
            pqc_kem_time_us: 5000,
            pqc_sig_verify_us: 2000,
            total_handshake_ms: 50,
            pqc_overhead_ms: 10,
            pqc_packet_size_extra: 1200,
            timestamp: Utc::now(),
            is_success: true,
            pqc_fallback_reason: None,
            client_hello_size: 512,
            server_hello_size: 256,
            cert_chain_length: 2,
            root_is_pqc: false,
            cert_valid_days_left: 365,
            rsa_key_size: 0,
            is_0rtt: false,
        }
    }

    #[test]
    fn tokenize_basic_eq() {
        let tokens = tokenize("pqc_kem == 'Kyber-512'").unwrap();
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[0], Token::Ident("pqc_kem".into()));
        assert_eq!(tokens[1], Token::Eq);
        assert_eq!(tokens[2], Token::String("Kyber-512".into()));
    }

    #[test]
    fn tokenize_and_or() {
        let tokens = tokenize("a == '1' AND b == '2'").unwrap();
        assert_eq!(tokens.len(), 7);
        assert_eq!(tokens[3], Token::And);
    }

    #[test]
    fn parse_simple_eq() {
        let expr = parse_condition("pqc_kem == 'Kyber-768'").unwrap();
        let record = test_record();
        let ctx = RuleContext {
            record: &record,
            prev_connection_had_pqc: false,
        };
        assert!(eval_expr(&expr, &ctx));
    }

    #[test]
    fn parse_not_eq() {
        let expr = parse_condition("pqc_kem != 'Kyber-512'").unwrap();
        let record = test_record();
        let ctx = RuleContext {
            record: &record,
            prev_connection_had_pqc: false,
        };
        assert!(eval_expr(&expr, &ctx));
    }

    #[test]
    fn parse_in_list() {
        let expr = parse_condition("pqc_kem IN ['Kyber-512', 'Kyber-768', 'Kyber-1024']").unwrap();
        let record = test_record();
        let ctx = RuleContext {
            record: &record,
            prev_connection_had_pqc: false,
        };
        assert!(eval_expr(&expr, &ctx));
    }

    #[test]
    fn parse_and_combined() {
        let expr = parse_condition("tls_version == '1.3' AND pqc_kem == 'Kyber-768'").unwrap();
        let record = test_record();
        let ctx = RuleContext {
            record: &record,
            prev_connection_had_pqc: false,
        };
        assert!(eval_expr(&expr, &ctx));
    }

    #[test]
    fn parse_or_combined() {
        let expr = parse_condition("tls_version == '1.2' OR pqc_kem == 'Kyber-768'").unwrap();
        let record = test_record();
        let ctx = RuleContext {
            record: &record,
            prev_connection_had_pqc: false,
        };
        assert!(eval_expr(&expr, &ctx));
    }

    #[test]
    fn parse_parenthesized() {
        let expr = parse_condition(
            "is_composite_cert == true AND (cert_sig_hash == 'SHA-1' OR rsa_key_size < 2048)",
        )
        .unwrap();
        let record = test_record();
        let ctx = RuleContext {
            record: &record,
            prev_connection_had_pqc: false,
        };
        assert!(!eval_expr(&expr, &ctx));
    }

    #[test]
    fn parse_none_check() {
        let expr = parse_condition("pqc_kem == None").unwrap();
        let mut record = test_record();
        record.server_kem_selected = None;
        let ctx = RuleContext {
            record: &record,
            prev_connection_had_pqc: false,
        };
        assert!(eval_expr(&expr, &ctx));
    }

    #[test]
    fn rule_pqc002_classic_only() {
        let rule_set = PqcRuleSet::default_set();
        let rule = rule_set.rules.iter().find(|r| r.id == "PQC-002").unwrap();
        let mut record = test_record();
        record.server_kem_selected = None;
        record.client_kem_offers = Vec::new();
        let ctx = RuleContext {
            record: &record,
            prev_connection_had_pqc: false,
        };
        let finding = rule.evaluate(&ctx);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::Medium);
    }

    #[test]
    fn rule_pqc005_self_signed() {
        let rule_set = PqcRuleSet::default_set();
        let rule = rule_set.rules.iter().find(|r| r.id == "PQC-005").unwrap();
        let mut record = test_record();
        record.cert_chain_length = 1;
        let ctx = RuleContext {
            record: &record,
            prev_connection_had_pqc: false,
        };
        let finding = rule.evaluate(&ctx);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().severity, Severity::Low);
    }

    #[test]
    fn scan_runs_against_records() {
        let mut record = test_record();
        record.server_kem_selected = None;
        record.client_kem_offers = Vec::new();
        let findings = scan_rules(&[record]);
        assert!(findings.iter().any(|f| f.title.contains("Classic-only")));
    }

    #[test]
    fn tokenize_number_comparison() {
        let tokens = tokenize("pqc_overhead_ms > 100").unwrap();
        assert_eq!(tokens.len(), 3);
        assert_eq!(tokens[2], Token::Number(100));
    }

    #[test]
    fn parse_number_gt() {
        let expr = parse_condition("client_hello_size > 10240").unwrap();
        let mut record = test_record();
        record.client_hello_size = 500;
        let ctx = RuleContext {
            record: &record,
            prev_connection_had_pqc: false,
        };
        assert!(!eval_expr(&expr, &ctx));

        record.client_hello_size = 20000;
        let ctx = RuleContext {
            record: &record,
            prev_connection_had_pqc: false,
        };
        assert!(eval_expr(&expr, &ctx));
    }

    #[test]
    fn parse_prev_connection_context() {
        let expr =
            parse_condition("tls_version == '1.2' AND prev_connection_had_pqc == true").unwrap();
        let mut record = test_record();
        record.tls_version = TlsVersion::TlsV1_2;
        let ctx = RuleContext {
            record: &record,
            prev_connection_had_pqc: true,
        };
        assert!(eval_expr(&expr, &ctx));
    }

    #[test]
    fn cvss_vector_in_rule_finding() {
        let rule_set = PqcRuleSet::default_set();
        let rule = rule_set.rules.iter().find(|r| r.id == "PQC-001").unwrap();
        let mut record = test_record();
        record.server_kem_selected = Some(KemId::MlKem512);
        let ctx = RuleContext {
            record: &record,
            prev_connection_had_pqc: false,
        };
        let finding = rule.evaluate(&ctx);
        assert!(finding.is_some());
        let f = finding.unwrap();
        assert!(f.cvss_vector.as_deref().unwrap_or("").contains("CVSS"));
        assert!(!f.impact.is_empty());
        assert!(!f.fix.is_empty());
    }
}
