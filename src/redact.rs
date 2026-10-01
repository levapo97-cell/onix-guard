//! Redacción de credenciales. Reemplaza el valor real por `[credencial · sha256:…]` y
//! guarda SOLO el hash. El valor real NUNCA sale de esta función. Fail-closed: ante un
//! nombre de campo sensible, redacta aunque el valor no matchee ningún patrón.

use crate::types::Credential;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub struct Redaction {
    pub params: Map<String, Value>,
    pub credentials: Vec<Credential>,
}

pub fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
}

/// Etiqueta legible que reemplaza al valor, p. ej. `[credencial · sha256:9f2c1a7b…0a1b]`.
pub fn label(hash: &str) -> String {
    let head = &hash[..8.min(hash.len())];
    let tail = if hash.len() >= 4 { &hash[hash.len() - 4..] } else { hash };
    format!("[credencial · sha256:{head}…{tail}]")
}

// Patrones de valor (orden importa: primero los más específicos/largos).
static CONN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:[^\s/@]+@\S+").unwrap());
static APIKEY: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:sk-ant-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|AIza[0-9A-Za-z_\-]{35}|xox[baprs]-[A-Za-z0-9\-]{10,})").unwrap()
});
static JWT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+").unwrap());
static ENVSECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?im)([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY)[A-Z0-9_]*\s*=\s*)("?)([^"\n\r]+)"#).unwrap()
});

/// ¿El NOMBRE del campo es sensible? (fail-closed).
fn secret_key(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["password", "passwd", "secret", "token", "api_key", "apikey", "access_key",
     "secret_key", "private_key", "authorization", "auth", "credential", "dsn"]
        .iter()
        .any(|k| n.contains(k))
}

fn kind_from_key(name: &str) -> &'static str {
    let n = name.to_ascii_lowercase();
    if n.contains("password") || n.contains("passwd") {
        "password"
    } else if n.contains("conn") || n.contains("dsn") || n.contains("url") {
        "conn_string"
    } else if n.contains("key") {
        "api_key"
    } else {
        "token"
    }
}

/// Redacta un string. Devuelve (string_redactado, credenciales_encontradas).
/// Si `key` es un nombre sensible, se redacta el valor COMPLETO (fail-closed).
pub fn redact_scalar(key: Option<&str>, s: &str) -> (String, Vec<Credential>) {
    if let Some(k) = key {
        if secret_key(k) {
            let hash = sha256_hex(s);
            let lbl = label(&hash);
            return (lbl.clone(), vec![Credential { kind: kind_from_key(k).into(), sha256: hash, label: lbl }]);
        }
    }

    let mut creds = Vec::new();
    let mut out = s.to_string();

    // Aplica cada patrón. Cada match se sustituye por su label; el hash es del valor real.
    for (re, kind, group) in [
        (&*CONN, "conn_string", 0usize),
        (&*APIKEY, "api_key", 0),
        (&*JWT, "token", 0),
        (&*ENVSECRET, "env", 3),
    ] {
        let mut collected: Vec<Credential> = Vec::new();
        out = re
            .replace_all(&out, |caps: &regex::Captures| {
                let secret = caps.get(group).map(|m| m.as_str()).unwrap_or("");
                let hash = sha256_hex(secret);
                let lbl = label(&hash);
                collected.push(Credential { kind: kind.into(), sha256: hash, label: lbl.clone() });
                if group == 0 {
                    lbl
                } else {
                    // ENVSECRET: conserva "KEY=" (grupo 1) + comilla (grupo 2) y redacta el valor.
                    format!("{}{}{}", &caps[1], &caps[2], lbl)
                }
            })
            .into_owned();
        creds.extend(collected);
    }

    (out, creds)
}

/// Redacta recursivamente todos los valores string de un objeto de params.
fn redact_value(key: Option<&str>, v: &Value, creds: &mut Vec<Credential>) -> Value {
    match v {
        Value::String(s) => {
            let (red, c) = redact_scalar(key, s);
            creds.extend(c);
            Value::String(red)
        }
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, val) in map {
                out.insert(k.clone(), redact_value(Some(k), val, creds));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(|e| redact_value(key, e, creds)).collect()),
        other => other.clone(),
    }
}

pub fn redact_params(params: &Option<Map<String, Value>>) -> Redaction {
    let mut credentials = Vec::new();
    let mut out = Map::new();
    if let Some(map) = params {
        for (k, v) in map {
            out.insert(k.clone(), redact_value(Some(k), v, &mut credentials));
        }
    }
    Redaction { params: out, credentials }
}

/// params_hash = SHA-256 del JSON canónico (serde_json::Map por defecto ordena claves).
pub fn params_hash(params: &Map<String, Value>) -> String {
    let canonical = serde_json::to_string(params).unwrap_or_default();
    sha256_hex(&canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn map(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn redacts_connection_string_and_never_leaks_value() {
        let secret = "postgres://devtools:SuperSecret123@db.internal:5432/onixguard";
        let p = Some(map(json!({ "command": format!("psql {secret}") })));
        let r = redact_params(&p);
        let out = serde_json::to_string(&r.params).unwrap();
        assert!(!out.contains("SuperSecret123"), "¡filtró la contraseña!");
        assert!(!out.contains("devtools:SuperSecret123"));
        assert_eq!(r.credentials.len(), 1);
        assert_eq!(r.credentials[0].kind, "conn_string");
        assert_eq!(r.credentials[0].sha256.len(), 64);
    }

    #[test]
    fn redacts_by_sensitive_key_name_even_if_value_is_plain() {
        let p = Some(map(json!({ "password": "hunter2", "user": "ronny" })));
        let r = redact_params(&p);
        let out = serde_json::to_string(&r.params).unwrap();
        assert!(!out.contains("hunter2"), "¡filtró el valor del campo password!");
        assert!(out.contains("ronny"), "no debía tocar campos no sensibles");
        assert_eq!(r.credentials.len(), 1);
        assert_eq!(r.credentials[0].kind, "password");
    }

    #[test]
    fn redacts_api_key_pattern() {
        let key = "sk-ant-abcdefghijklmnopqrstuvwxyz0123456789";
        let p = Some(map(json!({ "env": format!("ANTHROPIC_API_KEY={key}") })));
        let r = redact_params(&p);
        let out = serde_json::to_string(&r.params).unwrap();
        assert!(!out.contains(key), "¡filtró la api key!");
        assert!(!r.credentials.is_empty());
    }

    #[test]
    fn redacts_env_secret_assignment_keeps_key_name() {
        let p = Some(map(json!({ "content": "DB_PASSWORD=topsecret\nDEBUG=true" })));
        let r = redact_params(&p);
        let out = serde_json::to_string(&r.params).unwrap();
        assert!(!out.contains("topsecret"), "¡filtró el secreto del .env!");
        assert!(out.contains("DB_PASSWORD="), "debía conservar el nombre de la variable");
        assert!(out.contains("DEBUG=true"), "no debía tocar lo no-secreto");
    }

    #[test]
    fn leaves_clean_params_untouched() {
        let p = Some(map(json!({ "command": "npm run test", "cwd": "/repo" })));
        let r = redact_params(&p);
        assert!(r.credentials.is_empty());
        assert_eq!(r.params.get("command").unwrap(), "npm run test");
    }

    #[test]
    fn params_hash_is_deterministic() {
        let a = map(json!({ "b": 2, "a": 1 }));
        let b = map(json!({ "a": 1, "b": 2 }));
        assert_eq!(params_hash(&a), params_hash(&b), "el hash debe ser estable ante el orden de claves");
    }
}
