//! Tipos del contrato (espejo de onix-contracts). NormEvent entra, CleanEvent sale.
//! Se mantienen aquí para evitar la dependencia git del crate; deben coincidir con
//! onix-contracts/schemas/*.schema.json.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[derive(Debug, Clone, Deserialize)]
pub struct Result_ {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<i64>,
}

// Serialize manual para el clean (misma forma).
impl Serialize for Result_ {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("Result", 2)?;
        st.serialize_field("exit_code", &self.exit_code)?;
        st.serialize_field("duration_ms", &self.duration_ms)?;
        st.end()
    }
}

/// Evento normalizado que publica onix-ingestor (onix.norm.*).
#[derive(Debug, Clone, Deserialize)]
pub struct NormEvent {
    pub v: i64,
    pub session: String,
    pub agent_role: String,
    pub hook: String,
    pub ts: String,
    pub received_at: String,
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub params: Option<Map<String, Value>>,
    #[serde(default)]
    pub result: Option<Result_>,
    #[serde(default)]
    pub tokens: Option<i64>,
    #[serde(default)]
    pub cost_usd: Option<f64>,
    #[serde(default)]
    pub cwd: Option<String>,
    pub project: String,
    #[serde(default)]
    pub stage: Option<i64>,
}

/// Credencial detectada: SOLO metadatos + hash. NUNCA el valor real.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Credential {
    pub kind: String,
    pub sha256: String,
    pub label: String,
}

/// Evento limpio que publica onix-guard (onix.clean.*). Sin valores de credenciales.
#[derive(Debug, Clone, Serialize)]
pub struct CleanEvent {
    pub v: i64,
    pub session: String,
    pub agent_role: String,
    pub hook: String,
    pub ts: String,
    pub received_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params_normalized: Option<Map<String, Value>>,
    pub params_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Result_>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    pub project: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<i64>,
    pub is_error: bool,
    pub is_repetition: bool,
    pub credentials: Vec<Credential>,
}
