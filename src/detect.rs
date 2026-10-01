//! Detección de error y repetición (§8 del plan). Umbrales configurables.

use crate::types::Result_;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Error: la tool falló (exit_code != 0).
pub fn is_error(result: &Option<Result_>) -> bool {
    matches!(result, Some(r) if matches!(r.exit_code, Some(code) if code != 0))
}

/// Detecta repeticiones: mismo (session, tool, params_hash) >= `threshold` veces
/// dentro de una ventana de tiempo. Estado en memoria (por instancia del servicio).
pub struct RepetitionDetector {
    window: Duration,
    threshold: usize,
    seen: HashMap<String, Vec<Instant>>,
}

impl RepetitionDetector {
    /// Valores del plan: ventana 4 min, umbral 3.
    pub fn new(window_secs: u64, threshold: usize) -> Self {
        Self { window: Duration::from_secs(window_secs), threshold, seen: HashMap::new() }
    }

    pub fn default_rule() -> Self {
        Self::new(240, 3)
    }

    /// Registra una ocurrencia y devuelve true si alcanza el umbral dentro de la ventana.
    pub fn record(&mut self, session: &str, tool: &str, params_hash: &str) -> bool {
        self.record_at(session, tool, params_hash, Instant::now())
    }

    // Separado para poder testear con un reloj inyectado.
    pub fn record_at(&mut self, session: &str, tool: &str, params_hash: &str, now: Instant) -> bool {
        let key = format!("{session}|{tool}|{params_hash}");
        let entry = self.seen.entry(key).or_default();
        entry.push(now);
        entry.retain(|t| now.duration_since(*t) <= self.window);
        entry.len() >= self.threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_only_on_nonzero_exit() {
        assert!(!is_error(&None));
        assert!(!is_error(&Some(Result_ { exit_code: Some(0), duration_ms: None })));
        assert!(is_error(&Some(Result_ { exit_code: Some(1), duration_ms: None })));
    }

    #[test]
    fn third_repeat_in_window_is_flagged() {
        let mut d = RepetitionDetector::new(240, 3);
        let t0 = Instant::now();
        assert!(!d.record_at("s", "Bash", "h", t0));
        assert!(!d.record_at("s", "Bash", "h", t0));
        assert!(d.record_at("s", "Bash", "h", t0), "la 3ª igual debe marcarse");
    }

    #[test]
    fn different_hash_not_repetition() {
        let mut d = RepetitionDetector::new(240, 3);
        let t0 = Instant::now();
        assert!(!d.record_at("s", "Bash", "h1", t0));
        assert!(!d.record_at("s", "Bash", "h2", t0));
        assert!(!d.record_at("s", "Bash", "h3", t0));
    }

    #[test]
    fn outside_window_resets() {
        let mut d = RepetitionDetector::new(240, 3);
        let t0 = Instant::now();
        let later = t0 + Duration::from_secs(300); // fuera de la ventana de 240s
        assert!(!d.record_at("s", "Bash", "h", t0));
        assert!(!d.record_at("s", "Bash", "h", t0));
        // la anterior expiró: no llega a 3 dentro de la ventana
        assert!(!d.record_at("s", "Bash", "h", later));
    }
}
