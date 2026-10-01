//! onix-guard — seguridad + análisis de OnixGuard (FASE 2).
//!
//! Consume onix.norm.* de NATS/JetStream, REDACTA credenciales (SHA-256), DETECTA error y
//! repetición, y publica onix.clean.* SIN el valor real de ninguna credencial.
//! Expone /healthz. El valor crudo solo vive dentro de este proceso y se destruye.

mod detect;
mod redact;
mod types;

use detect::{is_error, RepetitionDetector};
use futures::StreamExt;
use redact::{params_hash, redact_params, Redaction};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use types::{CleanEvent, NormEvent};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

fn env(key: &str, def: &str) -> String {
    std::env::var(key).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| def.to_string())
}

#[tokio::main]
async fn main() -> Result<(), BoxErr> {
    // Modo healthcheck para Docker (imagen distroless, sin shell/curl).
    if std::env::args().any(|a| a == "--healthcheck") {
        std::process::exit(run_healthcheck(&env("PORT", "8083")));
    }

    let nats_url = env("NATS_URL", "nats://nats:4222");
    let port = env("PORT", "8083");
    eprintln!("onix-guard arrancando · nats={nats_url} · port={port}");

    // Servidor de salud en un hilo aparte (no bloquea el loop async).
    spawn_health_server(port);

    let client = async_nats::connect(&nats_url).await?;
    let js = async_nats::jetstream::new(client);

    // Garantiza los streams que consume (NORM) y al que publica (CLEAN).
    use async_nats::jetstream::stream::Config as StreamConfig;
    js.get_or_create_stream(StreamConfig {
        name: "ONIX_NORM".into(),
        subjects: vec!["onix.norm.>".into()],
        ..Default::default()
    })
    .await?;
    js.get_or_create_stream(StreamConfig {
        name: "ONIX_CLEAN".into(),
        subjects: vec!["onix.clean.>".into()],
        ..Default::default()
    })
    .await?;

    let stream = js.get_stream("ONIX_NORM").await?;
    use async_nats::jetstream::consumer::pull::Config as PullConfig;
    let consumer = stream
        .get_or_create_consumer(
            "onix-guard",
            PullConfig { durable_name: Some("onix-guard".into()), ..Default::default() },
        )
        .await?;

    let mut detector = RepetitionDetector::default_rule();
    let mut messages = consumer.messages().await?;
    eprintln!("onix-guard activo: onix.norm.* → onix.clean.*");

    while let Some(msg) = messages.next().await {
        let msg = msg?;
        match process(&msg.payload, &mut detector) {
            Ok((clean_bytes, session)) => {
                match js.publish(format!("onix.clean.{session}"), clean_bytes.into()).await {
                    Ok(ack) => {
                        let _ = ack.await; // confirma persistencia en el stream
                        let _ = msg.ack().await;
                    }
                    Err(e) => {
                        eprintln!("publish clean falló (reintento): {e}");
                        // sin ack → JetStream reentrega
                    }
                }
            }
            Err(e) => {
                eprintln!("norm inválido, descartado: {e}");
                let _ = msg.ack().await; // no reintentar algo que nunca parseará
            }
        }
    }
    Ok(())
}

/// Transforma un NormEvent en CleanEvent: redacta credenciales, calcula hash, detecta error/repetición.
fn process(payload: &[u8], detector: &mut RepetitionDetector) -> Result<(Vec<u8>, String), BoxErr> {
    let norm: NormEvent = serde_json::from_slice(payload)?;

    let Redaction { params, credentials } = redact_params(&norm.params);
    let phash = params_hash(&params);
    let is_err = is_error(&norm.result);

    let tool = norm.tool.clone().unwrap_or_default();
    let is_rep = if !tool.is_empty() {
        detector.record(&norm.session, &tool, &phash)
    } else {
        false
    };

    let clean = CleanEvent {
        v: norm.v,
        session: norm.session.clone(),
        agent_role: norm.agent_role,
        hook: norm.hook,
        ts: norm.ts,
        received_at: norm.received_at,
        tool: norm.tool,
        params_normalized: if norm.params.is_some() { Some(params) } else { None },
        params_hash: phash,
        result: norm.result,
        tokens: norm.tokens,
        cost_usd: norm.cost_usd,
        cwd: norm.cwd,
        project: norm.project,
        stage: norm.stage,
        is_error: is_err,
        is_repetition: is_rep,
        credentials,
    };
    let bytes = serde_json::to_vec(&clean)?;
    Ok((bytes, norm.session))
}

// ───────────────────────── salud ─────────────────────────

fn spawn_health_server(port: String) {
    std::thread::spawn(move || {
        let listener = match TcpListener::bind(format!("0.0.0.0:{port}")) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("no se pudo abrir el puerto de salud: {e}");
                return;
            }
        };
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                let mut buf = [0u8; 512];
                let _ = s.read(&mut buf);
                let body = r#"{"status":"ok","service":"onix-guard"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = s.write_all(resp.as_bytes());
            }
        }
    });
}

/// Cliente de healthcheck: GET /healthz a sí mismo, sale 0 (sano) o 1.
fn run_healthcheck(port: &str) -> i32 {
    match TcpStream::connect(format!("127.0.0.1:{port}")) {
        Ok(mut s) => {
            if s.write_all(b"GET /healthz HTTP/1.0\r\n\r\n").is_err() {
                return 1;
            }
            let mut resp = String::new();
            let _ = s.read_to_string(&mut resp);
            if resp.starts_with("HTTP/1.1 200") || resp.starts_with("HTTP/1.0 200") {
                0
            } else {
                1
            }
        }
        Err(_) => 1,
    }
}
