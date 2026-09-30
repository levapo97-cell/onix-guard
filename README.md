# onix-guard

Servicio de **seguridad + análisis** de OnixGuard. Escrito en **Rust**. Es el único servicio que ve el valor crudo de las credenciales, y lo **destruye**: redacta secretos (SHA-256), marca repeticiones e ineficiencias, y genera el post-mortem al cerrar etapas.

> **Estado:** se construye en **Fase 2**. Este README documenta su diseño.

---

## Responsabilidad

```mermaid
flowchart LR
  NATS1[("NATS onix.norm.*")] --> GUARD["onix-guard (Rust)"]
  GUARD -->|"redacta credenciales (SHA-256)<br/>marca is_error / is_repetition"| NATS2[("NATS onix.clean.*")]
  GUARD -.->|"al cerrar etapas"| PM["post-mortem (informe agregado)"]
```

Entrada `NormEvent` (`onix.norm.*`) → Salida `CleanEvent` (`onix.clean.*`), ya **sin valores de credenciales**.

## Qué hará

- **Redacción de secretos (fail-closed):** detecta API keys, tokens, contraseñas, cadenas de conexión y contenido de `.env`; reemplaza el valor por `[credencial · sha256:…]` + tipo. El valor real **nunca** se publica en `clean`, ni se guarda, ni se loguea. Ante la duda, redacta.
- **Detección** (umbrales configurables):
  - **Error:** tool falla o `exit_code != 0`.
  - **Repetición:** mismo `tool` + `params_hash` ≥ 3 veces en ventana de 4 min.
  - **Ineficiencia:** reintentos sin cambios, relectura de archivos grandes, tokens de etapa > 1.5× la mediana, etc.
- **Post-mortem:** informe agregado por etapa/agente (costo, tiempo, errores, cuellos de botella) para el estudio multiagente.

## Por qué Rust

Es el servicio crítico de seguridad (maneja el valor crudo de secretos) y de análisis intensivo. Rust da garantías de memoria y rendimiento para esa responsabilidad.

## Contratos

- **Consume:** `NormEvent` (`onix.norm.*`).
- **Produce:** `CleanEvent` (`onix.clean.*`) → lo consumen `onix-recorder` y `onix-gateway`.
- **Importa:** crate `onix-contracts` (ver ese repo).

## Estructura (futura)

```text
src/            # lógica de redacción, detección, post-mortem
Cargo.toml
Dockerfile      # multi-stage (rust → imagen mínima)
```

## Pruebas clave (QA)

Unit tests de **redacción** (que jamás filtre el valor) y de **detección** con casos límite. Es la red de seguridad más importante del sistema.

---

*Parte de OnixGuard. Ver el plan en `OnixGuard/docs/PLAN.md` §1, §8 (detección) y §9 (seguridad).*
