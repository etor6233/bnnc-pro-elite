# EVIDENCIA — FASE 6: CI en el repo público (Linux + Windows)

**Estado: DONE (checkmark verde).** Fecha: 2026-09-18.

## Workflow

- `.github/workflows/ci.yml` en `etor6233/bnnc-pro-elite`: por cada push/PR,
  matriz Linux + Windows:
  - **Rust**: `cargo fmt --check`, `cargo test --all-targets`,
    `cargo clippy --all-targets -- -D warnings`, y el gate explícito de los
    módulos Windows-only (`windows_etw`/`windows_tcp` son `#[cfg(windows)]`
    en `rust/lob-replay/src/lib.rs`): su compilación en Windows ejercita la
    inclusión y en Linux la exclusión.
  - **Python**: `unittest discover` con `websockets==17.0.1` (hash-lock de
    Windows en CI-Windows; misma versión pineada en Linux).
  - **C++**: `cpp/build.ps1 -Phase all` (MSVC, Windows) y `cpp/build.sh all`
    (g++, Linux) — los 7 suites (57 tests) con regeneración de golden
    vectors en cada corrida.

## Iteración real hasta verde (evidencia de las corridas)

1. Run `35385665414` (rojo): faltaba localizar vcvars por vswhere en el
   runner; rustfmt/clippy no instalados por perfil mínimo.
2. Run `35385923090` (rojo): Python sin `websockets` instalado; 5 tests de
   network-trace con fixture que no vinculaba el path resuelto (el verifier
   resuelve reparse points; el fixture no).
3. Run `35386528141` (rojo): hash-lock de wheels específico de Windows
   fallaba en Linux.
4. **Run `35387520776` (VERDE)** — checkmark verde en GitHub:

| Job | Resultado | Duración |
|---|---|---|
| C++ suites (windows-latest) | ✓ | 1m25s |
| C++ suites (ubuntu-latest) | ✓ | 32s |
| Rust + Python (windows-latest) | ✓ | 5m32s |
| Rust + Python (ubuntu-latest) | ✓ | 2m27s |

Corridas VERDES posteriores sobre `main` (mismo YAML, mismos gates):
`35388366114`, `35392017320` y la última sobre el historial final de `main`
(ver checkmark en la página del repo, pestaña Actions).

## Archivos de evidencia

- `.github/workflows/ci.yml` (repo)
- URL de la corrida verde: `https://github.com/etor6233/bnnc-pro-elite/actions/runs/35387520776`
- Logs por job descargables desde esa corrida (actions artifacts/logs).
