# EVIDENCIA — FASE 8: Publicación y evidencia final

**Estado: DONE.** Fecha: 2026-09-18.

## Qué se publicó

- Repo público `etor6233/bnnc-pro-elite`, rama `main` (historial limpio,
  ver `git log` en el repo):
  - código nuevo C++ completo en `cpp/` (ITCH/OUCH/SBE/FIX/multicast/
    recovery/resilience/bench) con golden/malformed vectors y generadores;
  - benchmarks medidos `cpp/bench/benchmarks/*.json`;
  - CI `.github/workflows/ci.yml` (verde, run `35387520776`);
  - `README.md` con la sección "Venue-connectivity layer (C++, 2026-09-18)"
    donde CADA claim apunta a un archivo de evidencia dentro del repo;
  - `docs/EVIDENCE.md` extendido con la tabla de claims nuevos.

## Verificaciones exigidas

- Repo renderizado: SÍ (markdown de README/EVIDENCE validado por GitHub).
- Links de evidencia OK: todos los enlaces de la sección nueva apuntan a
  archivos existentes en el repo (verificado con `git ls-files`).
- Cero rutas personales: SÍ — scan `C:\Users\NL|NLuciani|C:\Users` sobre
  `cpp/**`, workflow y README: 0 coincidencias.
- Cero secretos: SÍ — scan de tokens `gho_*`, claves API, `AKIA`,
  `BEGIN (RSA|EC|OPENSSH)` sobre el mismo conjunto: 0 coincidencias.
- No se publicaron: árbol vivo del servicio, journals históricos, holdout,
  binarios congelados, claves de la cuenta (el repo no contiene credenciales
  ni material de cuentas).

## Honestidad §5 de la instrucción

- El repo compensa con evidencia medible; no afirma 3+ años de experiencia
  laboral ni autorización de trabajo en USA. Ningún texto nuevo lo afirma.
