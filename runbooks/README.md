# Runbooks

Operación del servicio continuo hot-redundant BTCUSDT/ETHUSDT (ADR-17):

- [CONTINUOUS_SERVICE.md](CONTINUOUS_SERVICE.md) — runbook operativo del
  servicio continuo: preflight, inicio (consola elevada), estado, parada
  segura, recuperación, cuarentena y límites. Ésta es la referencia de
  OPERACIÓN actual; la producción NO se inicia hasta la revisión
  independiente de Codex.
- [QUALIFICATION_24H.md](QUALIFICATION_24H.md) — campaña HISTÓRICA de
  calificación de 24 h (soak de una ventana). No es el modo de operación
  continuo: documenta la campaña ya ejecutada, no dirige el servicio actual.

Runbooks especializados previstos (no ejecutados aún): `clock-unhealthy`,
`websocket-gap-resync`, `slow-full-disk` y `bad-release-rollback`. No hay
ejecución ni runbook de órdenes habilitado.

Guardas del launcher contra confusión test/operación (verificadas 2026-09-16
en `scripts/run_hot_redundant_qualification.ps1`):

- `-TimeScale > 1` es SOLO de test (reloj virtual de hitos + topología
  reducida 30/25 s, raíz de run `artifacts\hsc`); exige `-Mode Continuous` y
  está prohibido en `-Mode Production`.
- `-SkipKernelObserver` / `-ArbiterOverride` / `-ArbiterVerifyOverride` /
  `-ReleaseBinRoot` están rechazados en `-Mode Production`.
- `-Mode ValidateOnly` recompila `--release` salvo que se indique
  `-ReleaseBinRoot` con la ruta congelada (no asumir que es read-only).
