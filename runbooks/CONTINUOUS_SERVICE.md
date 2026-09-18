# Runbook — servicio continuo hot-redundant con arbitraje en vivo (ADR-17)

Ámbito: BTCUSDT/ETHUSDT, captura raw dual-lane continua, vista canónica
arbitrada, ventanas de calificación selladas y verificadas. Nada aquí
entrena ML, coloca órdenes ni elimina raw automáticamente.

Los comandos se ejecutan desde `C:\Users\NL\Desktop\NEW BINANCE\Binance`.

## 1. Preflight (no inicia captura)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run_hot_redundant_qualification.ps1 -Mode ValidateOnly
```

Revisa la salida: `status=PASS`, hashes de binarios/scripts/fuente, disco
libre >= requerido, reloj sano. **Producción requiere consola elevada**
(kernel ETW).

Nota (verificada 2026-09-16 contra el launcher): `-Mode ValidateOnly` NO es
estrictamente read-only: sin `-ReleaseBinRoot` compila `--release` en
`Binance\target\release` antes de imprimir el preflight (garantía
same-binary). Para validar un paquete ya congelado sin recompilar, pasar
`-ReleaseBinRoot <ruta congelada>` (aceptado en ValidateOnly; RECHAZADO en
`-Mode Production`).

## 2. Inicio continuo (producción; no iniciar sin revisión independiente)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run_hot_redundant_qualification.ps1 -Mode Continuous
```

(`-EpochWindowSeconds 14400` es el default; `-TimeScale 1` es el default y
es obligatorio en operación real: `TimeScale > 1` acelera hitos Y activa la
topología reducida de test. Sin `-SkipKernelObserver`: los observadores
elevados van habilitados; el launcher exige consola elevada salvo
invocación test explícita con skip tipado.)

El servicio:
- no tiene horizonte global (nunca termina por duración);
- renueva cada supervisor de símbolo cada `EpochWindowSeconds` (por defecto
  4 h) con solape planificado: el sucesor arranca `EpochWindowSeconds -
  overlap` antes de sellar al predecesor; los dos lanes del símbolo nunca se
  detienen antes de un sucesor READY;
- sella y verifica cada ventana de epoch (Rust + Python) mientras la
  siguiente captura;
- supervisa el árbitro canónico por símbolo: cualquier salida se recupera
  con `--resume` (identidad durable + cadena de segmentos, sin duplicación
  ni rollback) y backoff; la vista derivada degrada sin tocar raw;
- emite `WINDOW_MILESTONE` a 24 h / 7 d / 30 d sin detener la captura;
- conserva `stop.request` como único mecanismo de parada cooperativa.

Evidencia: `artifacts\hrs\hrs-<nonce>\` (service-events.jsonl, preflight,
terminal, canonical-live/<symbol>/*-seg-*.jsonl, trade-identity.bin).

## 3. Estado

```powershell
Get-Content artifacts\hrs\hrs-<nonce>\service-events.jsonl -Tail 50
# eventos: SERVICE_READY, SYMBOL_EPOCH_RENEWED (no_outer_gap), WINDOW_MILESTONE,
# LIVE_ARBITRATION_LAUNCHED/SEGMENT_SEALED/SEGMENT_VERIFIED, OBSERVER_FAILED, ...
Get-Content artifacts\hrs\hrs-<nonce>\service-terminal.json   # tras la parada
```

## 4. Parada segura (cooperativa, sin pérdida)

```powershell
# crear el stop file vacío (create-only)
[IO.File]::WriteAllBytes("artifacts\hrs\hrs-<nonce>\stop.request", [byte[]]@())
```

El servicio: termina el epoch en curso, drena supervisores (tope 1800 s),
completa la transición pendiente (rebind del árbitro), sella el último
segmento, verifica el conjunto canónico contra el oráculo raw (Rust +
Python, identidad PASS obligatoria) y escribe `service-terminal.json` con
estado honesto (`PASS` / `CAPTURE_COMPLETE_WITH_EXPLICIT_GAPS` /
`CAPTURE_COMPLETE_WITH_OBSERVABILITY_FAILURES`). Los procesos quedan en un
Job Object kill-on-close; el `finally` garantiza la limpieza.

## 5. Reinicio / recuperación

Un reinicio es simplemente un nuevo `-Mode Continuous` con un nuevo
`hrs-<nonce>` (nueva raíz, nuevo mutex). La recuperación AUTOMÁTICA dentro
de una corrida cubre:

- árbitro caído → `LIVE_ARBITRATION_EXITED_EARLY` + relanzamiento con
  `--resume` (segmento nuevo encadena `ARBITRATION_RESUMED` con
  `previous_journal_sha256` + `trade_floor` + `previous_tail_bytes`);
- supervisor de símbolo caído → `OUTER_GAP_OPENED/CLOSED` + backoff; el
  sucesor planificado se promueve sin gap;
- evaluador colgado → terminación al deadline monotónico,
  `LIVE_ARBITRATION_AUDIT_TIMEOUT`; el auditor se limpia también cuando
  muere su árbitro;
- disco bajo la reserva (100 GiB) → `STORAGE_SAFE_STOP_REQUESTED` + parada
  segura evidenciada; nunca se borra raw automáticamente.

## 6. Cuarentena / degradación de la vista derivada

Si la vista canónica no se puede probar (conflicto tipado, gap no puenteable,
verificación fallida), el árbitro falla cerrado: deja de publicar, escribe el
evento tipado y sale no-cero. El raw sigue capturando. La promoción de una
ventana exige el oráculo `oracle_identity=PASS` en AMBOS verificadores;
`SKIPPED`, timeout o auditoría pendiente nunca promueve.

## 7. Retención / discos / observadores

- Reserva persistente: 100 GiB; preflight valida espacio proyectado con
  factor de seguridad.
- Sin borrado automático de raw; la política de retención la decide el
  operador fuera del servicio.
- Kernel ETW + network witness: deadline por epoch (rotación), evidencia
  sellada por ventana; en corridas de prueba no elevadas el terminal registra
  `SKIPPED_NOT_ELEVATED` honesto (el gate elevado queda OPEN).

## 8. Upgrades

Congelar fuentes → build release completo (`cargo build --release -p
lob-replay --bin hot_redundant_capture --bin hot_redundant_verify --bin
raw_campaign --bin segmented_capture --bin campaign_verify --bin
kernel_network_trace --bin live_arbitration --bin live_arbitration_verify`)
→ suites Rust/Python completas → fmt/clippy → gates live/launcher/fault con
ESOS binarios → nuevo manifiesto con hashes. Cambiar algo después invalida
los gates afectados: repetirlos.

## 9. Límites honestos

- Un evento perdido por AMBOS lanes no es demostrable sin un tercer testigo
  que Binance no ofrece sin credenciales (acotación del contrato).
- Soak real 24 h / 7 d: gate de tiempo real, aparte de la preparación.
- Kernel ETW elevado: requiere consola elevada (gate explícito).
- Verificación oráculo completa de una ventana de 24 h: decenas de minutos
  (digest de libro completo por frame); las verificaciones por epoch usan el
  modo acotado `--tail-segment-only`.
