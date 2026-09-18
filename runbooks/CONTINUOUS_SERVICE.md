# Runbook â€” servicio continuo hot-redundant con arbitraje en vivo (ADR-17)

Ãmbito: BTCUSDT/ETHUSDT, captura raw dual-lane continua, vista canÃ³nica
arbitrada, ventanas de calificaciÃ³n selladas y verificadas. Nada aquÃ­
entrena ML, coloca Ã³rdenes ni elimina raw automÃ¡ticamente.

Los comandos se ejecutan desde `<WORKSPACE>\Binance`.

## 1. Preflight (no inicia captura)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run_hot_redundant_qualification.ps1 -Mode ValidateOnly
```

Revisa la salida: `status=PASS`, hashes de binarios/scripts/fuente, disco
libre >= requerido, reloj sano. **ProducciÃ³n requiere consola elevada**
(kernel ETW).

Nota (verificada 2026-09-16 contra el launcher): `-Mode ValidateOnly` NO es
estrictamente read-only: sin `-ReleaseBinRoot` compila `--release` en
`Binance\target\release` antes de imprimir el preflight (garantÃ­a
same-binary). Para validar un paquete ya congelado sin recompilar, pasar
`-ReleaseBinRoot <ruta congelada>` (aceptado en ValidateOnly; RECHAZADO en
`-Mode Production`).

## 2. Inicio continuo (producciÃ³n; no iniciar sin revisiÃ³n independiente)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\run_hot_redundant_qualification.ps1 -Mode Continuous
```

(`-EpochWindowSeconds 14400` es el default; `-TimeScale 1` es el default y
es obligatorio en operaciÃ³n real: `TimeScale > 1` acelera hitos Y activa la
topologÃ­a reducida de test. Sin `-SkipKernelObserver`: los observadores
elevados van habilitados; el launcher exige consola elevada salvo
invocaciÃ³n test explÃ­cita con skip tipado.)

El servicio:
- no tiene horizonte global (nunca termina por duraciÃ³n);
- renueva cada supervisor de sÃ­mbolo cada `EpochWindowSeconds` (por defecto
  4 h) con solape planificado: el sucesor arranca `EpochWindowSeconds -
  overlap` antes de sellar al predecesor; los dos lanes del sÃ­mbolo nunca se
  detienen antes de un sucesor READY;
- sella y verifica cada ventana de epoch (Rust + Python) mientras la
  siguiente captura;
- supervisa el Ã¡rbitro canÃ³nico por sÃ­mbolo: cualquier salida se recupera
  con `--resume` (identidad durable + cadena de segmentos, sin duplicaciÃ³n
  ni rollback) y backoff; la vista derivada degrada sin tocar raw;
- emite `WINDOW_MILESTONE` a 24 h / 7 d / 30 d sin detener la captura;
- conserva `stop.request` como Ãºnico mecanismo de parada cooperativa.

Evidencia: `artifacts\hrs\hrs-<nonce>\` (service-events.jsonl, preflight,
terminal, canonical-live/<symbol>/*-seg-*.jsonl, trade-identity.bin).

## 3. Estado

```powershell
Get-Content artifacts\hrs\hrs-<nonce>\service-events.jsonl -Tail 50
# eventos: SERVICE_READY, SYMBOL_EPOCH_RENEWED (no_outer_gap), WINDOW_MILESTONE,
# LIVE_ARBITRATION_LAUNCHED/SEGMENT_SEALED/SEGMENT_VERIFIED, OBSERVER_FAILED, ...
Get-Content artifacts\hrs\hrs-<nonce>\service-terminal.json   # tras la parada
```

## 4. Parada segura (cooperativa, sin pÃ©rdida)

```powershell
# crear el stop file vacÃ­o (create-only)
[IO.File]::WriteAllBytes("artifacts\hrs\hrs-<nonce>\stop.request", [byte[]]@())
```

El servicio: termina el epoch en curso, drena supervisores (tope 1800 s),
completa la transiciÃ³n pendiente (rebind del Ã¡rbitro), sella el Ãºltimo
segmento, verifica el conjunto canÃ³nico contra el orÃ¡culo raw (Rust +
Python, identidad PASS obligatoria) y escribe `service-terminal.json` con
estado honesto (`PASS` / `CAPTURE_COMPLETE_WITH_EXPLICIT_GAPS` /
`CAPTURE_COMPLETE_WITH_OBSERVABILITY_FAILURES`). Los procesos quedan en un
Job Object kill-on-close; el `finally` garantiza la limpieza.

## 5. Reinicio / recuperaciÃ³n

Un reinicio es simplemente un nuevo `-Mode Continuous` con un nuevo
`hrs-<nonce>` (nueva raÃ­z, nuevo mutex). La recuperaciÃ³n AUTOMÃTICA dentro
de una corrida cubre:

- Ã¡rbitro caÃ­do â†’ `LIVE_ARBITRATION_EXITED_EARLY` + relanzamiento con
  `--resume` (segmento nuevo encadena `ARBITRATION_RESUMED` con
  `previous_journal_sha256` + `trade_floor` + `previous_tail_bytes`);
- supervisor de sÃ­mbolo caÃ­do â†’ `OUTER_GAP_OPENED/CLOSED` + backoff; el
  sucesor planificado se promueve sin gap;
- evaluador colgado â†’ terminaciÃ³n al deadline monotÃ³nico,
  `LIVE_ARBITRATION_AUDIT_TIMEOUT`; el auditor se limpia tambiÃ©n cuando
  muere su Ã¡rbitro;
- disco bajo la reserva (100 GiB) â†’ `STORAGE_SAFE_STOP_REQUESTED` + parada
  segura evidenciada; nunca se borra raw automÃ¡ticamente.

## 6. Cuarentena / degradaciÃ³n de la vista derivada

Si la vista canÃ³nica no se puede probar (conflicto tipado, gap no puenteable,
verificaciÃ³n fallida), el Ã¡rbitro falla cerrado: deja de publicar, escribe el
evento tipado y sale no-cero. El raw sigue capturando. La promociÃ³n de una
ventana exige el orÃ¡culo `oracle_identity=PASS` en AMBOS verificadores;
`SKIPPED`, timeout o auditorÃ­a pendiente nunca promueve.

## 7. RetenciÃ³n / discos / observadores

- Reserva persistente: 100 GiB; preflight valida espacio proyectado con
  factor de seguridad.
- Sin borrado automÃ¡tico de raw; la polÃ­tica de retenciÃ³n la decide el
  operador fuera del servicio.
- Kernel ETW + network witness: deadline por epoch (rotaciÃ³n), evidencia
  sellada por ventana; en corridas de prueba no elevadas el terminal registra
  `SKIPPED_NOT_ELEVATED` honesto (el gate elevado queda OPEN).

## 8. Upgrades

Congelar fuentes â†’ build release completo (`cargo build --release -p
lob-replay --bin hot_redundant_capture --bin hot_redundant_verify --bin
raw_campaign --bin segmented_capture --bin campaign_verify --bin
kernel_network_trace --bin live_arbitration --bin live_arbitration_verify`)
â†’ suites Rust/Python completas â†’ fmt/clippy â†’ gates live/launcher/fault con
ESOS binarios â†’ nuevo manifiesto con hashes. Cambiar algo despuÃ©s invalida
los gates afectados: repetirlos.

## 9. LÃ­mites honestos

- Un evento perdido por AMBOS lanes no es demostrable sin un tercer testigo
  que Binance no ofrece sin credenciales (acotaciÃ³n del contrato).
- Soak real 24 h / 7 d: gate de tiempo real, aparte de la preparaciÃ³n.
- Kernel ETW elevado: requiere consola elevada (gate explÃ­cito).
- VerificaciÃ³n orÃ¡culo completa de una ventana de 24 h: decenas de minutos
  (digest de libro completo por frame); las verificaciones por epoch usan el
  modo acotado `--tail-segment-only`.
