# Representative 24-hour raw endurance qualification

This runbook governs `ENDURANCE_24H` in
[`CaptureCampaignPolicyV1`](../docs/CAPTURE_CAMPAIGN_POLICY_V1.md). It captures
only public Binance Spot `BTCUSDT` and `ETHUSDT` data. Credentials and order
entry are absent.

## Authorized components

- launcher/guardian: `scripts/run_24h_raw_qualification.ps1`;
- read-only monitor: `scripts/monitor_24h_raw_qualification.ps1`;
- Windows lifecycle primitives: `scripts/RawQualification.Windows.ps1`;
- independent guardian watchdog: `scripts/RawQualification.Watchdog.ps1`;
- bounded host probe: `scripts/RawQualification.TelemetryProbe.ps1`;
- bounded Python runtime fingerprint helper:
  `scripts/RawQualification.PythonRuntimeFingerprint.ps1`;
- build inputs: `target/release/raw_campaign.exe`,
  `target/release/segmented_capture.exe` and
  `target/release/campaign_verify.exe`;
- executed bytes: verified copies under the run's `sealed-runtime/bin`;
- terminal Python oracle (minimum): `binance_lob.raw_verify_cli`, executed only
  from the run's sealed source tree.

The old `scripts/run_24h_qualification.ps1` and canonical/feature prototypes are
not authorized for this gate.

## Fixed production topology

- campaign duration: `86400 s`;
- raw segment: `900 s`, without reconnect;
- planned candidate: absolute campaign slot `82800 s` (23 h), without
  accumulated REST/TLS/proof drift;
- overlap: `900 s`;
- predecessor: capture has the guarded planned duration
  `rotation + overlap - min(30 s, max(1 s, overlap/10))`, then terminally seals
  and drains; the guard ensures B's normal root-segment seal occurs strictly
  after A's terminal durable boundary, and completion is not triggered by the
  proof;
- handover proof: after A is terminal, it is recomputed retrospectively from the
  immutable A/B overlap. Only a valid durable proof permits B promotion;
- successor: continues capturing while the proof is derived and, after valid
  promotion, remains active through campaign end;
- repeated stress rotations launch their transport at immutable absolute slots;
  at most one later generation may be warm without supervisor authority while
  the preceding handover is proven. After promotion it must be transferred by
  one exact `CANDIDATE_REGISTERED` event before it can become a candidate;
- when the final successor would otherwise stop at its first root-segment seal,
  it retains at most 90 seconds of post-horizon capture (also bounded by the
  normal maximum generation duration). This tail is evidence-only, does not
  extend or repair the qualified freshness horizon, and leaves 30 seconds of the
  launcher's 120-second terminal budget for final publication;
- unexpected failure or unproven handover: terminal failure, exact evidence
  retained, no inferred continuity.
- production terminal verification: fixed at `43200 s` per independent
  verifier process and `86400 s` for the complete sequential post-capture
  verification stage. These are verification budgets, not additional capture
  time, and Production rejects any override.

The 23-hour threshold is a project margin, not an exchange guarantee.
`serverShutdown` starts one immediate candidate. Connection age, segment age and
campaign age use separate monotonic counters.

## Mandatory promotion order

1. Rust format/tests/clippy and Python tests;
2. source/config/executable locks;
3. isolated public child-process failure propagation;
4. short dual-symbol guardian smoke with exactly 2 generations, 1 proven
   handover and zero `serverShutdown` paths per symbol;
5. 120-minute dual-symbol stress with planned rotation slots and raw segment
   boundaries every 15 minutes;
6. exactly 8 generations, 7 proven handovers, 8 planned launches and zero
   `serverShutdown` paths per symbol in that stress;
7. independent Rust and Python verification of every completed stress campaign;
8. only then this 24-hour run.

Failure at any step preserves evidence and blocks the next step.
The declared 120-minute and 24-hour values are capture durations. Drain,
terminal commit and four independent verifier processes follow afterward; an
operator must wait for the exact terminal artifact and never infer PASS from the
capture deadline or process exit alone.

Before the short smoke, run the real retained-handle fault gate:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File .\scripts\run_raw_fault_gate.ps1 -OutputBase artifacts/fg
```

Promotion is allowed only when the command exits successfully and its canonical
`fault-evidence.json` validates as `RawQualificationFaultEvidenceV3` with the
typed coordinator-stderr receipt. A `fault-gate-failure.json` receipt, absent
PASS artifact, stderr mismatch, unexpected exit or cleanup residue blocks every
later campaign.

The V3 fault-evidence names are relative to the fault harness: `outer_job_*` is
the harness enclosure, `inner_job_*` is the qualification launcher's outer Job
nested inside that enclosure, and `workload_job_*` is the launcher's inner
Workload Job. Both qualification Jobs must be absent with Win32 open error 2
before PASS publication; the harness outer Job must report zero active members.

Each terminal fault-gate process census is one bounded `Win32_Process` snapshot,
reused for retained-PID absence, engine, verifier and exact run-root checks. The
run-root predicate applies ordinal-ignore-case `IndexOf` to the command-line
string itself; casting the numeric `IndexOf` result is forbidden because Windows
PowerShell 5.1 would compare `"-1"` as a string. Candidate failures preserve
sanitized PID/parent/name/creation and command/image-path digests. While the
original process handles remain retained, PID reuse is impossible: any CIM row
with that PID is a contradiction or identity inconsistency, never an accepted
reuse. The whole bounded census is repeated after `EVIDENCE_PROPOSED`; these are
two exact observations, not a claim of continuous global absence.

## Exact public smoke

Preflight and execute the short dual-symbol topology with the same arguments:

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File .\scripts\run_24h_raw_qualification.ps1 `
  -Mode Smoke -TotalSeconds 120 -RotationSeconds 60 `
  -OverlapSeconds 10 -SegmentSeconds 10 `
  -OutputBase artifacts\qualification-smoke-120s-v7 `
  -StartupDeadlineSeconds 180 -PostVerificationDeadlineSeconds 900 `
  -IndependentVerifierTimeoutSeconds 300 -ValidateOnly

powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File .\scripts\run_24h_raw_qualification.ps1 `
  -Mode Smoke -TotalSeconds 120 -RotationSeconds 60 `
  -OverlapSeconds 10 -SegmentSeconds 10 `
  -OutputBase artifacts\qualification-smoke-120s-v7 `
  -StartupDeadlineSeconds 180 -PostVerificationDeadlineSeconds 900 `
  -IndependentVerifierTimeoutSeconds 300
```

Terminal promotion requires, independently for BTCUSDT and ETHUSDT, exactly two
generations, one proven handover, two planned generation launches and zero
`serverShutdown` event, durable-event and generation-launch paths. Both
coordinator stderr files and all child-stderr event counts must be empty/zero,
both coordinator exit codes must be zero, and the Rust and Python terminal
oracles must independently accept each exact campaign. `Mode Smoke` is fixed to
these parameters, and both launcher and monitor enforce this topology before a
terminal `COMPLETE` can be accepted.

## Exact accelerated rotation stress

This is continuous public capture. Fifteen minutes is both a transport-rotation
stress interval and a raw file boundary; it is not sampling, a training block or
a market transformation.

```powershell
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File .\scripts\run_24h_raw_qualification.ps1 `
  -Mode Test -TotalSeconds 7200 -RotationSeconds 900 `
  -OverlapSeconds 900 -SegmentSeconds 900 `
  -OutputBase artifacts\qualification-rotation-stress-120m-v8 `
  -StartupDeadlineSeconds 180 -PostVerificationDeadlineSeconds 14400 `
  -IndependentVerifierTimeoutSeconds 7200 -ValidateOnly

powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File .\scripts\run_24h_raw_qualification.ps1 `
  -Mode Test -TotalSeconds 7200 -RotationSeconds 900 `
  -OverlapSeconds 900 -SegmentSeconds 900 `
  -OutputBase artifacts\qualification-rotation-stress-120m-v8 `
  -StartupDeadlineSeconds 180 -PostVerificationDeadlineSeconds 14400 `
  -IndependentVerifierTimeoutSeconds 7200
```

Terminal promotion requires, independently for each symbol, exactly eight
generations, seven proven handovers, eight planned generation launches and zero
`serverShutdown` event, durable-event and generation-launch paths. It also
requires clean coordinator exits and stderr, the exact `RawCampaignManifestV1`
parameters, and two successful independent terminal oracles per campaign. The
exact `Test` parameter tuple above activates the mandatory
`ROTATION_STRESS_120M` topology in both launcher and monitor; other ad-hoc Test
durations cannot be mistaken for this promotion gate.

## Preflight

Run as an elevated 64-bit Windows PowerShell when service/clock configuration
requires it. The guardian itself verifies:

- AC sleep disabled and a system execution-state request successfully armed;
- Windows Time `Leap Indicator = 0`, stratum 1–15 and a non-local source;
- public WebSocket/REST endpoints reachable on TCP 443;
- NTFS output volume with at least the conservative projected reserve and 100
  GiB minimum;
- no conflicting known collector process and one repository mutex owner;
- exact production config, Binance revision, binaries, source lock, scripts and
  Python verifier source digests;
- inventario exacto de los `.py` del verificador en el worktree; caches
  `__pycache__`/`.pyc` del desarrollo no se ejecutan ni integran ese digest;
- bundle `sealed-runtime` creado con bytes verificados dentro del run: binarios,
  configuration and a Python source-only tree without any cache; coordinators and
  oracles run exclusively from that bundle;
- a sealed, minimal child-environment allowlist block:
  `SystemDrive,SystemRoot,TEMP,TMP,WINDIR`; los coordinadores y oracles no
  heredan el entorno completo del usuario. `SystemDrive` evita que componentes
  de Windows expandan `%SystemDrive%` literalmente bajo el directorio de trabajo.

Read-only production preflight:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\run_24h_raw_qualification.ps1 -Mode Production -ValidateOnly
```

## Launch

Launch from an operator-owned foreground PowerShell window and leave that window
open. Do not launch this 24-hour gate from a transient chat/agent command,
browser task or remote shell whose own disconnect owns the process lifetime. A
chat or browser disconnect then has no effect on the local guardian. Closing the
PowerShell window, logging off, rebooting, sleeping or terminating the guardian
does affect the run and must remain a fail-closed event.

Do not override production timings or verifier budgets:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\run_24h_raw_qualification.ps1 -Mode Production
```

An actual host Internet outage is materially different from a chat disconnect.
If either active Binance depth/trade transport is lost, the campaign records
`GENERATION_DISCONNECT_FAIL_CLOSED`, preserves its acknowledged raw prefix and
cannot become `COMPLETE`. Do not reconnect inside the same epoch, fill depth
from REST or concatenate across the missing interval. After connectivity is
restored, a new command creates a new campaign/epoch; the failed interval stays
explicit evidence. This follows Binance's official rule to discard and rebuild
the local book after missed diff-depth events.

The launcher creates one new common run root, samples the host monotonic clock
and creates two distinct named Jobs bound by
`RawQualificationProcessControlV2`:

- the outer kill-on-close Job contains the watchdog plus every campaign
  workload and bounded host probe;
- the inner kill-on-close Workload Job contains BTC/ETH coordinators, captures,
  terminal Rust/Python verifiers and all their descendants, but never the
  watchdog or host probes.

The watchdog is assigned only to the outer Job, retains the exact
guardian-pulse file identity, rechecks its startup deadline and durably
publishes `watchdog-ready.json`. The launcher validates that READY payload, its
QPC origin/deadline, pulse prefix and live process identity before it may start
either market coordinator. Host probes remain outer-only and use their own
bounded child containment.

BTC and ETH coordinators use
`CREATE_SUSPENDED_ASSIGN_OUTER_AND_WORKLOAD_JOBS_RESUME`: they are created
suspended, assigned root-to-leaf to the outer Job and then the Workload Job, and
resumed only after both assignments succeed. Terminal verifiers use the same
dual assignment. The launcher records exact PID, creation time, executable
path/hash and command line. Closing or crashing the guardian, or any
qualification failure, terminates the outer Job and therefore the complete
contained tree; it cannot leave an apparently healthy collector detached from
supervision.

The two coordinator launch instants are measured with the same host monotonic
clock and must be no more than five seconds apart. The exact skew and both
launch ticks are persisted and checked again by the monitor; exceeding that
bound fails closed instead of silently shortening one symbol's capture.

The campaign clock starts only after both coordinators have been launched; host
preflight time cannot consume capture duration. At the deadline the launcher
uses separate monotonic terminal stages: up to 120 seconds for every child
`PROCESS_TERMINAL` plus `GENERATION_EXITED`, then up to 1800 seconds for the
coordinator's terminal rescan/commit. Independent Rust/Python oracle execution
has its own bounded budget and cannot be reported as live capture.

## Live health

Use the run root printed by `READY`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `
  .\scripts\monitor_24h_raw_qualification.ps1 -RunRoot <run-root>
```

`HEALTHY_RUNNING` requires all of the following, not merely live PIDs:

- the exact hash-bound watchdog READY handshake and retained pulse identity;
- exact guardian and BTC/ETH process identities;
- fresh hash-chained campaign heartbeats;
- both depth/trade transports connected and snapshot durable;
- monotonic received/durable counters with no reported failure;
- fresh hash-chained host telemetry, healthy clock and storage reserve;
- exact source/config/binary/script digests still present.

The monitor validates the semantics of every retained launcher, guardian-pulse
and host-telemetry record, not only the newest one. A later healthy sample
cannot hide an earlier unhealthy clock, insufficient reserve, invalid stage or
monotonic regression.

Cada lectura live congela primero un prefijo exacto del journal; nunca mezcla
bytes anexados durante el scan. Las sondas de clock, contadores, CIM y red
tienen deadlines duros, y un watchdog independiente termina el Job si el
guardian heartbeat stops advancing.

The watchdog retains one open file identity for the guardian pulse and requires
newline-complete, strictly increasing byte length within a local monotonic
deadline. Wall-clock timestamps, touching the file, truncation or path
replacement cannot manufacture freshness; any such condition fences the Job.

The first observation after launch must be repeated for several minutes. The
operator records the same run root and checks that both symbols' depth and trade
counters advance, durable counts do not regress, telemetry records grow and no
new failure/terminal artifact exists.

## Terminal PASS

Process exit never implies success. After both exact retained-handle coordinator
exit observations have been durably published, the guardian applies
`RawQualificationCoordinatorWorkloadJobDrainV3` to the inner Workload Job only
(`INNER_WORKLOAD_ONLY`). Starting at the later exit-observation tick, bounded
queries must show a monotonic non-increasing active-process count and exactly
zero members within 10 monotonic seconds. Retained-handle observations before
and after the final query must independently prove that the watchdog remains
alive in the outer Job. The receipt result is exactly
`WORKLOAD_EMPTY_WATCHDOG_ALIVE`. A nonzero terminal count, count increase,
watchdog exit, query ambiguity or deadline excess fails closed.
Only after that receipt is durable does the guardian check every raw generation
and clock record and run both independent oracles over each frozen campaign
directory:

- Rust `campaign_verify.exe`;
- the hash-bound project Python environment and `binance_lob.raw_verify_cli`.

Both exit codes must be zero. Their stdout/stderr/reports and SHA-256 digests are
stored outside the exact campaign inventory and bound by
`launcher-terminal.json`.

Every terminal condition is timestamped when observed and is accepted only
after proving that observation remained inside its monotonic deadline. Once an
exact clean-exit proof is durable, later Windows PID reuse by an unrelated
process neither revokes nor fabricates that proof; a still-live original process
identity remains a contradiction.

`CAMPAIGN_PROCESS_EXITED.body.exit_observed_monotonic_tick` is the conservative
QPC observation taken after the retained process handle reports exit; Windows
does not supply the physical termination QPC here. It is used for elapsed and
deadline arithmetic. The enclosing journal `monotonic_tick` is the still-later
durable publication instant. They are deliberately distinct and causally
ordered; backdating publication to the exit observation is forbidden. The V3
Workload-drain origin is the maximum of the two coordinator observation ticks,
while its final Workload query and watchdog-liveness observation occur after
both exit publications.

A `COMPLETE` exit additionally requires empty stderr, logs within limits, clean
exact output of both coordinators (PID, elapsed and zero code), the V3 receipt
proving `Workload=0` with the watchdog still alive before starting the
oracles, and a final re-read of sizes/hashes. Each oracle is assigned to both
Jobs y sus descendientes deben drenar el Workload de vuelta a cero, con el
watchdog vivo. Tras los cuatro oracles, una consulta inmediata vuelve a exigir
`Workload=0`. Only then does the guardian durably publish `STOP`; the watchdog
sale limpiamente y el Job exterior debe drenar a cero antes de publicar
`COMPLETE`. La cardinalidad del Job exterior nunca se usa como prueba de
identidad del watchdog.

Final `COMPLETE` additionally requires:

- exact `RawCampaignManifestV1` parameters and zero supervisor gaps;
- every generation terminally sealed with clean durable prefixes;
- `received == durable > 0`, zero local drops and no unbound artifact;
- exactly one planned A/B handover per symbol for the 24-hour topology;
- each stored proof independently recomputed from the terminal raw A/B bytes;
- monotonic lifecycle coverage from bounded first startup through the 24-hour
  deadline, with B started before A terminates;
- no ambiguous clock telemetry record;
- launcher/source/config/executable/verifier digests unchanged across the run;
- final hash-linked launcher and host journals.

Any mismatch writes `FAILED` when possible and is never promoted by globbing
files into another dataset.

## Meaning of the result

A 24-hour `COMPLETE` proves an engineering endurance gate and one representative
near-deadline rotation. Only after terminal verification may its raws be
considered a valid campaign input for a future dataset release. It does not
prove market-regime coverage, execution quality, edge or profitability. The
next reliability gate is seven continuous days.

## Representative run of 2026-08-27/28

The run
`artifacts/qualification-24h-raw/20260827T141854Z-dual-97de6baf0974`
completed the market-data portion correctly for both symbols: each campaign
committed two generations, one planned proven handover, zero supervisor gaps,
zero `serverShutdown` paths and zero stderr. Rust and Python independently
accepted both immutable campaign trees. The exact depth boundary advanced by
one update ID at each handover and the raw trade overlaps were retained as
evidence.

The enclosing launcher nevertheless remained `FAILED`, and is never promoted,
because its old provenance check reread the mutable development source tree
after verification. Unrelated `.pyc` caches had appeared there even though all
21 `.py` bytes were unchanged. The corrected launcher now executes and
terminally rechecks a source-only `sealed-runtime` inside the run. The sealed
bundle has been exercised with a real public two-generation handover and both
independent verifiers, and the deterministic fault/security suites pass. A
fresh smoke is still mandatory because source changes never retroactively
promote historical evidence.

Terminal verification on that run was deliberately exhaustive: Rust took
473.490 s/359.141 s and Python took 1218.261 s/695.451 s for BTCUSDT/ETHUSDT.
This first full scan is an integrity oracle, not the optimized research replay
path. Continuous collection must therefore remain independent of closed-window
verification; a cached replay index may accelerate later reads but may never
replace the initial byte/hash validation.

## Qualified current-source 120-minute gate

The mandatory accelerated gate completed at
`artifacts/qualification-rotation-stress-120m-v8/20260826T010327Z-dual-f3caeb4b9c30`.
The launcher exited zero and its terminal is `COMPLETE` with SHA-256
`dbece5a46155febbe13a068275b3c0fab1ab99f9bff9bff999cb6353e725273b`.
Both symbols completed exactly eight planned generations and seven proven
handovers. The subsequent read-only monitor returned `COMPLETE`, reported zero
schedule deviations and independently reverified the current bytes with fresh
Rust and Python processes for BTCUSDT and ETHUSDT. Its current-byte campaign
verification SHA-256 values are
`8a9e0e9c86d61755b430db011cc3960fa3ad4c491432cf91581fc3583e0955a0`
for BTCUSDT and
`124fab1bc2853c06c19bf34fac30c3acc81e8c22bd905f9dc943e11bc9615e9a`
for ETHUSDT. The retained-handle public fault gate for the same current launcher
and monitor hashes is
`artifacts/fg/f-0f066748ccc74c00/fault-evidence.json`, with canonical record
SHA-256
`c05c6c387053c88bedf7153318f27a776213882b208c3f29d692265781511b28`.
This authorizes the 24-hour production-mode engineering endurance run; only that
run's own terminal result can qualify its captured data.

## Preserved early representative attempt

The production-mode campaign started at `2026-08-26T00:37:01Z` in
`artifacts/qualification-24h-raw/20260826T003701Z-dual-f0a04917f102`.
Its visible persistent PowerShell guardian PID at launch was `20776`; BTCUSDT
coordinator PID was `26844` and ETHUSDT coordinator PID was `50780`. The sealed
launcher-startup SHA-256 is
`553726f03aedd8c82e28c877c9b327b3e6fac2e7fe65a653b1441c27c16e9eb5`
and campaign-bindings SHA-256 is
`d7d82cef6f79b90c13fac0abd07806d94897edf08ff15cd3a5ed999d7e4974cb`.
Independent read-only monitor observations at approximately 35 and 287 capture
seconds both returned `HEALTHY_RUNNING`, `CAPTURING`, with zero schedule
deviations and advancing durable depth/trade counters for both symbols. The run
was then deliberately stopped and all four exact processes drained to zero
after measured 120-minute verifier throughput showed that the former
`7200 s`/`14400 s` Production verification budgets could falsely time out an
otherwise valid 24-hour capture. It is preserved as an early, non-promotable
attempt. Production now fixes `43200 s` per verifier and `86400 s` total; this
attempt can never be retroactively promoted.

## Preserved failed attempt

`artifacts/qualification-24h/20260823T184009Z-dual` is rejected: it stopped
receiving after about 23 minutes while processes remained alive. Its bytes are
retained only as failed evidence. Root cause and hashes are recorded in
`benchmarks/2026-08-23-false-liveness-24h-attempt.json`.

`artifacts/qualification-smoke-120s-final/20260824T223858Z-dual-9a7425bff766`
is also rejected as promotion evidence. Both raw campaigns reached their own
complete manifests, but the enclosing launcher failed while evaluating the Job
drain because Windows PowerShell 5.1 parsed a function-call subtraction as
command arguments. The artifacts are retained; current source must pass fresh
gates and must never retroactively promote this attempt.

`artifacts/qualification-smoke-120s-v2/20260825T000512Z-dual-dd73e1c32434`
is rejected as promotion evidence as well. BTCUSDT and ETHUSDT both reached
their own `COMPLETE` manifests without detected raw corruption, but enclosing
launcher finalization failed because it incorrectly required the outer Job to
drain to one exact watchdog. The preserved terminal SHA-256 is
`3f15c3d9e5e3267f43532b65dc0516495e018f1e974b20622cd4bcb5fd56838b`;
the preserved containment SHA-256 is
`0f2774718e888225d41a6e8b2301022c9c68e049b0f3b4f70543a3ae9ec159dc`.
It was not promoted and cannot be retroactively promoted by the corrected
outer/Workload topology.

`artifacts/watchdog-only-82b28d25af3e479b9a8a779bbbea1ad2` is retained only
as a non-authoritative watchdog diagnostic. It demonstrated that outer-Job
cardinality is not an exact watchdog identity assertion, but it has no signed
exact PID census and cannot satisfy or replace any promotion gate.

`artifacts/qualification-smoke-120s-v3/20260825T010617Z-dual-6d9031247659`
is rejected too. Both campaign manifests reached `COMPLETE` with two generations
and one handover, but a same-poll launcher calculation subtracted a pre-read QPC
tick from the later terminal-evaluation origin and failed closed at `-403` ticks
(`40.3` microseconds at 10 MHz). Therefore no Workload drain or independent
verification qualified the enclosing run. Its launcher-terminal SHA-256 is
`cb74e16bcec05afec0d5aa562d1a65fa56a5f4ff7c957067deeae2414ce78fae`;
its containment SHA-256 is
`a3e729e16190edab67535a71863ac40898650775fcc9508d7c3f8ce0f8a7a1e4`.
Containment drained four processes to zero. The artifacts remain failed evidence
and cannot be promoted by later source corrections.

`artifacts/qualification-smoke-120s-v4/20260825T012844Z-dual-ef8feac92ccf`
is also rejected. Both campaigns completed with exact 2/1 topology and zero
gaps, the Workload V3 drain reached zero, and all four Rust/Python verifier
processes exited zero with empty stderr. Publication of COMPLETE then failed
closed because Windows PowerShell 5.1 coerced explicit `$null` failure arguments
to `""` through nullable `[string]` parameters. The authoritative FAILED
launcher-terminal SHA-256 is
`5a4af2b1ae30dbf1bb4c27c4038fd433cb2c9e142b2ec126437eb2431c54b558`;
the independently recomputed containment SHA-256 is
`4a833e067100ae7142c19d9f7d85616240f3809ee0e66e02fad52c96ef5b1f13`,
with outer containment from two processes to zero. A near-terminal monitor read
also exposed a separate telemetry-versus-FSM phase race and therefore was not
accepted. Preserve the complete run directory, but never promote it
retroactively.

`artifacts/qualification-smoke-120s-v5/20260825T031821Z-dual-8c777c081d65`
is rejected as well. Both campaigns completed with exact 2/1 topology, zero
gaps and four successful independent verifiers; the Workload Job drained to
zero before and after verification. The clean watchdog stop then exposed that
Windows PowerShell 5.1 treats the C# launch result's `ProcessHandle` property as
read-only: the native handle was closed, but the subsequent PowerShell-side
attempt to replace it with zero threw before `GUARDIAN_WATCHDOG_STOPPED` and
before a COMPLETE terminal could be committed. The authoritative FAILED
launcher-terminal SHA-256 is
`4a9b4e5a852224acbc9acd01904234f73f36cf7a869b2f28c5a2c90f77a1c818`;
the independently recomputed embedded containment SHA-256 is
`073c35b7da8b417c42c9dfd0ffe6f10eaa4078d2a9c31c6cc615c881a1b245c1`,
and the stop request SHA-256 is
`5300ab871cc4f1dc90f485b8f3e51b558e597a1a9b0f7aeae2b607a6eea2bc3d`.
Containment observed zero outer-Job processes before and after fencing. The
source correction cannot retroactively promote this run; the next smoke uses a
new evidence namespace.

`artifacts/qualification-smoke-120s-v6/20260825T033643Z-dual-d91eb85c8a53`
is preserved as non-promotable monitor-regression evidence. Its launcher did
publish a coherent COMPLETE terminal (SHA-256
`3a8edf805a66ba145b1d1cd1e17a5dc2a08caeba05c20770ca7968d5eafc3ccf`):
both symbols completed the exact 2/1 topology, all four independent verifiers
exited zero with empty stderr, the watchdog exited zero and both Jobs were
absent afterward. The mandatory post-terminal monitor nevertheless rejected
the run because Windows PowerShell 5.1 evaluated
`@($symbol + "-rust", $symbol + "-python")` as one space-joined string rather
than two array elements. The monitor source was corrected to construct an
explicit two-element `string[]` and to compare identities case-sensitively.
Because v6 sealed the prior monitor SHA-256
`34520c42c263f41a38961cabd288e28d5b5c695dd864a562ed04dd388b9350bf`,
it cannot qualify corrected source; a fresh namespace is mandatory.

`artifacts/qualification-rotation-stress-120m-v3/20260825T040030Z-dual-17183416e208`
is a failed environmental stress attempt and is never promotable. At 955
capture seconds, after both symbols had launched their second planned
generation, bounded host probe `host-000032` observed Windows Time
`Last Sync Error: 2` (only stale time data available). The launcher failed
closed before any handover or independent terminal verification and drained
the outer Job from ten active processes to zero. Its authoritative FAILED
terminal SHA-256 is
`3ce40795ca92a124767f7f489a4c8bf956a2ffaf98cd8b3ff2216cdfa4dd6b57`;
the exact host-probe stderr SHA-256 is
`5696f2ef34717b75c5df18326f4d77614ede42930c03dcefbd8efae3d04da8ff`.
The next stress requires an error-free, deliberately qualified host clock and
uses a new evidence namespace; source correction cannot promote this attempt.

`artifacts/fg/f-4cc1a872453445a6/fault-evidence.json` is retained as a
non-promotable diagnostic. The V3 harness proved the injected termination and
complete Job containment and published record SHA-256
`a3b7612a0af44b2f1c741f43433fa5aefe3b2cd611fef6e651b00920f3196664`.
The launcher nevertheless reported a terminal-publication acknowledgement
error: PowerShell 5.1 emitted a standalone `$null` pipeline item before the
returned `FAILED` string, and the exact typed ACK check rejected the two-item
output. Terminal SHA-256
`7f0a9570b8d4aa750ba8d287cd29c952c05c3bd02eaed56ea70634d5daa814c9`
and containment SHA-256
`7754dd6f61e493d5bea8f5ac11409769f4d5ceeab316324768822b07bbc5e41c`
remain immutable evidence; fresh gates on corrected source are mandatory.

## Telemetry concurrency incident and correction — 2026-08-27

`artifacts/qualification-24h-raw/20260826T162502Z-dual-f4797a82dd96`
is failed and permanently non-promotable. At BTCUSDT telemetry record `8111`,
`trade_last_socket_activity_mono_ns=40721747600700` was published against
`mono_ns=40721747599600`: the socket observation exceeded its heartbeat by
exactly `1,100 ns`. Windows recorded no suspend/resume event; guardian and host
telemetry also remained continuous. The cause was local: `mono_ns` was sampled
before concurrently updated atomics. The coordinator correctly failed closed,
requested a session-bound stop and the launcher contained both campaigns. Its
authoritative launcher-terminal SHA-256 is
`d095aec9613c7dead1f8e1b3109850f96cd2b912f9008d41fe4ea313fb950134`.

The correction does not add a timing tolerance. The producer now publishes the
receipt counter before writer handoff; telemetry loads causal facts in
invariant-preserving order and samples `mono_ns` only after the complete
observation. A producer-side validator refuses to persist any record violating
`durable <= written <= received`, `market <= socket <= observation` or
`last_durable <= observation` bounds. A concurrent 100,000
snapshot regression test exercises these relationships. The Python raw reader
now recognizes the exact Windows clock-quality value while preserving
`permits_one_way_claim == false`; unknown values remain rejected. Nested Python
CLI tests use `-B`, so tests cannot contaminate the source-only verifier tree.

`artifacts/qualification-telemetry-fix-final-smoke/20260827T140518Z-dual-deb4c226083e`
is the fresh final-source smoke evidence. The launcher terminal is `COMPLETE`
with SHA-256
`e510e4c7f47c5ac24215a4fc838adcb56acb54291c915b94a38a8bb60b409ccf`:
BTCUSDT and ETHUSDT each completed two generations and one proven handover,
all stderr files are empty, all 56 telemetry records satisfy the causal
invariants, both Rust/Python current-byte verifiers passed, and the independent
read-only monitor returned `COMPLETE`. This smoke qualifies the correction for
a fresh endurance attempt; it does not retroactively promote the failed
11-hour run or replace the required 24-hour gate.

`artifacts/fg/f-c7b7e0570e2f480e/fault-evidence.json` is an internally valid
historical `PASS` for launcher
`79b64f6875fc23d820720b61d629c26cb02bb4ddb0b7e2db678d8fe5a6955300`
and monitor
`9386cedeb99b19f68fed63a0828394793c17e1d9e8dc125d8c1ba371bf79d31f`.
Later schedule/topology hardening changed those source bytes, so this evidence
is preserved but cannot qualify the current source set. Promotion requires a
fresh fault gate whose retained bindings equal the final current hashes.

## Active endurance monitor scalability observation - 2026-08-28

The active endurance namespace
`artifacts/qualification-24h-raw/20260827T141854Z-dual-97de6baf0974`
must remain untouched until its launcher becomes terminal. During capture, a
read-only full monitor pass spent several minutes replaying the growing
campaign journals and then rejected generation 0 as stale. Immediate bounded
tail evidence showed both coordinators still publishing every five seconds,
guardian stage `CAPTURING`, both processes active and all three stderr files at
zero bytes. Therefore that one monitor result is not evidence of a capture gap;
it exposes that a from-zero audit can consume its own 30-second freshness
linearization window as history grows.

No pinned launcher/monitor source is changed during this active run. After the
campaign becomes terminal, the monitor must be corrected and freshly gated by
verifying an authenticated historical prefix once, advancing from its exact
hash/cursor through the concurrent delta, and only then evaluating freshness at
the publication point. Increasing the deadline or accepting a stale heartbeat
is forbidden. Final promotion still requires the authoritative launcher
terminal plus current-byte independent verifiers; lightweight tail checks are
operational observations only.

The current source now implements that correction without changing the
30-second policy. For each live campaign it freezes and fully authenticates the
historical prefix once, retains the exact complete-record index/digest, complete
LF byte boundary/digest, observed file length/digest and lifecycle state, then
parses only the newly appended records. A partial final record is bound by the
observed-file digest and may become authoritative only after its LF arrives and
its next hash-chain record validates. The same incremental barrier runs again
at final linearization. The operational security self-test proves equality with
replay-from-zero across both a clean boundary and a completed partial tail, and
rejects mutations of the observed bytes or continuation cursor. The raw fault
gate also remains green (459 assertions, 308 rejected mutants). These are
source-level gates; a fresh public smoke must still bind and exercise the final
source hashes before any new endurance or seven-day evidence can promote them.

The reproducible read-only benchmark
`benchmarks/2026-08-28-monitor-campaign-journal-incremental-btc-v1.json`
(SHA-256 `0c194e1e11e205c470f6ccff16ad054ec70f0978e06de6098b08c34fc3f4fdc7`)
uses the preserved 24-hour BTCUSDT journal: 19,847,590 bytes and 17,605
records. Replay from byte zero took 33,237.753 ms; seven authenticated
no-growth continuations produced a 17.388 ms median, a measured 1,911.57x
speedup, while retaining the exact terminal digest and lifecycle state. This is
a monitor scalability measurement, not market latency or trading performance.

## Current-source pre-endurance qualification - 2026-08-28

The retained-handle fault gate initially exposed stale build-tree path
assumptions after the launcher had begun executing byte-verified copies from
the per-run `sealed-runtime`. No false PASS was published. The harness now
binds each coordinator and collector to the exact sealed execution path while
independently requiring the SHA-256 of the retained source artifact. A
byte-identical process at the build-tree path or any other path remains
invalid. The corrected self-test passes 461 assertions and rejects 309
mutants. The fresh public gate is
`artifacts/fg/f-ccbc4b97b76548dd/fault-evidence.json`; its file SHA-256 is
`95a2d39e064dc35ba3ab113b464128a251100df0490294ff8f10cd40524ffac5`,
and the embedded evidence record SHA-256 is
`54664aaf2094f918b708ccfa2ef5277bb45af509c6ca8ebc397e4ed53e69943d`.

The exact public smoke
`artifacts/qualification-smoke-120s-v8/20260828T181742Z-dual-f971d148ff3d`
is `COMPLETE`. Its launcher terminal SHA-256 is
`4db242981db3a923fbe500a09303e7579a93ac5f6445aaae7eafae0402d555b3`.
BTCUSDT and ETHUSDT each have exactly two planned
generation launches, two completed generations, one proven handover, zero
`serverShutdown` paths and zero gap/failure events.

The exact accelerated rotation gate
`artifacts/qualification-rotation-stress-120m-v9/20260828T182303Z-dual-9af51bb4e57e`
is `COMPLETE`; launcher terminal SHA-256
`66ff0c650b8b756b0523712ceb17fa80321321c861b933ee9f6ce9c5705bd26f`.
For each symbol it proves eight planned launches, eight completed generations,
seven handovers and zero `serverShutdown` paths. Every stderr artifact is empty.
The retained terminal oracles and a later current-byte monitor reverification
agree exactly on report SHA-256 values:

- BTCUSDT Rust: `2891f80a1345845505e1fa0b4ced61cb3df612122ff7642fd9024ead4b968065`;
- BTCUSDT Python: `062121ff78d9960e756b143dedc627234401cfe16bad14367070e113e1423f20`;
- ETHUSDT Rust: `67354cbcb8d657e8ff592e5750c4a6a38ee527848753d7df884f12e20925d4d7`;
- ETHUSDT Python: `13dd12b718c7e7ddef41986f3333956a44ab6cbf4035c418272b56a97f2e2c09`.

The final read-only monitor returned `COMPLETE`, authenticated the frozen
launcher terminal through its durable post-link, and reran both Rust and Python
against the current campaign bytes. This gate authorizes a fresh 24-hour
Production attempt for the pinned launcher/monitor/capture/verifier source set;
it does not itself qualify an unexecuted 24-hour dataset.
