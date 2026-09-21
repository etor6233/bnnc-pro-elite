# Aeron IPC One-Way Latency Demo — Measured Results

This document reports a real, locally executed Aeron IPC latency measurement.
Every number below was produced by an actual run on this Windows host; nothing is
extrapolated or simulated.

## 1. Scope

A one-way publish-to-receive latency measurement over Aeron IPC (`aeron:ipc`),
which is a shared-memory transport between processes on the same host. It is a
local transport demo only: it does not exercise a network interface, UDP, or
RDMA, and the results must not be read as network or RDMA latencies.

## 2. Configuration

| Parameter | Value |
|-----------|-------|
| Channel | `aeron:ipc` |
| Stream ID | `1001` |
| Payload size | 32 bytes (8-byte little-endian publish timestamp + 24 bytes zero padding) |
| Messages (`M`) | 1,000,000 |
| Timestamp source | `System.nanoTime()` written little-endian into the first 8 bytes |
| Publisher idle strategy | `org.agrona.concurrent.BusySpinIdleStrategy` (offer retry loop) |
| Subscriber idle strategy | `org.agrona.concurrent.BusySpinIdleStrategy` (poll loop) |
| Client `Aeron.Context` idle strategy | `BusySpinIdleStrategy` |
| Histogram | `org.HdrHistogram.Histogram(1, 60_000_000_000, 3)` — lowest discernible value 1 ns, highest trackable value 60 s, 3 significant figures |
| Media driver | `io.aeron.driver.MediaDriver` (separate process, `aeron.dir.delete.on.start=true`, `aeron.dir.delete.on.shutdown=true`) |

### JVM

- Runtime: OpenJDK 21.0.11 LTS (Temurin-21.0.11+10), 64-Bit Server VM, mixed mode, sharing.
- Executable: the Temurin JDK 21 installation's `bin\java.exe` (`javac` and
  `jar` in the same directory). The run script resolves the JDK via
  `JAVA_HOME`, `java` on `PATH`, or the standard Eclipse Adoptium install
  locations — no hard-coded machine paths.
- Module flags (required by Aeron 1.53 on JDK 21, taken from the pinned
  `aeron-samples/scripts/java-common.cmd`, captured commit `dad28d2`):
  `--add-opens java.base/jdk.internal.misc=ALL-UNNAMED`
  `--add-opens java.base/java.util.zip=ALL-UNNAMED`

### Machine

- CPU: `Intel(R) Core(TM) Ultra 9 285K` — 24 cores, 24 logical processors,
  reported MaxClockSpeed 3700 MHz (via `Get-CimInstance Win32_Processor`).
- OS: `Microsoft Windows 11 Pro`, version `10.0.26200`, 64-bit
  (via `Get-CimInstance Win32_OperatingSystem`).

## 3. Dependencies (official Maven Central jars)

| Artifact | Version | SHA256 | URL |
|----------|---------|--------|-----|
| `io.aeron:aeron-all` | 1.53.2 | `2F8C1DBBEDF72D791842F311E0158F4BEF51527117C6F22A3A787D7D43A9B29C` | https://repo1.maven.org/maven2/io/aeron/aeron-all/1.53.2/aeron-all-1.53.2.jar |
| `org.hdrhistogram:HdrHistogram` | 2.2.2 | `22D1D4316C4EC13A68B559E98C8256D69071593731DA96136640F864FA14FAD8` | https://repo1.maven.org/maven2/org/hdrhistogram/HdrHistogram/2.2.2/HdrHistogram-2.2.2.jar |

Version selection: `1.53.2` is the highest stable released `aeron-all` version
`<= 1.54.0`, consistent with the captured SNAPSHOT
(`external-review/low-latency-reference/aeron/version.txt` reports
`1.54.0-SNAPSHOT`). The modern Aeron groupId is `io.aeron`; the historical
`uk.co.real-logic:aeron-all` artifact ends at `0.9.4`. `HdrHistogram 2.2.2` is
the latest stable release per `repo1.maven.org` metadata.

## 4. Commands used

The entire demo is re-runnable with a single command (from the repository
root, or any directory — the script resolves its own paths):

```powershell
powershell -ExecutionPolicy Bypass -File "cpp\evidence\10-latency-elite\PHASE3\aeron-ipc\run_aeron_ipc_demo.ps1" -Messages 1000000
```

The script performs, in order: download the two jars only if missing (and write
`jars_manifest.json` with SHA256), compile the adapted sources with JDK 21
javac, start `io.aeron.driver.MediaDriver` in the background, start
`IpcLatencySubscriber` in the background, run `IpcLatencyPublisher` in the
foreground, wait for the subscriber to exit after `M` messages, stop the media
driver, and print `aeron_ipc_results.json`.

## 5. Measured results (1,000,000 messages)

| Metric | Nanoseconds | Human-readable |
|--------|-------------|----------------|
| count | 1,000,000 | 1,000,000 |
| min | 0 | 0 ns |
| p50 | 400 | 400 ns |
| p90 | 491,519 | 491.519 us |
| p99 | 1,370,111 | 1.370111 ms |
| p99.9 | 1,524,735 | 1.524735 ms |
| p99.99 | 1,544,191 | 1.544191 ms |
| max | 1,548,287 | 1.548287 ms |
| mean | 120,069.293 | 120.069 us |
| stddev | 319,965.812 | 319.966 us |

The full percentile distribution is captured in `aeron-ipc/subscriber.log`.

### Interpretation and honesty notes

- The median latency is sub-microsecond (400 ns), confirming the IPC shared-memory
  path is working and fast. About 54% of messages were delivered in `<= 400 ns`.
- `min = 0 ns` is a clock-resolution artifact: for the fastest deliveries, the
  publisher and subscriber `System.nanoTime()` reads returned the same tick, so
  the measured difference is 0 ns.
- The tail (p90 and above) reflects two effects of this measurement design:
  (1) messages are published back-to-back at maximum rate rather than paced, so
  any brief subscriber stall is followed by a backlog drain, and those queued
  messages report queueing delay plus transport time; and (2) the run was made
  on a live host while other services were running (these were intentionally not
  stopped), so the OS scheduler contributes context-switch and cache-migration
  stalls in the tail.
- This is a one-way, throughput-saturated, shared-memory local transport
  measurement. It is not a network measurement, and it is not a round-trip or
  RDMA measurement.

## 6. Source attribution

`src/IpcLatencyPublisher.java` and `src/IpcLatencySubscriber.java` are adapted
from the captured Aeron samples `BasicPublisher.java` and `BasicSubscriber.java`
(`io.aeron:aeron`, Apache-2.0, Copyright 2014-2025 Real Logic Limited), captured
commit `dad28d2` in `external-review/low-latency-reference/aeron`. Each file
carries the required attribution comment at the top.
