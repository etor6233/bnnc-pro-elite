# MANIFEST — FASE 4 (kernel-bypass design documentation)

Date: 2026-09-19. Scope: kernel-bypass design documentation (DPDK,
OpenOnload, Machnet). No binary was executed, no hardware was provisioned,
and no external figure was reproduced; every external figure is quoted with
attribution (repository, pinned commit, file).

## 1. Deliverable

| File | SHA-256 |
|---|---|
| `cpp/bench/KERNEL_BYPASS_DESIGN.md` | `8ADD7BE3DDEA98A834141538481CEF5FB988129CA0CE561CDC87E4E34ACE13FA` |

## 2. Elite notes referenced

| File | SHA-256 |
|---|---|
| `COMPUTER_SYSTEMS_PERFORMANCE_LOW_LATENCY.md` (workspace elite note) | `BF5877B347816354CBA255F7565E019883C4375F48BDF7C0BEE32E45BC587ADE` |
| `NETWORKING_DISTRIBUTED_STREAMING.md` (workspace elite note) | `976C96FE70F33408170E64BABDF6B8FCEE69ECDE002613A1A38163BAC43D61B8` |

## 3. Verified capture commits (`git log -1 --format=%H`)

Each capture is an independent git clone under
`external-review/low-latency-reference/`. All three HEADs match the pinned
commits of INDEX.md — no discrepancy.

| Repo | Pinned commit | Verified HEAD | Match |
|---|---|---|---|
| dpdk | 6bbb7b38b17f | 6bbb7b38b17f9ea4c981b5d374612a16833df41e | YES |
| onload (OpenOnload) | 4b4648b360fd | 4b4648b360fda3abd921ec550f26896d58171772 | YES |
| machnet (microsoft) | 877397b94d31 | 877397b94d3131e5e76f0b25b6f2bb5d8a82308f | YES |

## 4. Verbatim Machnet README quote used in the document

Source file inside the capture: `machnet/README.md`, commit
`877397b94d3131e5e76f0b25b6f2bb5d8a82308f`.

The claim (bold as it appears in the source file):

```
Distributed applications like databases and finance can use Machnet as the
networking library to get sub-100 microsecond tail latency at high message
rates, e.g., **750,000 1KB request-reply messages per second on Azure F8s_v2
VMs with 61 microsecond P99.9 round-trip latency**.
```

Context (same file, opening paragraph of the "Machnet: Easy kernel-bypass
messaging between cloud VMs" section):

```
Machnet provides an easy way for applications to reduce their datacenter
networking latency via kernel-bypass (DPDK-based) messaging. Distributed
applications like databases and finance can use Machnet as the networking
library to get sub-100 microsecond tail latency at high message rates, e.g.,
**750,000 1KB request-reply messages per second on Azure F8s_v2 VMs with 61
microsecond P99.9 round-trip latency**. We support a variety of cloud (Azure,
AWS, GCP) and bare-metal platforms, OSs and NICs, evaluated in
docs/PERFORMANCE_REPORT.md.
```

The claim belongs to Machnet's README (Microsoft), not to this repository,
and is presented that way in the design document.

## 5. Sources cited in the document

- `dpdk/README`, `dpdk/doc/guides/linux_gsg/sys_reqs.rst` and
  `dpdk/doc/guides/nics/index.rst` (dpdk capture, commit 6bbb7b38b17f).
- `onload/README.md` (onload capture, commit 4b4648b360fd); GPL-2.0 —
  concept only, no code reuse.
- `machnet/README.md` (machnet capture, commit 877397b94d31); MIT.
- `COMPUTER_SYSTEMS_PERFORMANCE_LOW_LATENCY.md` and
  `NETWORKING_DISTRIBUTED_STREAMING.md` (workspace elite notes).
- `cpp/bench/hdr_histogram.hpp` (this repository's HDR implementation,
  HdrHistogram_c semantics, commit 1343a18908c6) and
  `cpp/evidence/EVIDENCE_05_BENCHMARKS.md` (this repository's measured
  numbers).
