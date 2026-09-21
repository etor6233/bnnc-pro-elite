# Kernel-Bypass Design Reference (PHASE 4)

This document is a design reference only. It records the kernel-bypass
technologies that would be required to drive message-path latency below what
the host kernel networking stack provides, and it documents the pinned external
sources consulted. Nothing in this document was executed on this host: there is
no dedicated DPDK-capable NIC, no Solarflare/AMD adapter, and no Azure DPDK VM
provisioned in this environment. Every number attributed to an external project
is quoted from that project's captured documentation with an explicit
(repository, pinned commit, file) citation; the only measured numbers that
appear here are the ones this repository already produced and published under
`cpp/bench/benchmarks/` (see `evidence/EVIDENCE_05_BENCHMARKS.md`).

Reference capture root used throughout:

```
external-review/low-latency-reference/
    dpdk/      pinned commit 6bbb7b38b17f9ea4c981b5d374612a16833df41e (BSD)
    onload/    pinned commit 4b4648b360fda3abd921ec550f26896d58171772 (GPL-2.0, concept only)
    machnet/   pinned commit 877397b94d3131e5e76f0b25b6f2bb5d8a82308f (MIT)
```

Supporting elite notes consulted (cited by name and section):

- `NETWORKING_DISTRIBUTED_STREAMING.md` (workspace root)
- `COMPUTER_SYSTEMS_PERFORMANCE_LOW_LATENCY.md` (workspace root)

---

## 1. Purpose and scope

This document answers one design question: what would it take, in terms of
network data path, to get message transport to a tail latency that the Linux
kernel networking stack cannot reliably reach on this kind of workload. It is
written for the C++ low-latency venue-connectivity layer in this repository
(`cpp/`), which today measures per-message codec decode and multicast
publication latencies on a single Windows host.

The scope is deliberately narrow and honest:

1. Explain, at concept level, why the kernel networking path costs latency.
2. Summarize three kernel-bypass technologies (DPDK, OpenOnload, Machnet) and
   their hardware/licensing prerequisites.
3. State plainly why none of them can be run on this host.
4. Lay out a concrete, step-by-step plan of what would be done on real
   hardware, marked PLANNED because none of it has been executed.
5. Provide a status table separating what is measured in this repository from
   what is documented-only design.

No code from any GPL-licensed source was copied. DPDK (BSD), Machnet (MIT), and
the elite notes were used for concept and, where quoted, are quoted verbatim
with attribution. OpenOnload is GPL-2.0 and was read for concept only.

---

## 2. Why kernel-bypass exists

### 2.1 The kernel networking path has fixed per-message costs

The elite notes `NETWORKING_DISTRIBUTED_STREAMING.md` (Section 21.1) decompose
the receive path as follows:

```
wire -> NIC queue -> interrupt/NAPI -> kernel stack -> socket
-> wakeup/scheduler -> userspace -> parse -> state update -> decision
```

The same note (Section 2.1) lists the latency components an end-to-end message
pays: serialization, local enqueue, kernel/NIC traversal, propagation,
switching/routing, remote queueing, parsing, scheduling, application work, and
the response path. The kernel stages in the middle are not free, and they are
paid once per packet or once per syscall batch.

`COMPUTER_SYSTEMS_PERFORMANCE_LOW_LATENCY.md` (Section 18.3) gives the
user-kernel execution model that makes each stage cost something:

```
user code
-> runtime/libc
-> syscall instruction / exception / interrupt
-> trap entry + privilege change
-> argument validation and copy
-> kernel subsystem
-> possible blocking, wakeup, and context switch
-> driver/device or another process
-> return and context restore
```

From this model the classic kernel networking costs are:

- **Syscalls.** Each `send`/`recv` crosses the user/kernel boundary, pays trap
  entry and privilege change, and validates/copies arguments before any work
  happens. The notes instruct recording "syscalls per operation and bytes per
  call" on any critical path (`COMPUTER_SYSTEMS_PERFORMANCE_LOW_LATENCY.md`,
  Section 18.3).
- **Copies.** Data moves from the NIC DMA buffer through the socket buffer and
  into userspace. The notes call out "copies and representation changes" as a
  recorded cost and stress that "zero-copy" must always name which copy is
  avoided (`NETWORKING_DISTRIBUTED_STREAMING.md`, Sections 21.3).
- **Context switches and scheduling.** A blocking socket wakes the process,
  which requires a wakeup and a context switch before userspace resumes. The
  notes list runnable/wait/off-CPU time, wakeup latency, and involuntary
  context switches as the metrics that explain a pause
  (`COMPUTER_SYSTEMS_PERFORMANCE_LOW_LATENCY.md`, Sections 18.3 and 18.5).
- **Interrupts.** The conventional receive path is interrupt-driven: a packet
  arrival interrupts a core, which costs interrupt latency and cache pollution;
  NAPI mitigates but does not eliminate this. The notes document RSS/RPS/RFS/XPS
  and IRQ steering as the kernel-side tools that rearrange, rather than remove,
  this cost (`NETWORKING_DISTRIBUTED_STREAMING.md`, Sections 21.1-21.2).

### 2.2 What kernel-bypass changes

Kernel-bypass moves the fast path into userspace. Instead of the kernel
notifying the application and copying each packet, the application (or a
userspace library) polls the NIC's receive/transmit descriptors directly and
owns the buffers. This eliminates the per-packet syscall, the kernel copy, and
the interrupt-driven wakeup, at the price of dedicated polled cores, hugepages
or pinned memory, and reimplemented protocol and buffer-ownership semantics.

The notes are explicit about the tradeoffs (`NETWORKING_DISTRIBUTED_STREAMING.md`,
Sections 21.4-21.6): dedicated cores and energy, more complex operation and
security, strict NUMA and queue ownership, and the need to reimplement or
integrate protocol-stack functions. They also state the acceptance gate: adopt
kernel-bypass only after the kernel stack is proven to be the bottleneck and
the workload justifies it, and only if it improves end-to-end p99/p99.9 rather
than a synthetic packet-rate figure. `COMPUTER_SYSTEMS_PERFORMANCE_LOW_LATENCY.md`
records the same discipline, including the caveat that hugepages, pinned memory
and kernel bypass "alter isolation and operation" and must not be recommended
without a workload.

This document therefore treats kernel-bypass as a design option to be planned
and later measured, not as a claim.

---

## 3. DPDK

### 3.1 What it solves

The DPDK README (verbatim, `dpdk/README`):

> DPDK is a set of libraries and drivers for fast packet processing. It
> supports many processor architectures and both FreeBSD and Linux.

DPDK supplies poll-mode drivers (PMDs), a userspace memory manager (hugepages,
mempools, mbufs), and an environment abstraction layer (EAL) that together let
an application process packets in userspace without the kernel stack. The elite
note summarizes the model (`NETWORKING_DISTRIBUTED_STREAMING.md`, Section 21.5):
poll-mode drivers consult RX/TX descriptors in userspace, normally without
interrupts, and use bursts, mbufs/mempools, hugepages, and per-core resources;
the two common execution models are run-to-completion (receive, process, and
transmit on the same lcore) and pipeline (pass work between lcores through
rings).

### 3.2 Poll-mode drivers

A PMD replaces the interrupt-driven NIC driver with a polling loop: the
application repeatedly drains the RX descriptor ring, processes mbufs, and
submits TX descriptors. This removes interrupt latency and per-packet syscalls.
The cost is that the polling core is dedicated and busy even when there is no
traffic. The DPDK capture documents one PMD per supported NIC family under
`dpdk/doc/guides/nics/`.

### 3.3 Hugepages

DPDK requires hugepages for its packet-buffer memory pools. From the capture
(`dpdk/doc/guides/linux_gsg/sys_reqs.rst`): hugepage support is required "for
the large memory pool allocation used for packet buffers," and by using
hugepages "fewer pages are needed, and therefore less Translation Lookaside
Buffers (TLBs) ... which reduce the time it takes to translate a virtual page
address to a physical page address." 2 MB and 1 GB pages are supported, and for
64-bit applications the capture recommends 1 GB hugepages where the platform
supports them.

### 3.4 Citation and license

- Repository: DPDK (captured under
  `external-review/low-latency-reference/dpdk`).
- Pinned commit: `6bbb7b38b17f9ea4c981b5d374612a16833df41e` (short
  `6bbb7b38b17f`), verified on this host with
  `git -C <path> log -1 --format=%H`.
- License (verbatim, `dpdk/README`): "The DPDK uses the Open Source BSD-3-Clause
  license for the core libraries and drivers. The kernel components are GPL-2.0
  licensed."

### 3.5 Hardware and system requirements

From the capture (`dpdk/doc/guides/linux_gsg/sys_reqs.rst`):

- Linux kernel version >= 5.4, glibc >= 2.7, with HUGETLBFS and
  PROC_PAGE_MONITOR enabled.
- Build toolchain: GCC 8.0+ or Clang 7+, Meson 0.57+ and ninja, Python 3.6+,
  pyelftools 0.22+, and the libnuma development package.
- A NIC with a poll-mode driver. The capture's NIC guide
  (`dpdk/doc/guides/nics/index.rst`) documents many families, including Intel
  ixgbe/i40e/ice/igb/igc, Mellanox/NVIDIA mlx4/mlx5, Broadcom bnxt, Amazon
  ena, Chelsio cxgbe, Solarflare sfc_efx, and the virtual drivers virtio,
  vmxnet3, and netvsc (Hyper-V/Azure).

### 3.6 Why it is not runnable on this host

- This is a Windows development host; DPDK targets Linux and FreeBSD. The
  capture's system requirements are Linux-specific (kernel >= 5.4, HUGETLBFS,
  VFIO/uio, Meson + GCC/Clang).
- There is no dedicated DPDK-capable NIC assigned to this machine, and DPDK
  takes exclusive control of the NIC it drives.
- The pinned toolchain for this repository is MSVC on Windows without cmake
  (`external-review/low-latency-reference/INDEX.md`, Section 6), which does not
  match DPDK's Meson/GCC build path.

---

## 4. OpenOnload

### 4.1 What it solves

OpenOnload accelerates existing BSD-sockets TCP and UDP applications in
userspace. Verbatim from the capture (`onload/README.md`):

> Onload is a high performance user-level network stack, which accelerates TCP
> and UDP network I/O for applications using the BSD sockets on Linux.

The same file describes the mechanism:

> OpenOnload comprises a user-level shared library that intercepts network-
> related system calls and implements the protocol stack, and supporting kernel
> modules.

Acceleration is transparent: the application is binary-compatible and is
launched by prefixing the command line with `onload`. This is the classic
`LD_PRELOAD`-style interception model in which the library takes over the
socket calls and runs the protocol stack in userspace instead of the kernel.

### 4.2 Kernel-bypass Ethernet I/O

On AMD Solarflare adapters, OpenOnload uses a native hardware interface that
bypasses the kernel for Ethernet I/O. Verbatim from the capture
(`onload/README.md`):

> Onload provides optimum networking acceleration and additional features using
> the native ef_vi hardware interface provided by AMD Solarflare network
> adapters compared to using Linux's AF_XDP mechanism.

For non-Solarflare adapters the capture documents an AF_XDP mode, described as
"a community-supported work in progress that is not currently at release
quality."

### 4.3 Citation and license

- Repository: OpenOnload (captured under
  `external-review/low-latency-reference/onload`).
- Pinned commit: `4b4648b360fda3abd921ec550f26896d58171772` (short
  `4b4648b360fd`), verified on this host with
  `git -C <path> log -1 --format=%H`.
- License: GPL-2.0. The capture README states the project is "Open Source
  (GPLv2.0 and BSD-2-Clause)." For this repository the policy is concept-only:
  OpenOnload was read for capabilities, and no code was copied from it (GPL
  contamination avoidance). One file in the capture (`aux.h`) is not
  materialized on Windows because the name is reserved by the Windows
  filesystem; this does not affect the concept material read here.

### 4.4 Hardware requirements

From the capture (`onload/README.md`):

- AMD Solarflare network adapters for native acceleration: SFN8522, SFN8542,
  SFN8042, X2522, X2522-25G, X2541, and X3522.
- Compatible Linux environments: Debian 12+, Ubuntu LTS 24.04+, EL 9.0+/10.0+,
  and kernel.org kernels 6.1 through 7.0.
- Alternatively, AF_XDP mode on non-Solarflare NICs with an AF_XDP-capable
  driver (community-supported, not release quality).

### 4.5 Why it is not runnable on this host

- There is no AMD Solarflare adapter in this machine, and no second machine to
  form a test pair.
- OpenOnload is a Linux kernel-module-plus-library stack; this is a Windows
  host, so neither the `sfc` driver nor the userspace library applies.

---

## 5. Machnet

### 5.1 What it solves

Machnet is Microsoft's DPDK-based kernel-bypass messaging library aimed at
datacenter and finance workloads in cloud VMs. Its architecture (verbatim,
`machnet/README.md`):

> Machnet runs as a separate process on all machines where the application is
> deployed and mediates access to the DPDK NIC. Applications interact with
> Machnet over shared memory with a sockets-like API. Machnet processes in the
> cluster communicate with each other using DPDK.

### 5.2 The performance claim (quoted from their README, not ours)

Verbatim from `machnet/README.md` (capture path
`external-review/low-latency-reference/machnet/README.md`), the sentence that
contains the 750K RPS / 61 microsecond claim:

> Distributed applications like databases and finance can use Machnet as the
> networking library to get sub-100 microsecond tail latency at high message
> rates, e.g., **750,000 1KB request-reply messages per second on Azure F8s_v2
> VMs with 61 microsecond P99.9 round-trip latency**.

This claim is attributed to the Machnet README and is reproduced here as the
vendor's stated result, not as a measurement of this repository. The README
refers readers to `docs/PERFORMANCE_REPORT.md` in the same capture for the
platforms, OSs and NICs it evaluated.

### 5.3 Hardware and deployment requirements (as documented in their repo)

From `machnet/README.md`:

- Two machines, each with a dedicated NIC for Machnet; the dedicated NIC may be
  shared by multiple Machnet applications.
- On Azure: create two VMs with accelerated networking enabled. The default NIC
  (`eth0`) is "never used by Machnet." After shutting the VMs down, create a
  second accelerated NIC per VM with no public IP and attach it so each VM has
  an `eth1` used by Machnet.
- The NIC must be unbound from the OS for DPDK. On Azure the README directs
  using `driverctl` with the `uio_hv_generic` driver (DPDK's Hyper-V driver);
  elsewhere it uses `dpdk-devbind.py` with `vfio-pci`.
- The README's stated performance figure is on Azure F8s_v2 VMs.
- The reference deployment uses the prebuilt Docker image
  `ghcr.io/microsoft/machnet/machnet:latest`, or Machnet can be built from
  source with cmake.
- `examples/` contains launch scripts, and `src/ext/machnet.h` documents the
  sockets-like API (`machnet_init`, `machnet_attach`, `machnet_listen`,
  `machnet_connect`, `machnet_send`, `machnet_recv`).

### 5.4 Citation and license

- Repository: Machnet (Microsoft), captured under
  `external-review/low-latency-reference/machnet`.
- Pinned commit: `877397b94d3131e5e76f0b25b6f2bb5d8a82308f` (short
  `877397b94d31`), verified on this host with
  `git -C <path> log -1 --format=%H`.
- License: MIT (`external-review/low-latency-reference/INDEX.md`, Section 9).

### 5.5 Why it is not runnable on this host

- No Azure DPDK VM has been provisioned, and no cloud accelerated-NIC pair
  exists.
- There is no dedicated NIC to unbind, and Machnet (like DPDK) requires a Linux
  environment and exclusive NIC access.
- This is a single Windows host; Machnet's documented setup is two Linux VMs
  with two NICs each.

---

## 6. Concrete plan (all steps PLANNED, none executed)

The goal of either plan is to measure message-path latency with this
repository's own HDR histogram (`cpp/bench/hdr_histogram.hpp`, whose semantics
mirror HdrHistogram_c at commit 1343a18908c6) and compare the result against
the per-message numbers already measured and published in this repository
(`cpp/bench/benchmarks/*.json`, summarized in
`evidence/EVIDENCE_05_BENCHMARKS.md`):

- ITCH 5.0 decode: p50 16 ns, p99 20 ns, 59,916,500 msg/s.
- SBE Binance decode: p50 83 ns, p99 111 ns, 11,822,300 msg/s.
- Multicast UDP publication (29 B): p50 2,682 ns, p99 95,146 ns, 203,376 dgram/s.
- JSON depth decode (Python stdlib): p50 1,500 ns, p99 4,900 ns, 615,889 msg/s.

These are per-host measurements, not cross-vendor claims, and the closest
measured inter-process baseline currently in the repository is the multicast
UDP publication number above.

### 6.1 Plan A - Machnet on Azure (PLANNED)

1. PLANNED: provision two Azure VMs (F8s_v2 class, matching the Machnet README
   claim) with accelerated networking enabled.
2. PLANNED: stop the VMs, create a second accelerated NIC per VM with no public
   IP, attach one to each VM, and confirm each VM exposes `eth1`.
3. PLANNED: install Docker, pull `ghcr.io/microsoft/machnet/machnet:latest`
   (or build Machnet from source with cmake per the README).
4. PLANNED: note the `eth1` IP and MAC, then unbind `eth1` with `driverctl` and
   `uio_hv_generic` as the README directs, and start Machnet on both VMs.
5. PLANNED: run the README's `msg_gen` end-to-end benchmark.
6. PLANNED: instrument the same request-reply path with our HDR histogram
   (`cpp/bench/hdr_histogram.hpp`) and record p50/p99/p99.9.
7. PLANNED: compare the measured tail against our measured multicast UDP
   publication and codec numbers, and against the Machnet README's quoted
   750,000 msg/s at 61 microsecond p99.9 claim.

### 6.2 Plan B - OpenOnload on a dedicated Solarflare adapter (PLANNED)

1. PLANNED: provision a Linux host (Ubuntu 24.04 or Debian 12, within the
   README's supported range) with a supported AMD Solarflare adapter, e.g.
   X2522-25G, and a second equivalent host to form a test pair.
2. PLANNED: build and install OpenOnload from source per the capture's
   `DEVELOPING.md`, pinning the captured commit 4b4648b360fd.
3. PLANNED: launch this repository's C++ benchmark binaries under the `onload`
   command wrapper so the socket calls are accelerated transparently.
4. PLANNED: measure with our HDR histogram and record p50/p99/p99.9 for the
   same message sizes used in the Machnet plan.
5. PLANNED: compare against the measured baseline numbers in Section 6 and
   against OpenOnload's documented low application-to-application latency.

Every step above is design intent only. No Azure resource was created, no
Solarflare hardware was acquired, and no Machnet or OpenOnload binary was built
or run on this host.

---

## 7. Honest status table

| Item | Status | Evidence / source |
|---|---|---|
| HDR histogram implementation vs HdrHistogram_c semantics | Measured (deterministic crosscheck, PASS) | `cpp/evidence/10-latency-elite/PHASE1/crosscheck_report.json` |
| ITCH 5.0 decode latency/throughput | Measured on this host | `cpp/bench/benchmarks/bench_itch_final.json`, `evidence/EVIDENCE_05_BENCHMARKS.md` |
| SBE Binance decode latency/throughput | Measured on this host | `cpp/bench/benchmarks/bench_sbe_final.json` |
| Multicast UDP publication latency/throughput | Measured on this host | `cpp/bench/benchmarks/bench_mcast_final.json` |
| JSON depth decode latency/throughput | Measured on this host | `cpp/bench/benchmarks/bench_json_final.json` |
| Aeron IPC demo (jars + sources) | Set up, no measured results committed | `cpp/evidence/10-latency-elite/PHASE3/aeron-ipc/` |
| DPDK capabilities, license, requirements | Documented-only design, not run | `dpdk` capture, commit 6bbb7b38b17f |
| OpenOnload capabilities, license, requirements | Documented-only design (GPL-2.0, concept only), not run | `onload` capture, commit 4b4648b360fd |
| Machnet capabilities, quote, Azure requirements | Documented-only design, not run | `machnet` capture, commit 877397b94d31 |
| Machnet 750K msg/s / 61 us p99.9 figure | Vendor claim, quoted with attribution, not reproduced here | `machnet/README.md` |

No kernel-bypass technology was executed, and no external latency figure is
presented as a result of this repository.
