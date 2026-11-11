# Logihertz PREEMPT_RT Kernel Patchset (`lh-kernel-preempt-patch`)

[![Organization](https://img.shields.io/badge/Organization-Logihertz%20Systems-000000.svg)](https://logihertz.com/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Standard: C11](https://img.shields.io/badge/C11-ISO%2FIEC%209899%3A2011-orange.svg)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![Kernel: Linux 6.6 LTS](https://img.shields.io/badge/Linux%20Kernel-6.6%20LTS%20PREEMPT__RT-blue.svg)](https://kernel.org/)
[![Hardware: NVIDIA Jetson Orin](https://img.shields.io/badge/Hardware-Tegra234%20%7C%20ARM64-76B900.svg?logo=nvidia&logoColor=white)](https://developer.nvidia.com/embedded/jetson-orin)
[![OASIS SARIF v2.1.0](https://img.shields.io/badge/OASIS-SARIF%20v2.1.0-green.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20Third--Party-success.svg)](#architecture)
[![CI Matrix](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-kernel-preempt-patch/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-kernel-preempt-patch/actions/workflows/ci.yml)

**Production-grade, zero-dependency C11 Real-Time Linux 6.6 LTS `PREEMPT_RT` Kernel Patchset, Deterministic Jitter Analyzer, and 10-Rule Real-Time Kernel Posture Auditor tailored for NVIDIA Jetson Orin (`tegra234` / ARM64) and industrial edge appliances.**

---

## Executive Summary

Mission-critical robotics, autonomous perception pipelines, edge AI inference engines, and industrial control systems demand microsecond-level deterministic scheduling. Standard Linux distribution kernels and default OEM BSPs introduce unpredictable latencies exceeding hundreds of milliseconds due to non-sleeping spinlocks, unthreaded interrupt service routines, deep CPU C-state sleep transitions, and unrestricted memory paging.

**`lh-kernel-preempt-patch`** (`bin/lh-preempt`) provides an end-to-end real-time hardening suite for **Linux 6.6 LTS** on **NVIDIA Jetson Orin** (`tegra234` architecture, including AGX Orin, Orin NX, and Orin Nano):
- **Linux 6.6 LTS Real-Time Patchset**: Modular, DCO-signed unified diff series resolving priority inversion and interrupt delays on ARM64 Tegra234 hardware.
- **Pure C11 Engine with Zero Dependencies**: Implemented in clean ISO C11 without third-party libraries, linking only standard `libc` and `-lm`. Compiles cleanly under GCC and Clang with `-std=c11 -O2 -Wall -Wextra -Werror -pedantic`.
- **Deterministic Latency & Jitter Math**: Evaluates worst-case execution time (WCET), peak jitter ($\Delta J$), CPU bandwidth bounds ($U_{\text{RT}}$), and flags firmware/SMI latency spikes.
- **Unified Diff Verification Engine**: Validates patch headers, line counts, hunks, and DCO compliance.
- **10-Rule PREEMPT_RT Posture Auditor**: Audits kernel `.config` and cmdline manifests with ANSI terminal tables, JSON, and OASIS SARIF v2.1.0 outputs.

---

## Architecture & Real-Time Scheduling Mathematics

### 1. Latency & Jitter Mathematical Models

In deterministic hard real-time systems, task completion variance must be bounded:

#### Peak Jitter ($\Delta J$):
$$\Delta J = L_{\max} - L_{\min}$$

#### Real-Time Bandwidth Utilization Bound ($U_{\text{RT}}$):
To prevent runaway `SCHED_FIFO` threads from locking up isolated cores or starving critical system tasks, the RT runtime ratio must be bounded:
$$U_{\text{RT}} = \frac{\text{sched\_rt\_runtime\_us}}{\text{sched\_rt\_period\_us}} \le 0.95$$

#### Worst-Case Execution Time (WCET) Margin ($M_{\text{WCET}}$):
$$M_{\text{WCET}} = D_{\text{deadline\_us}} - \left(L_{\text{max\_irq\_us}} + C_{\text{context\_switch\_us}}\right)$$

#### Deterministic Latency Ceiling:
On tuned NVIDIA Jetson Orin (`tegra234`) hardware running Linux 6.6 LTS `PREEMPT_RT`, maximum observed latency must not exceed $50\ \mu\text{s}$:
$$L_{\max} \le 50\ \mu\text{s}$$

Any spike exceeding $50\ \mu\text{s}$ indicates firmware System Management Interrupts (SMI), ARM EL3 TrustZone context switching, or unthreaded interrupt contention.

---

## Real-Time Linux 6.6 LTS Patch Series (`patches/`)

The repository includes a production-validated patch series for NVIDIA Jetson Orin (`tegra234`):

| Patch File | Subsystem | Description |
|:---|:---:|:---|
| [`0001-arm64-tegra234-preempt-rt-irq-threading.patch`](patches/0001-arm64-tegra234-preempt-rt-irq-threading.patch) | `arch/arm64/tegra` | Enforces `IRQF_ONESHOT` and forced IRQ threading on Tegra234 GICv3, GPIO, and VI camera interrupt handlers. |
| [`0002-sched-rt-deterministic-throttling-guard.patch`](patches/0002-sched-rt-deterministic-throttling-guard.patch) | `kernel/sched` | Configures `sched_rt_runtime_us` safety reservation (950,000 us per 1,000,000 us period) to prevent isolated core starvation. |
| [`0003-drivers-nvgpu-rt-mutex-conversion.patch`](patches/0003-drivers-nvgpu-rt-mutex-conversion.patch) | `drivers/gpu/nvgpu` | Converts non-sleeping `spinlock_t` in GPU DMA allocation paths to sleeping `rt_mutex` primitives to eliminate priority-inversion stalls. |

---

## Core Detection Rules (`LH-RT-001` .. `LH-RT-010`)

The built-in `rt_auditor` evaluates real-time kernel configurations against 10 deterministic rules:

| Rule ID | Severity | Weight ($W_r$) | CWE Mapping | Trigger Condition & Description |
|:---|:---:|:---:|:---:|:---|
| **LH-RT-001** | `CRITICAL` | 25 | CWE-400 | Full real-time preemption disabled (`CONFIG_PREEMPT_RT` not `"y"` or `preempt_mode != "full"`) |
| **LH-RT-002** | `CRITICAL` | 25 | CWE-833 | Unbounded `SCHED_FIFO` CPU starvation risk (`sched_rt_runtime_us == -1` or RT bandwidth $> 0.95$) |
| **LH-RT-003** | `CRITICAL` | 25 | CWE-662 | Worst-case `cyclictest` latency exceeds deterministic ceiling (`max_latency_us > 50`) |
| **LH-RT-004** | `HIGH` | 10 | CWE-400 | Missing CPU core isolation (`isolcpus`, `nohz_full`, or `rcu_nocbs` empty/unconfigured) |
| **LH-RT-005** | `HIGH` | 667 | CWE-667 | Forced interrupt threading disabled (`CONFIG_IRQ_FORCED_THREADING != "y"` or `threadirqs` missing) |
| **LH-RT-006** | `HIGH` | 10 | CWE-400 | Dynamic CPU frequency scaling or deep C-state sleep enabled (`cpufreq_governor != "performance"` or `max_cstate > 0`) |
| **LH-RT-007** | `HIGH` | 10 | CWE-770 | Memory paging active without `mlockall` guard (`vm_swappiness > 0` or `numa_balancing_enabled: true`) |
| **LH-RT-008** | `MEDIUM` | 4 | CWE-662 | Suboptimal timer tick resolution (`CONFIG_HZ < 1000` or `high_res_timers_enabled: false`) |
| **LH-RT-009** | `MEDIUM` | 4 | CWE-250 | Unhandled hardware/firmware latency spikes (`efi_runtime_enabled: true` or `ras_daemon_irq_on_rt_cores: true`) |
| **LH-RT-010** | `LOW` | 1 | CWE-755 | Missing hardware watchdog recovery or lockdep telemetry (`hardware_watchdog_enabled: false`) |

### Standardized Security & Posture Score:

$$S_{\text{posture}} = \max\left(0, 100 - \sum_{r \in \text{Violations}} W_r\right) = \max\left(0, 100 - (25 \cdot c_{\text{CRIT}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MED}} + 1 \cdot c_{\text{LOW}})\right)$$

- **Hardened Kernel Baseline (`hardened_rt_kernel.json`)**: $S_{\text{posture}} = 100/100$ (Exit code `0`).
- **Non-Compliant Configuration (`vulnerable_rt_kernel.json`)**: $S_{\text{posture}} = \max(0, 100 - 124) = 0/100$ (Exit code `1`).

---

## Build & Test Instructions

### Compilation (GCC or Clang)
```bash
# Build binary bin/lh-preempt
make CC=gcc

# Run verification test suite
make CC=gcc test

# Clean artifacts
make clean
```

---

## CLI Reference (`bin/lh-preempt`)

```bash
# 1. Audit a kernel RT configuration manifest
bin/lh-preempt scan fixtures/hardened_rt_kernel.json --format table
bin/lh-preempt scan fixtures/hardened_rt_kernel.json --format sarif --output report.sarif

# 2. Verify integrity and DCO headers of the kernel patch series
bin/lh-preempt verify-patches patches

# 3. Analyze cyclictest telemetry for jitter and SMI spikes
bin/lh-preempt analyze-jitter fixtures/sample_cyclictest.json

# 4. Generate recommended Kconfig and kernel cmdline fragment for Tegra234
bin/lh-preempt gen-config --soc tegra234

# 5. CLI Help & Version
bin/lh-preempt --help
bin/lh-preempt --version
```

---

## Exit Codes

| Exit Code | Semantic Meaning |
|:---:|:---|
| **`0`** | Clean scan (Score: 100, zero violations), valid patch series, or jitter within deterministic bounds |
| **`1`** | Posture violation detected, corrupted/unsigned patch file, or jitter exceeding latency ceiling |
| **`2`** | Invalid CLI usage, missing file, or invalid JSON configuration |

---

## Corporate Attribution & Governance

- **Organization**: [Logihertz Systems (OPC) Private Limited](https://logihertz.com/)
- **GitHub Organization**: [`Logihertz-Systems-OPC-Pvt-Ltd`](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd)
- **Creator, Founder, Director & Sole Developer**: **Sameer Tawade** ([`ops@logihertz.com`](mailto:ops@logihertz.com) / [`security@logihertz.com`](mailto:security@logihertz.com))
- **Git Commit Author**: `logihertzsystems <ops@logihertz.com>`
- **License**: Released under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

Copyright &copy; 2026 Logihertz Systems (OPC) Private Limited. All Rights Reserved.
