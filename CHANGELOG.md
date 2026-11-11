# Changelog

All notable changes to **`lh-kernel-preempt-patch`** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-11-11

### Added
- **Linux 6.6 LTS Tegra234 PREEMPT_RT Patchset** (`patches/`):
  - `0001-arm64-tegra234-preempt-rt-irq-threading.patch`: Forced IRQ threading (`IRQF_ONESHOT`) for Tegra234 GICv3, GPIO, and VI camera interrupt handlers.
  - `0002-sched-rt-deterministic-throttling-guard.patch`: Bounded real-time bandwidth throttling guard (`sched_rt_runtime_us` = 950,000 us per 1,000,000 us) preventing isolated core lockups.
  - `0003-drivers-nvgpu-rt-mutex-conversion.patch`: Conversion of non-sleeping `spinlock_t` to sleeping `rt_mutex` in nvgpu DMA allocation paths.
  - `patches/series`: Quilt/git patch series manifest for automated kernel build pipelines.
- **Deterministic Latency & Jitter Math** (`src/latency_math.c`, `include/latency_math.h`):
  - Peak Jitter calculation: $\Delta J = L_{\max} - L_{\min}$.
  - Real-Time CPU Bandwidth Utilization Bound: $U_{\text{RT}} = \frac{\text{sched\_rt\_runtime\_us}}{\text{sched\_rt\_period\_us}} \le 0.95$.
  - Worst-Case Interrupt Latency Margin: $M_{\text{WCET}} = D_{\text{deadline\_us}} - (L_{\text{max\_irq\_us}} + C_{\text{context\_switch\_us}})$.
  - cyclictest telemetry array statistical evaluation (mean, standard deviation $\sigma$, SMI / TrustZone spike detection $> 50\ \mu\text{s}$).
- **Unified Diff & Patch Verification Engine** (`src/patch_engine.c`, `include/patch_engine.h`):
  - DCO header verification (`From:`, `Subject:`, `Signed-off-by:`).
  - Unified diff structure validation (`--- a/`, `+++ b/`, `@@ -l,s +l,s @@`).
  - Hunk count and integrity hash calculation.
  - Series manifest verification (`verify_patch_series`).
- **10-Rule Real-Time Kernel Posture Auditor** (`src/rt_auditor.c`, `include/rt_auditor.h`):
  - Evaluates rules `LH-RT-001` through `LH-RT-010` covering PREEMPT_RT mode, RT throttling, cyclictest jitter ceiling, CPU core isolation (`isolcpus`, `nohz_full`, `rcu_nocbs`), forced IRQ threading, CPU frequency governor, memory locking (`mlockall`), timer tick frequency (1000 Hz), hardware SMI spikes, and hardware watchdog recovery.
  - Computes standardized Logihertz Security Posture Score:
    $$S_{\text{posture}} = \max(0, 100 - (25\cdot c_{\text{CRIT}} + 10\cdot c_{\text{HIGH}} + 4\cdot c_{\text{MED}} + 1\cdot c_{\text{LOW}}))$$
- **Multi-Format Exporters** (`src/exporters.c`, `include/exporters.h`):
  - ANSI terminal box table with score banner.
  - Machine-readable Canonical JSON.
  - Standard OASIS SARIF v2.1.0 with complete CWE mappings.
- **Pure C11 CLI Application** (`bin/lh-preempt`):
  - Subcommands: `scan`, `verify-patches`, `analyze-jitter`, `gen-config`, `--version`, `--help`.
- **C11 Verification Test Suite** (`tests/test_runner.c`):
  - 80+ deterministic assertions validating latency math, patch verification, config parsing, 10-rule posture checks, and CLI exit codes.
