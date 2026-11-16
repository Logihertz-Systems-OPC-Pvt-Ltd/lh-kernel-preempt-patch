# Engineering & Technical Architecture Specification

**Specification ID**: `LH-SPEC-2026-034`  
**Repository**: `lh-kernel-preempt-patch`  
**CLI Executable**: `lh-preempt`  
**Standard Release Version**: `0.1.0`  
**Standard License**: `Apache-2.0`  
**Classification**: `Industrial Sovereign Cybersecurity & Critical Infrastructure Telemetry`

---

## Section 1: Document Control & Specification Metadata

| Metadata Attribute | Value |
| :--- | :--- |
| **Document Identification** | `LH-SPEC-2026-034` |
| **System Name** | `Logihertz Systems Sovereign Ecosystem` |
| **Target Component** | `lh-kernel-preempt-patch` (`lh-preempt`) |
| **Target Language / Platform** | `C` |
| **Legal Entity** | Logihertz Systems (OPC) Private Limited |
| **Corporate Identity (CIN)** | `U72100MH2025OPC463857` |
| **GSTIN Registration** | `27AAGCL6394P1ZL` |
| **Principal Architect** | Sameer Tawade (`ops@logihertz.com` / `security@logihertz.com`) |
| **Headquarters & Registered Office** | Mumbai, Maharashtra, Republic of India |
| **Official Portal** | [https://www.logihertz.com](https://www.logihertz.com) |
| **Repository URL** | [https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-kernel-preempt-patch](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-kernel-preempt-patch) |
| **Document Status** | `APPROVED FOR PRODUCTION & INDUSTRIAL CERTIFICATION` |
| **Effective Release Date** | `2026-11-16` |

---

## Section 2: Normative RFC 2119 Requirements & System Invariants

This technical architecture specification enforces strict deterministic execution invariants in accordance with **RFC 2119** (`MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `RECOMMENDED`, `MAY`).

1. **Zero-Daemon Execution Invariant**:
   - The CLI binary `lh-preempt` `MUST` execute as a clean, self-contained, stateless, zero-daemon process.
   - It `MUST NOT` spawn background daemons, fork unmonitored worker processes, or establish persistent Unix domain socket listeners unless explicitly invoked in daemon mode.
   - All state transitions `MUST` be deterministic, ephemeral, and strictly bounded by the execution lifecycle.

2. **Zero External Runtime Dependency Mandate**:
   - The software `MUST NOT` load, link, or depend upon third-party runtime package registries (e.g. PyPI, npm, Packagist, crates.io, Maven) at runtime.
   - For `C`, all cryptographic, mathematical, serialization, and networking primitives `MUST` be implemented exclusively via language standard libraries or clean-room internal zero-dependency modules.

3. **Deterministic Air-Gapped Operation**:
   - The system `MUST` function with 100% feature parity in air-gapped, isolated, and offline enclaves.
   - The software `MUST NOT` initiate unsolicited network calls, telemetry telemetry pings, phone-home beacons, or external CDN queries.
   - All verification baselines, heuristics, and schemas `MUST` be packaged locally within the distribution.

4. **Constant-Time Cryptographic Comparison**:
   - All cryptographic comparison routines (hashes, HMAC tags, signatures, secret tokens, and commitments) `MUST` execute in constant time (`subtle.ConstantTimeCompare`, `CRYPTO_memcmp`, or equivalent).
   - The implementation `MUST NOT` short-circuit string comparisons when evaluating sensitive keys, thereby mitigating timing side-channel attacks.

5. **Memory Safety & Explicit Zeroization**:
   - All transient buffers containing sensitive key material, decrypted plaintexts, seeds, and cryptographic nonces `MUST` be explicitly overwritten with zeroes immediately following completion of the cryptographic operation.
   - For C/C++ implementations, bounds checks and safe buffer wrappers `MUST` prevent stack/heap overflows. For Rust implementations, `#![forbid(unsafe_code)]` `MUST` be enforced.

6. **Standardized Telemetry Interoperability**:
   - All security assessment outputs `MUST` support machine-readable ingestion via OASIS SARIF v2.1.0 JSON and Canonical Indented JSON schemas, alongside ANSI console tables.

---

## Section 3: Core Mathematical & Algorithmic Specification

### 3.1 Domain Engine Mathematical Foundation: Deterministic Worst-Case Execution Time & Jitter Bound

The underlying computational core of `lh-kernel-preempt-patch` is formally governed by the following mathematical and algorithmic formulations:

$$T_{\text{latency}} = t_{\text{actual}} - t_{\text{scheduled}}, \quad \max(T_{\text{latency}}) \le T_{\text{deadline}} = 50\,\mu\text{s}$$

### 3.2 Standardized Logihertz Security Posture Score Formulation

To achieve absolute cross-tool normalization across all 60 repositories in the Logihertz Systems Ecosystem, the security posture score $S_{\text{posture}}$ is evaluated on a standardized continuous integer scale $[0, 100]$:

$$S_{\text{posture}} = \max\left(0, \; 100 - \left(25 \cdot c_{\text{CRITICAL}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MEDIUM}} + 1 \cdot c_{\text{LOW}}\right)\right)$$

Where:
- $c_{\text{CRITICAL}}$ represents the total count of triggered Critical-severity normative rules (deduction: $-25$ per finding).
- $c_{\text{HIGH}}$ represents the total count of triggered High-severity normative rules (deduction: $-10$ per finding).
- $c_{\text{MEDIUM}}$ represents the total count of triggered Medium-severity normative rules (deduction: $-4$ per finding).
- $c_{\text{LOW}}$ represents the total count of triggered Low-severity normative rules (deduction: $-1$ per finding).

The final compliance verdict is strictly bifurcated:
$$\text{Verdict} = \begin{cases} \text{PASS} & \text{if } S_{\text{posture}} = 100 \land \sum c_i = 0 \\ \text{FAIL} & \text{otherwise} \end{cases}$$

---

## Section 4: Normative 10-Rule Detection Matrix

The detection engine evaluates configurations, manifests, firmware, protocols, and streams against the following 10 deterministic security rules:

| Rule ID | Severity | Weight | CWE ID | Trigger Predicate / Condition | Remediation Guideline |
| :--- | :--- | :---: | :---: | :--- | :--- |
| `LH-RT-001` | `CRITICAL` | `25` | `CWE-400` | CWE-400 | Full real-time preemption disabled (CONFIG_PREEMPT_RT not "y" or preempt_mode != "full") |
| `LH-RT-002` | `CRITICAL` | `25` | `CWE-833` | CWE-833 | Unbounded SCHED_FIFO CPU starvation risk (sched_rt_runtime_us == -1 or RT bandwidth $> 0.95$) |
| `LH-RT-003` | `CRITICAL` | `25` | `CWE-662` | CWE-662 | Worst-case cyclictest latency exceeds deterministic ceiling (max_latency_us > 50) |
| `LH-RT-004` | `HIGH` | `10` | `CWE-400` | CWE-400 | Missing CPU core isolation (isolcpus, nohz_full, or rcu_nocbs empty/unconfigured) |
| `LH-RT-005` | `HIGH` | `10` | `CWE-667` | CWE-667 | Forced interrupt threading disabled (CONFIG_IRQ_FORCED_THREADING != "y" or threadirqs missing) |
| `LH-RT-006` | `HIGH` | `10` | `CWE-400` | CWE-400 | Dynamic CPU frequency scaling or deep C-state sleep enabled (cpufreq_governor != "performance" or max_cstate > 0) |
| `LH-RT-007` | `HIGH` | `10` | `CWE-770` | CWE-770 | Memory paging active without mlockall guard (vm_swappiness > 0 or numa_balancing_enabled: true) |
| `LH-RT-008` | `MEDIUM` | `4` | `CWE-662` | CWE-662 | Suboptimal timer tick resolution (CONFIG_HZ < 1000 or high_res_timers_enabled: false) |
| `LH-RT-009` | `MEDIUM` | `4` | `CWE-250` | CWE-250 | Unhandled hardware/firmware latency spikes (efi_runtime_enabled: true or ras_daemon_irq_on_rt_cores: true) |
| `LH-RT-010` | `LOW` | `1` | `CWE-755` | CWE-755 | Missing hardware watchdog recovery or lockdep telemetry (hardware_watchdog_enabled: false) |

---

## Section 5: CLI Contract, Exit Codes & OASIS SARIF v2.1.0 Specification

### 5.1 Command-Line Interface Syntax

The primary entrypoint `lh-preempt` conforms to standard POSIX argument conventions:

```text
USAGE:
  lh-preempt <command> [flags] [arguments]

CORE COMMANDS:
  scan <target> [--format table|json|sarif] [--output <file>]
      Execute deterministic security evaluation against target manifest or telemetry stream.
  verify <target>
      Validate operational parameters, cryptographic checksums, and structural invariants.
  --version, version
      Output release version, architecture, and legal attribution.
  --help, help
      Display comprehensive operational usage and command reference.
```

### 5.2 Deterministic Exit Code Protocol

| Exit Code | Classification | Operational Semantics |
| :---: | :--- | :--- |
| `0` | **SUCCESS / PASS** | Target passed all checks; zero Critical/High violations detected; $S_{\text{posture}} = 100$. |
| `1` | **FINDINGS / FAIL** | Target triggered one or more security rule violations; policy threshold breached. |
| `2` | **ERROR / USAGE** | Invalid CLI invocation, syntax error, missing input file, or fatal I/O failure. |

### 5.3 OASIS SARIF v2.1.0 Schema Compliance

Exported SARIF documents validate against the official OASIS schema (`sarif-schema-2.1.0.json`). Each result object maps:
- `ruleId`: Standardized identifier (`LH-RT-001` .. `LH-RT-010`).
- `level`: SARIF severity levels (`error` for Critical/High, `warning` for Medium, `note` for Low).
- `message.text`: Comprehensive explanation, CWE mapping, and actionable remediation steps.
- `locations[].physicalLocation.artifactLocation.uri`: Absolute or normalized relative path of target artifact.

---

## 6. Standalone Future Development Roadmap (`v0.2.0` — `v0.5.0`)

`lh-kernel-preempt-patch` is developed as an independent, standalone open-source project. The following roadmap defines the planned architectural, algorithmic, and protocol enhancements for upcoming point releases of `lh-kernel-preempt-patch`:

| Target Release | Milestone Focus | Planned Technical Deliverables for `lh-kernel-preempt-patch` |
|---|---|---|
| **`v0.2.0`** | Parser & Protocol Expansion | Expand PREEMPT_RT patch verification to Linux 6.12 LTS (mainline PREEMPT_RT) and add ARM64 GICv3/GICv4 pseudo-NMI latency analysis. |
| **`v0.3.0`** | Deep Algorithmic & Stateful Analysis | Implement a Linux trace-cmd / ftrace (irqsoff, preemptoff, timerlat, osnoise) trace parser for automated kernel function latency attribution. |
| **`v0.4.0`** | Remediation, Synthesis & Format Interop | Synthesize automated CPU isolation (cpuset cgroup v2, IRQ smp_affinity masks, and rcu_nocbs) tuning scripts. |
| **`v0.5.0`** | High-Throughput Performance & Formal Verification | Add Extreme Value Theory (Weibull / Gumbel distribution) statistical Worst-Case Execution Time (WCET) tail-latency modeling. |

### 6.1 `v0.2.0` — Parser & Protocol Expansion
- **Format & Protocol Ingestion**: Expand PREEMPT_RT patch verification to Linux 6.12 LTS (mainline PREEMPT_RT) and add ARM64 GICv3/GICv4 pseudo-NMI latency analysis.
- **Zero-Dependency Architecture**: Pure standard library implementation with deterministic parsing guarantees and strict error handling.
- **Verification & Telemetry**: Regression test suites verifying schema edge-cases, malformed payload rejections, and SARIF v2.1.0 output fidelity.

### 6.2 `v0.3.0` — Deep Algorithmic & Stateful Analysis
- **Algorithmic Core**: Implement a Linux trace-cmd / ftrace (irqsoff, preemptoff, timerlat, osnoise) trace parser for automated kernel function latency attribution.
- **State Machine & Analysis Engine**: High-fidelity state tracking, cycle detection, and invariant checking with minimal computational overhead.
- **Differential & Regression Verification**: Comprehensive test harnesses covering stateful transitions, edge conditions, and mathematical boundary constraints.

### 6.3 `v0.4.0` — Remediation, Synthesis & Format Interoperability
- **Synthesis & Interoperability**: Synthesize automated CPU isolation (cpuset cgroup v2, IRQ smp_affinity masks, and rcu_nocbs) tuning scripts.
- **Automated Remediation Workflows**: Idempotent generation of verified configuration patches, policy rules, and standardized cross-format exports.
- **Contract & Artifact Validation**: Cryptographic baseline verification and end-to-end integration testing for synthesized deliverables.

### 6.4 `v0.5.0` — High-Throughput Performance & Formal Verification
- **High-Throughput Optimization**: Add Extreme Value Theory (Weibull / Gumbel distribution) statistical Worst-Case Execution Time (WCET) tail-latency modeling.
- **Hardware & Kernel Acceleration**: Vectorized SIMD/eBPF/sub-millisecond streaming execution with bounded memory allocation.
- **Formal Verification & Assurance**: Mathematical proof of invariant preservation, false-positive calibration, and high-assurance certification baselines.

---

## Section 7: Verification, Quality Assurance & Legal Attribution

### 7.1 Automated Verification Protocol

Prior to distribution, all builds must execute the standardized Logihertz test suite:
- Unit and mathematical property tests verifying all equations and edge cases.
- Static analysis with zero warnings under standard strict linters.
- Subprocess CLI verification covering exit codes `0`, `1`, and `2`.

### 7.2 Copyright & Governance Notice

```text
Copyright 2025-2026 Logihertz Systems (OPC) Private Limited.
Creator, Founder, Director & Sole Developer: Sameer Tawade <ops@logihertz.com> / <security@logihertz.com>
Official Corporate Portal: https://www.logihertz.com
```

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this software except in compliance with the License. You may obtain a copy of the License at `http://www.apache.org/licenses/LICENSE-2.0`.
