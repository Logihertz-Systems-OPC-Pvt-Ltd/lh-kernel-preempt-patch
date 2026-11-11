# Security Policy

## Scope & Commitment

Logihertz Systems (OPC) Private Limited maintains rigorous safety, timing, and security
standards across our open-source edge computing and real-time infrastructure.

**`lh-kernel-preempt-patch`** provides deterministic low-latency kernel modifications and
compliance auditing for safety-critical edge AI hardware (including NVIDIA Jetson Orin / Tegra234).

We welcome responsible security disclosures regarding:
- Priority-inversion deadlocks or unbounded spinlock stalls in PREEMPT_RT patch diffs.
- Vulnerabilities in C11 parsing logic (`config_parser.c`, `patch_engine.c`).
- Buffer overflow, memory corruption, or format string bugs in `bin/lh-preempt`.
- Real-time CPU starvation escapes or SCHED_FIFO bandwidth exhaustion.
- Non-deterministic latency spikes or hardware interrupt masking vulnerabilities.
- Misclassification or bypasses in the 10-rule `rt_auditor` engine.

---

## Supported Versions

| Version | Status | Security Support |
|:---|:---:|:---|
| `0.1.x` | Active | Full security updates and patches |
| `< 0.1.0` | End of Life | Not supported |

---

## Reporting a Vulnerability

Please report potential security or safety vulnerabilities privately. **Do not create public GitHub issues for undisclosed security flaws.**

### Reporting Channels:
1. **Email (Primary)**: [`security@logihertz.com`](mailto:security@logihertz.com)
2. **Operations (Escalation)**: [`ops@logihertz.com`](mailto:ops@logihertz.com)

### When submitting a report, please include:
- A clear technical description of the vulnerability and its real-time or security impact.
- Affected Linux kernel version (e.g., Linux 6.6.y-rt) and target SoC architecture (e.g., Tegra234 / ARM64).
- Reproduction steps, cyclictest telemetry, or minimal proof-of-concept configuration.
- Any suggested patches or workarounds.

---

## Service Level Agreements (SLA)

| Milestone | Target Response Time |
|:---|:---:|
| **Initial Acknowledgment** | Within 48 hours |
| **Triage & Severity Classification** | Within 3 business days |
| **Patch Development & Private Verification** | Within 5 business days |
| **Public Advisory & Coordinated Release** | Within 14 calendar days |

---

## Disclosure Guidelines

- Please allow sufficient time for patch validation on physical hardware before public disclosure.
- Ensure test artifacts do not contain proprietary firmware binaries or confidential keys.
- Logihertz Systems acknowledges security researchers in our release notes and `CHANGELOG.md`.
