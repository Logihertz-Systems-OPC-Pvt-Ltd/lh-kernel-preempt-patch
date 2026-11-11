# Contributing to Logihertz PREEMPT_RT Kernel Patchset (`lh-kernel-preempt-patch`)

Thank you for contributing to **`lh-kernel-preempt-patch`**! We maintain strict
deterministic real-time engineering standards, clean-room C11 code quality,
and zero external runtime dependencies.

---

## 1. Zero External Dependencies & C11 Mandate

- **Strict C11 Standard**: All C code in `src/`, `include/`, and `tests/` must adhere to **ISO/IEC 9899:2011 (C11)**.
- **Zero Third-Party Libraries**: Linking external third-party libraries (e.g. cJSON, libyaml, glib, boost) is forbidden. Use only standard `libc` and `-lm`.
- **Compiler Cleanliness**: Code must compile cleanly with **zero warnings** under both GCC and Clang with:
  ```bash
  -std=c11 -O2 -Wall -Wextra -Werror -pedantic
  ```
- **Memory Safety**: No memory leaks or invalid pointer dereferences. All allocations must be bounded and explicitly freed.

---

## 2. Kernel Patch Series Guidelines (`patches/`)

When submitting or updating real-time patches for Linux 6.6 LTS on NVIDIA Jetson Orin (`tegra234`):
1. Format patches as clean unified diffs (`diff -uprN` or `git format-patch`).
2. Include full commit message explaining:
   - Root cause of non-deterministic latency.
   - Specific subsystem affected (e.g. GICv3 IRQ threading, nvgpu mutex, scheduler throttling).
   - Worst-case execution time (WCET) impact before and after.
3. Include valid Developer's Certificate of Origin (DCO):
   `Signed-off-by: Your Name <your.email@example.com>`
4. Update `patches/series` maintaining correct sequential patch order.
5. Verify patches pass validation via `bin/lh-preempt verify-patches patches`.

---

## 3. Real-Time Posture Auditor Guidelines (`LH-RT-001` .. `LH-RT-010`)

When proposing changes or new detection rules in `src/rt_auditor.c`:
1. Assign a unique rule ID (`LH-RT-xxx`).
2. Map the vulnerability to an official CWE (e.g. CWE-400, CWE-833, CWE-662, CWE-667).
3. Assign severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and corresponding weight.
4. Update `fixtures/vulnerable_rt_kernel.json` to trigger the rule and `fixtures/hardened_rt_kernel.json` to pass it cleanly.
5. Add deterministic assertions in `tests/test_runner.c`.

---

## 4. Local Build & Test Workflow

```bash
# Clean build artifacts
make clean

# Build CLI binary (bin/lh-preempt) with GCC
make CC=gcc

# Build and run the test suite
make CC=gcc test

# Build with Clang (if installed)
make CC=clang test

# Run CLI verification on patches
bin/lh-preempt verify-patches patches

# Run CLI posture audit on hardened fixture
bin/lh-preempt scan fixtures/hardened_rt_kernel.json --format table

# Run CLI jitter analysis
bin/lh-preempt analyze-jitter fixtures/sample_cyclictest.json
```

---

## 5. Commit & Attribution Standards

- Maintainer attribution: `Sameer Tawade <ops@logihertz.com>`
- Organization identity: `logihertzsystems <ops@logihertz.com>`
- Use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
