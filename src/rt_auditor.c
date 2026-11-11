#include "rt_auditor.h"
#include <stdio.h>
#include <string.h>

const RuleDef g_rt_rules[10] = {
    {
        .id = "LH-RT-001",
        .title = "Full real-time preemption disabled (CONFIG_PREEMPT_RT)",
        .description = "Kernel lacks CONFIG_PREEMPT_RT=y or runs in voluntary/server preemption mode, permitting unbounded kernel-space latencies.",
        .cwe = "CWE-400",
        .weight = 25,
        .severity = "CRITICAL",
        .recommendation = "Enable CONFIG_PREEMPT_RT=y and set preempt_mode=\"full\" in kernel configuration."
    },
    {
        .id = "LH-RT-002",
        .title = "Unbounded SCHED_FIFO CPU starvation risk (RT throttling disabled)",
        .description = "sched_rt_runtime_us is disabled (-1) or bandwidth ratio exceeds 0.95, risking total core lockup during thread runaway.",
        .cwe = "CWE-833",
        .weight = 25,
        .severity = "CRITICAL",
        .recommendation = "Configure sched_rt_runtime_us to 950000 with sched_rt_period_us=1000000 (ratio <= 0.95)."
    },
    {
        .id = "LH-RT-003",
        .title = "Worst-case cyclictest latency exceeds deterministic ceiling (> 50us)",
        .description = "Observed maximum scheduling latency exceeds the 50 microsecond deterministic ceiling required for hard real-time control.",
        .cwe = "CWE-662",
        .weight = 25,
        .severity = "CRITICAL",
        .recommendation = "Tune CPU core isolation, forced IRQ threading, and disable deep C-states to keep max latency <= 50us."
    },
    {
        .id = "LH-RT-004",
        .title = "Missing CPU core isolation for real-time workload execution",
        .description = "Kernel cmdline lacks isolcpus, nohz_full, or rcu_nocbs parameters, allowing non-RT tasks and timer ticks to disrupt RT cores.",
        .cwe = "CWE-400",
        .weight = 10,
        .severity = "HIGH",
        .recommendation = "Configure isolcpus=2-7, nohz_full=2-7, and rcu_nocbs=2-7 in kernel command line."
    },
    {
        .id = "LH-RT-005",
        .title = "Forced interrupt threading disabled on real-time kernel",
        .description = "CONFIG_IRQ_FORCED_THREADING is disabled or threadirqs cmdline parameter is absent, causing hardirqs to delay RT threads.",
        .cwe = "CWE-667",
        .weight = 10,
        .severity = "HIGH",
        .recommendation = "Enable CONFIG_IRQ_FORCED_THREADING=y and pass threadirqs on kernel cmdline."
    },
    {
        .id = "LH-RT-006",
        .title = "Dynamic CPU frequency scaling or deep C-state sleep enabled",
        .description = "cpufreq governor is not performance or max_cstate > 0, introducing milliseconds of wake-up transition jitter.",
        .cwe = "CWE-400",
        .weight = 10,
        .severity = "HIGH",
        .recommendation = "Set cpufreq_governor=\"performance\" and limit max_cstate=0 via idle kernel parameters."
    },
    {
        .id = "LH-RT-007",
        .title = "Memory paging or NUMA balancing active without mlockall guard",
        .description = "vm_swappiness > 0 or numa_balancing is enabled, causing major page faults and memory migration stalls on RT threads.",
        .cwe = "CWE-770",
        .weight = 10,
        .severity = "HIGH",
        .recommendation = "Configure vm.swappiness=0 and numa_balancing_enabled=false."
    },
    {
        .id = "LH-RT-008",
        .title = "Suboptimal timer tick resolution (< 1000 Hz) or missing high-res timers",
        .description = "CONFIG_HZ is configured below 1000 Hz or high_res_timers are disabled, reducing timer precision to multiple milliseconds.",
        .cwe = "CWE-662",
        .weight = 4,
        .severity = "MEDIUM",
        .recommendation = "Configure CONFIG_HZ=1000 and enable CONFIG_HIGH_RES_TIMERS=y."
    },
    {
        .id = "LH-RT-009",
        .title = "Unhandled hardware/firmware latency spikes (EFI runtime / RAS daemon)",
        .description = "EFI runtime services or hardware RAS daemon interrupts execute on isolated RT cores, introducing unbounded TrustZone/SMI pauses.",
        .cwe = "CWE-250",
        .weight = 4,
        .severity = "MEDIUM",
        .recommendation = "Set efi_runtime_enabled=false or pin RAS/telemetry interrupts exclusively to housekeeping cores."
    },
    {
        .id = "LH-RT-010",
        .title = "Missing hardware watchdog recovery or lockdep deadlock telemetry",
        .description = "Hardware watchdog recovery is disabled or RT mutex debug verification is not certified for deadlock recovery.",
        .cwe = "CWE-755",
        .weight = 1,
        .severity = "LOW",
        .recommendation = "Enable hardware_watchdog_enabled=true and verify rt_mutex_debug_verified=true."
    }
};

static void add_finding(
    AuditResult *res,
    int rule_idx,
    const char *evidence
) {
    if (res->total_findings >= 16) {
        return;
    }

    const RuleDef *r = &g_rt_rules[rule_idx];
    AuditFinding *f = &res->findings[res->total_findings++];

    snprintf(f->rule_id, sizeof(f->rule_id), "%s", r->id);
    snprintf(f->severity, sizeof(f->severity), "%s", r->severity);
    snprintf(f->cwe, sizeof(f->cwe), "%s", r->cwe);
    snprintf(f->title, sizeof(f->title), "%s", r->title);
    snprintf(f->description, sizeof(f->description), "%s", r->description);
    snprintf(f->recommendation, sizeof(f->recommendation), "%s", r->recommendation);
    snprintf(f->evidence, sizeof(f->evidence), "%.127s", evidence);

    if (strcmp(r->severity, "CRITICAL") == 0) res->critical_count++;
    else if (strcmp(r->severity, "HIGH") == 0) res->high_count++;
    else if (strcmp(r->severity, "MEDIUM") == 0) res->medium_count++;
    else if (strcmp(r->severity, "LOW") == 0) res->low_count++;
}

int audit_kernel_config(const KernelConfig *cfg, const char *target_name, AuditResult *out)
{
    if (!cfg || !out) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    snprintf(out->target, sizeof(out->target), "%s", target_name ? target_name : "in-memory-config");

    char ev[512];

    /* LH-RT-001: CONFIG_PREEMPT_RT & preempt_mode */
    if (strcmp(cfg->config_preempt_rt, "y") != 0 || strcmp(cfg->preempt_mode, "full") != 0) {
        snprintf(ev, sizeof(ev), "CONFIG_PREEMPT_RT=\"%s\", preempt_mode=\"%s\"", cfg->config_preempt_rt, cfg->preempt_mode);
        add_finding(out, 0, ev);
    }

    /* LH-RT-002: sched_rt_runtime_us & bandwidth ratio */
    double rt_ratio = (cfg->sched_rt_period_us > 0) ? ((double)cfg->sched_rt_runtime_us / (double)cfg->sched_rt_period_us) : 1.0;
    if (cfg->sched_rt_runtime_us < 0 || rt_ratio > 0.95) {
        snprintf(ev, sizeof(ev), "runtime=%ld, period=%ld (ratio=%.2f > 0.95)", cfg->sched_rt_runtime_us, cfg->sched_rt_period_us, rt_ratio);
        add_finding(out, 1, ev);
    }

    /* LH-RT-003: max cyclictest latency ceiling */
    if (cfg->max_latency_us > LH_DEFAULT_MAX_LATENCY_CEILING_US) {
        snprintf(ev, sizeof(ev), "max_latency=%.1fus (ceiling=%.1fus)", cfg->max_latency_us, LH_DEFAULT_MAX_LATENCY_CEILING_US);
        add_finding(out, 2, ev);
    }

    /* LH-RT-004: CPU core isolation (isolcpus, nohz_full, rcu_nocbs) */
    if (strlen(cfg->isolcpus) == 0 || strlen(cfg->nohz_full) == 0 || strlen(cfg->rcu_nocbs) == 0) {
        snprintf(ev, sizeof(ev), "isolcpus=\"%s\", nohz_full=\"%s\", rcu_nocbs=\"%s\"", cfg->isolcpus, cfg->nohz_full, cfg->rcu_nocbs);
        add_finding(out, 3, ev);
    }

    /* LH-RT-005: Forced IRQ threading */
    if (strcmp(cfg->config_irq_forced_threading, "y") != 0 || !cfg->threadirqs) {
        snprintf(ev, sizeof(ev), "CONFIG_IRQ_FORCED_THREADING=\"%s\", threadirqs=%s", cfg->config_irq_forced_threading, cfg->threadirqs ? "true" : "false");
        add_finding(out, 4, ev);
    }

    /* LH-RT-006: cpufreq governor & max_cstate */
    if (strcmp(cfg->cpufreq_governor, "performance") != 0 || cfg->max_cstate > 0) {
        snprintf(ev, sizeof(ev), "governor=\"%s\", max_cstate=%d (required: performance, 0)", cfg->cpufreq_governor, cfg->max_cstate);
        add_finding(out, 5, ev);
    }

    /* LH-RT-007: vm_swappiness & numa_balancing */
    if (cfg->vm_swappiness > 0 || cfg->numa_balancing_enabled) {
        snprintf(ev, sizeof(ev), "vm_swappiness=%d, numa_balancing=%s", cfg->vm_swappiness, cfg->numa_balancing_enabled ? "true" : "false");
        add_finding(out, 6, ev);
    }

    /* LH-RT-008: CONFIG_HZ & high_res_timers */
    if (cfg->config_hz < 1000 || !cfg->high_res_timers_enabled) {
        snprintf(ev, sizeof(ev), "CONFIG_HZ=%d, high_res_timers=%s (required: >=1000, true)", cfg->config_hz, cfg->high_res_timers_enabled ? "true" : "false");
        add_finding(out, 7, ev);
    }

    /* LH-RT-009: EFI runtime & RAS daemon on RT cores */
    if (cfg->efi_runtime_enabled || cfg->ras_daemon_irq_on_rt_cores) {
        snprintf(ev, sizeof(ev), "efi_runtime=%s, ras_daemon_on_rt=%s", cfg->efi_runtime_enabled ? "true" : "false", cfg->ras_daemon_irq_on_rt_cores ? "true" : "false");
        add_finding(out, 8, ev);
    }

    /* LH-RT-010: Hardware watchdog & RT mutex debug */
    if (!cfg->hardware_watchdog_enabled || !cfg->rt_mutex_debug_verified) {
        snprintf(ev, sizeof(ev), "watchdog=%s, rt_mutex_debug=%s", cfg->hardware_watchdog_enabled ? "true" : "false", cfg->rt_mutex_debug_verified ? "true" : "false");
        add_finding(out, 9, ev);
    }

    int deduction = 0;
    for (int i = 0; i < out->total_findings; i++) {
        for (int r = 0; r < 10; r++) {
            if (strcmp(out->findings[i].rule_id, g_rt_rules[r].id) == 0) {
                deduction += g_rt_rules[r].weight;
                break;
            }
        }
    }

    out->posture_score = 100 - deduction;
    if (out->posture_score < 0) {
        out->posture_score = 0;
    }

    return 0;
}
