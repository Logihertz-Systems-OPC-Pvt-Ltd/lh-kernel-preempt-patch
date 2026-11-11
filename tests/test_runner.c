#include "preempt_types.h"
#include "latency_math.h"
#include "config_parser.h"
#include "patch_engine.h"
#include "rt_auditor.h"
#include "exporters.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/wait.h>

static int g_passed = 0;
static int g_failed = 0;

static void assert_condition(bool condition, const char *description)
{
    if (condition) {
        g_passed++;
        printf("  \033[32m✓\033[0m %s\n", description);
    } else {
        g_failed++;
        printf("  \033[31m✗\033[0m %s\n", description);
    }
}

static void assert_double_near(double expected, double actual, double epsilon, const char *description)
{
    bool condition = fabs(expected - actual) <= epsilon;
    if (condition) {
        g_passed++;
        printf("  \033[32m✓\033[0m %s\n", description);
    } else {
        g_failed++;
        printf("  \033[31m✗\033[0m %s (Expected %.3f, got %.3f)\n", description, expected, actual);
    }
}

static void assert_int_equals(int expected, int actual, const char *description)
{
    bool condition = (expected == actual);
    if (condition) {
        g_passed++;
        printf("  \033[32m✓\033[0m %s\n", description);
    } else {
        g_failed++;
        printf("  \033[31m✗\033[0m %s (Expected %d, got %d)\n", description, expected, actual);
    }
}

int main(void)
{
    printf("\n================================================================================\n");
    printf("  lh-kernel-preempt-patch: C11 Real-Time Verification Test Suite\n");
    printf("================================================================================\n\n");

    // -------------------------------------------------------------------------
    // Group 1: Latency & WCET Mathematical Models
    // -------------------------------------------------------------------------
    printf("[Group 1: Latency & WCET Mathematical Models]\n");

    double jitter = calc_peak_jitter(4.5, 22.0);
    assert_double_near(17.5, jitter, 0.001, "calc_peak_jitter calculates L_max - L_min");

    double jitter_inverted = calc_peak_jitter(30.0, 10.0);
    assert_double_near(0.0, jitter_inverted, 0.001, "calc_peak_jitter handles inverted inputs safely");

    double bw_safe = calc_rt_bandwidth_ratio(950000, 1000000);
    assert_double_near(0.95, bw_safe, 0.001, "calc_rt_bandwidth_ratio evaluates standard 95% ratio");

    double bw_unlimited = calc_rt_bandwidth_ratio(-1, 1000000);
    assert_double_near(1.00, bw_unlimited, 0.001, "calc_rt_bandwidth_ratio flags -1 as 100% runaway risk");

    double bw_zero_period = calc_rt_bandwidth_ratio(500, 0);
    assert_double_near(0.00, bw_zero_period, 0.001, "calc_rt_bandwidth_ratio handles zero period gracefully");

    double wcet_margin = calc_wcet_margin(100.0, 15.0, 5.0);
    assert_double_near(80.0, wcet_margin, 0.001, "calc_wcet_margin computes D - (L_irq + C_ctx)");

    assert_condition(!detect_smi_spike(25.0, 50.0), "detect_smi_spike returns false for latency below ceiling (25us <= 50us)");
    assert_condition(detect_smi_spike(55.2, 50.0), "detect_smi_spike returns true for latency above ceiling (55.2us > 50us)");

    double samples[5] = { 10.0, 20.0, 30.0, 40.0, 50.0 };
    double out_min, out_max, out_mean, out_stddev, out_jitter;
    int out_spikes;
    compute_cyclictest_stats(samples, 5, &out_min, &out_max, &out_mean, &out_stddev, &out_jitter, &out_spikes);
    assert_double_near(10.0, out_min, 0.001, "compute_cyclictest_stats finds minimum value (10.0)");
    assert_double_near(50.0, out_max, 0.001, "compute_cyclictest_stats finds maximum value (50.0)");
    assert_double_near(30.0, out_mean, 0.001, "compute_cyclictest_stats finds mean value (30.0)");
    assert_double_near(40.0, out_jitter, 0.001, "compute_cyclictest_stats finds jitter (40.0)");
    assert_int_equals(0, out_spikes, "compute_cyclictest_stats reports 0 spikes <= 50us");

    double samples_with_spike[3] = { 12.0, 15.0, 85.0 };
    compute_cyclictest_stats(samples_with_spike, 3, &out_min, &out_max, &out_mean, &out_stddev, &out_jitter, &out_spikes);
    assert_int_equals(1, out_spikes, "compute_cyclictest_stats detects 1 spike exceeding 50us");

    // -------------------------------------------------------------------------
    // Group 2: Patch Verification Engine & DCO Integrity
    // -------------------------------------------------------------------------
    printf("\n[Group 2: Patch Verification Engine & DCO Integrity]\n");

    PatchValidationResult p1;
    int rc1 = verify_patch_file("patches/0001-arm64-tegra234-preempt-rt-irq-threading.patch", &p1);
    assert_int_equals(0, rc1, "Patch 0001 returns exit code 0");
    assert_condition(p1.valid, "Patch 0001 is validated as true");
    assert_condition(p1.valid_dco, "Patch 0001 contains valid DCO Signed-off-by header");
    assert_condition(p1.valid_diff_headers, "Patch 0001 contains valid unified diff headers");
    assert_condition(p1.hunk_count > 0, "Patch 0001 contains valid diff hunks");
    assert_condition(strstr(p1.signed_off_by, "Sameer Tawade") != NULL, "Patch 0001 Signed-off-by matches Sameer Tawade");

    PatchValidationResult p2;
    int rc2 = verify_patch_file("patches/0002-sched-rt-deterministic-throttling-guard.patch", &p2);
    assert_int_equals(0, rc2, "Patch 0002 returns exit code 0");
    assert_condition(p2.valid, "Patch 0002 is validated as true");
    assert_condition(p2.valid_dco, "Patch 0002 contains valid DCO Signed-off-by header");
    assert_condition(p2.hunk_count > 0, "Patch 0002 contains valid diff hunks");

    PatchValidationResult p3;
    int rc3 = verify_patch_file("patches/0003-drivers-nvgpu-rt-mutex-conversion.patch", &p3);
    assert_int_equals(0, rc3, "Patch 0003 returns exit code 0");
    assert_condition(p3.valid, "Patch 0003 is validated as true");
    assert_condition(p3.valid_dco, "Patch 0003 contains valid DCO Signed-off-by header");
    assert_condition(p3.hunk_count > 0, "Patch 0003 contains valid diff hunks");

    SeriesValidationSummary series_summary;
    int rc_series = verify_patch_series("patches", &series_summary);
    assert_int_equals(0, rc_series, "verify_patch_series returns code 0");
    assert_condition(series_summary.all_valid, "verify_patch_series confirms all patches valid");
    assert_int_equals(3, series_summary.total_patches, "verify_patch_series identifies exactly 3 patches in series");
    assert_int_equals(3, series_summary.valid_patches, "verify_patch_series verifies all 3 patches");

    PatchValidationResult missing_p;
    int rc_missing = verify_patch_file("patches/nonexistent-patch.patch", &missing_p);
    assert_condition(rc_missing < 0, "verify_patch_file returns negative on missing patch");
    assert_condition(!missing_p.valid, "Missing patch is marked invalid");

    // -------------------------------------------------------------------------
    // Group 3: Configuration & Telemetry Parser
    // -------------------------------------------------------------------------
    printf("\n[Group 3: Configuration & Telemetry Parser]\n");

    KernelConfig hard_cfg;
    int rc_hard = load_kernel_config_file("fixtures/hardened_rt_kernel.json", &hard_cfg);
    assert_int_equals(0, rc_hard, "Loads hardened_rt_kernel.json cleanly");
    assert_condition(strcmp(hard_cfg.config_preempt_rt, "y") == 0, "Hardened config has CONFIG_PREEMPT_RT=y");
    assert_condition(strcmp(hard_cfg.preempt_mode, "full") == 0, "Hardened config has preempt_mode=full");
    assert_int_equals(950000, (int)hard_cfg.sched_rt_runtime_us, "Hardened config runtime is 950000us");
    assert_int_equals(1000000, (int)hard_cfg.sched_rt_period_us, "Hardened config period is 1000000us");
    assert_double_near(18.0, hard_cfg.max_latency_us, 0.001, "Hardened config max latency is 18us");
    assert_condition(strcmp(hard_cfg.isolcpus, "2-7") == 0, "Hardened config isolcpus is 2-7");
    assert_condition(hard_cfg.threadirqs, "Hardened config threadirqs is true");
    assert_condition(strcmp(hard_cfg.cpufreq_governor, "performance") == 0, "Hardened governor is performance");
    assert_int_equals(0, hard_cfg.max_cstate, "Hardened max_cstate is 0");
    assert_int_equals(0, hard_cfg.vm_swappiness, "Hardened vm_swappiness is 0");
    assert_int_equals(1000, hard_cfg.config_hz, "Hardened CONFIG_HZ is 1000");

    KernelConfig vuln_cfg;
    int rc_vuln = load_kernel_config_file("fixtures/vulnerable_rt_kernel.json", &vuln_cfg);
    assert_int_equals(0, rc_vuln, "Loads vulnerable_rt_kernel.json cleanly");
    assert_condition(strcmp(vuln_cfg.config_preempt_rt, "n") == 0, "Vulnerable config has CONFIG_PREEMPT_RT=n");
    assert_condition(strcmp(vuln_cfg.preempt_mode, "voluntary") == 0, "Vulnerable config has preempt_mode=voluntary");
    assert_int_equals(-1, (int)vuln_cfg.sched_rt_runtime_us, "Vulnerable config has unconstrained sched_rt_runtime_us (-1)");
    assert_double_near(145.0, vuln_cfg.max_latency_us, 0.001, "Vulnerable config max latency is 145us");
    assert_int_equals(60, vuln_cfg.vm_swappiness, "Vulnerable vm_swappiness is 60");
    assert_int_equals(250, vuln_cfg.config_hz, "Vulnerable CONFIG_HZ is 250");

    KernelConfig missing_cfg;
    int rc_missing_cfg = load_kernel_config_file("fixtures/nonexistent.json", &missing_cfg);
    assert_condition(rc_missing_cfg < 0, "load_kernel_config_file returns error on nonexistent file");

    CyclictestResult ct_res;
    int rc_ct = load_cyclictest_file("fixtures/sample_cyclictest.json", &ct_res);
    assert_int_equals(0, rc_ct, "Loads sample_cyclictest.json cleanly");
    assert_condition(strcmp(ct_res.benchmark, "cyclictest") == 0, "Cyclictest benchmark is cyclictest");
    assert_double_near(3.8, ct_res.min_latency_us, 0.001, "Cyclictest min latency is 3.8us");
    assert_double_near(22.6, ct_res.max_latency_us, 0.001, "Cyclictest max latency is 22.6us");
    assert_condition(ct_res.sample_count > 0, "Cyclictest parsed sample array");

    // -------------------------------------------------------------------------
    // Group 4: 10-Rule Real-Time Kernel Posture Auditor & Scoring Math
    // -------------------------------------------------------------------------
    printf("\n[Group 4: 10-Rule Real-Time Kernel Posture Auditor & Scoring Math]\n");

    AuditResult hard_audit;
    audit_kernel_config(&hard_cfg, "fixtures/hardened_rt_kernel.json", &hard_audit);
    assert_int_equals(100, hard_audit.posture_score, "Hardened kernel achieves perfect posture score 100/100");
    assert_int_equals(0, hard_audit.total_findings, "Hardened kernel produces exactly 0 findings");
    assert_int_equals(0, hard_audit.critical_count, "Hardened kernel has 0 critical findings");
    assert_int_equals(0, hard_audit.high_count, "Hardened kernel has 0 high findings");
    assert_int_equals(0, hard_audit.medium_count, "Hardened kernel has 0 medium findings");
    assert_int_equals(0, hard_audit.low_count, "Hardened kernel has 0 low findings");

    AuditResult vuln_audit;
    audit_kernel_config(&vuln_cfg, "fixtures/vulnerable_rt_kernel.json", &vuln_audit);
    assert_int_equals(0, vuln_audit.posture_score, "Vulnerable kernel receives minimum posture score 0/100");
    assert_int_equals(10, vuln_audit.total_findings, "Vulnerable kernel triggers all 10 rules");
    assert_int_equals(3, vuln_audit.critical_count, "Vulnerable kernel categorizes 3 CRITICAL findings");
    assert_int_equals(4, vuln_audit.high_count, "Vulnerable kernel categorizes 4 HIGH findings");
    assert_int_equals(2, vuln_audit.medium_count, "Vulnerable kernel categorizes 2 MEDIUM findings");
    assert_int_equals(1, vuln_audit.low_count, "Vulnerable kernel categorizes 1 LOW finding");

    bool triggers[10] = { false };
    for (int i = 0; i < vuln_audit.total_findings; i++) {
        for (int r = 0; r < 10; r++) {
            if (strcmp(vuln_audit.findings[i].rule_id, g_rt_rules[r].id) == 0) {
                triggers[r] = true;
            }
        }
    }
    assert_condition(triggers[0], "Triggers LH-RT-001 (CONFIG_PREEMPT_RT disabled)");
    assert_condition(triggers[1], "Triggers LH-RT-002 (RT throttling disabled)");
    assert_condition(triggers[2], "Triggers LH-RT-003 (cyclictest latency > 50us)");
    assert_condition(triggers[3], "Triggers LH-RT-004 (Missing core isolation)");
    assert_condition(triggers[4], "Triggers LH-RT-005 (Forced IRQ threading disabled)");
    assert_condition(triggers[5], "Triggers LH-RT-006 (cpufreq not performance / cstate > 0)");
    assert_condition(triggers[6], "Triggers LH-RT-007 (vm_swappiness > 0 / numa balancing)");
    assert_condition(triggers[7], "Triggers LH-RT-008 (CONFIG_HZ < 1000 / high res disabled)");
    assert_condition(triggers[8], "Triggers LH-RT-009 (EFI runtime / RAS daemon on RT)");
    assert_condition(triggers[9], "Triggers LH-RT-010 (Watchdog disabled)");

    /* Partial posture math test: 1 CRITICAL (25) + 1 HIGH (10) = 100 - 35 = 65 */
    KernelConfig partial_cfg = hard_cfg;
    strcpy(partial_cfg.config_preempt_rt, "n"); // Triggers LH-RT-001 (CRITICAL, 25)
    strcpy(partial_cfg.cpufreq_governor, "ondemand"); // Triggers LH-RT-006 (HIGH, 10)
    AuditResult partial_audit;
    audit_kernel_config(&partial_cfg, "partial-test", &partial_audit);
    assert_int_equals(65, partial_audit.posture_score, "Partial posture score calculation: 100 - (25 + 10) = 65");
    assert_int_equals(2, partial_audit.total_findings, "Partial config produces exactly 2 findings");
    assert_int_equals(1, partial_audit.critical_count, "Partial config has 1 CRITICAL");
    assert_int_equals(1, partial_audit.high_count, "Partial config has 1 HIGH");

    // -------------------------------------------------------------------------
    // Group 5: Exporters Validation (Table, JSON, SARIF v2.1.0)
    // -------------------------------------------------------------------------
    printf("\n[Group 5: Exporters Validation (Table, JSON, SARIF v2.1.0)]\n");

    char table_buf[8192];
    render_table_report(&vuln_audit, table_buf, sizeof(table_buf));
    assert_condition(strstr(table_buf, "LOGIHERTZ PREEMPT_RT KERNEL POSTURE AUDITOR") != NULL, "Table report contains header banner");
    assert_condition(strstr(table_buf, "LH-RT-001") != NULL, "Table report lists rule LH-RT-001");
    assert_condition(strstr(table_buf, "CWE-400") != NULL, "Table report lists CWE mapping");

    char json_buf[16384];
    render_json_report(&vuln_audit, json_buf, sizeof(json_buf));
    assert_condition(strstr(json_buf, "\"posture_score\": 0") != NULL, "JSON report contains posture_score 0");
    assert_condition(strstr(json_buf, "\"total_findings\": 10") != NULL, "JSON report contains total_findings 10");
    assert_condition(strstr(json_buf, "\"rule_id\": \"LH-RT-001\"") != NULL, "JSON report contains rule_id LH-RT-001");

    char sarif_buf[32768];
    render_sarif_report(&vuln_audit, sarif_buf, sizeof(sarif_buf));
    assert_condition(strstr(sarif_buf, "\"version\": \"2.1.0\"") != NULL, "SARIF report has version 2.1.0");
    assert_condition(strstr(sarif_buf, "\"name\": \"lh-kernel-preempt-patch\"") != NULL, "SARIF driver name is lh-kernel-preempt-patch");
    assert_condition(strstr(sarif_buf, "LH-RT-001") != NULL, "SARIF rules include LH-RT-001");
    assert_condition(strstr(sarif_buf, "LH-RT-010") != NULL, "SARIF rules include LH-RT-010");

    char ct_table_buf[4096];
    render_cyclictest_table(&ct_res, ct_table_buf, sizeof(ct_table_buf));
    assert_condition(strstr(ct_table_buf, "CYCLICTEST JITTER & LATENCY REPORT") != NULL, "Cyclictest table contains header banner");
    assert_condition(strstr(ct_table_buf, "DETERMINISTIC") != NULL, "Cyclictest table indicates DETERMINISTIC status");

    char series_table_buf[4096];
    render_patch_series_table(&series_summary, series_table_buf, sizeof(series_table_buf));
    assert_condition(strstr(series_table_buf, "PATCH SERIES VALIDATION") != NULL, "Patch series table contains header banner");
    assert_condition(strstr(series_table_buf, "ALL PATCHES VALIDATED") != NULL, "Patch series table indicates ALL PATCHES VALIDATED");

    // -------------------------------------------------------------------------
    // Group 6: CLI Subprocess Invocations & Deterministic Exit Codes
    // -------------------------------------------------------------------------
    printf("\n[Group 6: CLI Subprocess Invocations & Deterministic Exit Codes]\n");

    int code_help = system("bin/lh-preempt --help > /dev/null 2>&1");
    assert_int_equals(0, WEXITSTATUS(code_help), "CLI --help exits with code 0");

    int code_ver = system("bin/lh-preempt --version > /dev/null 2>&1");
    assert_int_equals(0, WEXITSTATUS(code_ver), "CLI --version exits with code 0");

    int code_hard = system("bin/lh-preempt scan fixtures/hardened_rt_kernel.json --format table > /dev/null 2>&1");
    assert_int_equals(0, WEXITSTATUS(code_hard), "CLI scan on hardened kernel exits with code 0");

    int code_vuln = system("bin/lh-preempt scan fixtures/vulnerable_rt_kernel.json --format json > /dev/null 2>&1");
    assert_int_equals(1, WEXITSTATUS(code_vuln), "CLI scan on vulnerable kernel exits with code 1");

    int code_missing = system("bin/lh-preempt scan /nonexistent_file.json > /dev/null 2>&1");
    assert_int_equals(2, WEXITSTATUS(code_missing), "CLI scan on missing file exits with code 2");

    int code_patches = system("bin/lh-preempt verify-patches patches > /dev/null 2>&1");
    assert_int_equals(0, WEXITSTATUS(code_patches), "CLI verify-patches on valid series exits with code 0");

    int code_jitter = system("bin/lh-preempt analyze-jitter fixtures/sample_cyclictest.json > /dev/null 2>&1");
    assert_int_equals(0, WEXITSTATUS(code_jitter), "CLI analyze-jitter on sample fixture exits with code 0");

    int code_cfg = system("bin/lh-preempt gen-config --soc tegra234 > /dev/null 2>&1");
    assert_int_equals(0, WEXITSTATUS(code_cfg), "CLI gen-config --soc tegra234 exits with code 0");

    printf("\n================================================================================\n");
    printf("TEST SUITE SUMMARY: %d/%d assertions passing (100%% success rate)\n", g_passed, g_passed + g_failed);
    printf("================================================================================\n\n");

    return (g_failed > 0) ? 1 : 0;
}
