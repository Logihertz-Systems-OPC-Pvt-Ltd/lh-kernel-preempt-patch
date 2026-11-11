#include "preempt_types.h"
#include "config_parser.h"
#include "patch_engine.h"
#include "rt_auditor.h"
#include "exporters.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_version(void)
{
    printf("lh-preempt v%s (Clean-room C11)\n", LH_PREEMPT_VERSION);
    printf("%s\n", LH_ORGANIZATION);
    printf("%s\n", LH_ORG_URL);
}

static void print_help(void)
{
    printf("lh-preempt: Enterprise Zero-Dependency PREEMPT_RT Hardening & Jitter Analyzer\n");
    printf("Version: %s | %s\n\n", LH_PREEMPT_VERSION, LH_ORGANIZATION);
    printf("USAGE:\n");
    printf("  lh-preempt scan <policy.json> [options]\n");
    printf("  lh-preempt verify-patches <patches_dir>\n");
    printf("  lh-preempt analyze-jitter <cyclictest.json>\n");
    printf("  lh-preempt gen-config --soc <tegra234>\n");
    printf("  lh-preempt --version\n");
    printf("  lh-preempt --help\n\n");
    printf("COMMANDS:\n");
    printf("  scan             Audit kernel configuration against rules LH-RT-001..010\n");
    printf("  verify-patches   Validate unified diff headers and DCO signatures in patch series\n");
    printf("  analyze-jitter   Compute cyclictest statistical latency metrics and flag SMI spikes\n");
    printf("  gen-config       Output recommended Linux 6.6 LTS PREEMPT_RT Kconfig & cmdline\n\n");
    printf("SCAN OPTIONS:\n");
    printf("  --format, -f <table|json|sarif>   Report format (default: table)\n");
    printf("  --output, -o <path>               Optional destination file path\n");
}

static int handle_scan(int argc, char **argv)
{
    const char *target = NULL;
    const char *format = "table";
    const char *output = NULL;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--format") == 0 || strcmp(argv[i], "-f") == 0) {
            if (i + 1 < argc) format = argv[++i];
        } else if (strncmp(argv[i], "--format=", 9) == 0) {
            format = argv[i] + 9;
        } else if (strcmp(argv[i], "--output") == 0 || strcmp(argv[i], "-o") == 0) {
            if (i + 1 < argc) output = argv[++i];
        } else if (strncmp(argv[i], "--output=", 9) == 0) {
            output = argv[i] + 9;
        } else if (argv[i][0] != '-' && target == NULL) {
            target = argv[i];
        } else {
            fprintf(stderr, "Error: Unrecognized option '%s'.\n", argv[i]);
            return EXIT_USAGE_ERROR;
        }
    }

    if (!target) {
        fprintf(stderr, "Error: Missing target policy JSON file path.\n");
        fprintf(stderr, "Usage: lh-preempt scan <policy.json> [--format table|json|sarif]\n");
        return EXIT_USAGE_ERROR;
    }

    KernelConfig cfg;
    int rc = load_kernel_config_file(target, &cfg);
    if (rc != 0) {
        fprintf(stderr, "Error: Failed to load/parse kernel config JSON: %s\n", target);
        return EXIT_USAGE_ERROR;
    }

    AuditResult result;
    audit_kernel_config(&cfg, target, &result);

    static char report_buf[65536];
    if (strcmp(format, "json") == 0) {
        render_json_report(&result, report_buf, sizeof(report_buf));
    } else if (strcmp(format, "sarif") == 0) {
        render_sarif_report(&result, report_buf, sizeof(report_buf));
    } else {
        render_table_report(&result, report_buf, sizeof(report_buf));
    }

    if (output) {
        FILE *fp = fopen(output, "w");
        if (!fp) {
            fprintf(stderr, "Error: Cannot write report to: %s\n", output);
            return EXIT_USAGE_ERROR;
        }
        fputs(report_buf, fp);
        fclose(fp);
        printf("Report successfully written to %s\n", output);
    } else {
        fputs(report_buf, stdout);
    }

    return (result.total_findings > 0) ? EXIT_POLICY_VIOLATION : EXIT_PASS;
}

static int handle_verify_patches(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Error: Missing patches directory path.\n");
        fprintf(stderr, "Usage: lh-preempt verify-patches <patches_dir>\n");
        return EXIT_USAGE_ERROR;
    }

    const char *patches_dir = argv[2];
    SeriesValidationSummary summary;
    int rc = verify_patch_series(patches_dir, &summary);
    if (rc < 0) {
        fprintf(stderr, "Error: Cannot open series file in: %s/series\n", patches_dir);
        return EXIT_USAGE_ERROR;
    }

    static char table_buf[8192];
    render_patch_series_table(&summary, table_buf, sizeof(table_buf));
    fputs(table_buf, stdout);

    return summary.all_valid ? EXIT_PASS : EXIT_POLICY_VIOLATION;
}

static int handle_analyze_jitter(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Error: Missing cyclictest JSON file path.\n");
        fprintf(stderr, "Usage: lh-preempt analyze-jitter <cyclictest.json>\n");
        return EXIT_USAGE_ERROR;
    }

    const char *cyclictest_path = argv[2];
    CyclictestResult res;
    int rc = load_cyclictest_file(cyclictest_path, &res);
    if (rc != 0) {
        fprintf(stderr, "Error: Failed to load cyclictest JSON file: %s\n", cyclictest_path);
        return EXIT_USAGE_ERROR;
    }

    static char table_buf[8192];
    render_cyclictest_table(&res, table_buf, sizeof(table_buf));
    fputs(table_buf, stdout);

    return (res.max_latency_us <= LH_DEFAULT_MAX_LATENCY_CEILING_US) ? EXIT_PASS : EXIT_POLICY_VIOLATION;
}

static int handle_gen_config(int argc, char **argv)
{
    const char *soc = "tegra234";
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--soc") == 0 && i + 1 < argc) {
            soc = argv[++i];
        } else if (strncmp(argv[i], "--soc=", 6) == 0) {
            soc = argv[i] + 6;
        }
    }

    if (strcmp(soc, "tegra234") != 0 && strcmp(soc, "orin") != 0) {
        fprintf(stderr, "Error: Unsupported SoC '%s'. Supported target: tegra234 (NVIDIA Jetson Orin)\n", soc);
        return EXIT_USAGE_ERROR;
    }

    printf("# ==============================================================================\n");
    printf("# Logihertz Systems: Linux 6.6 LTS PREEMPT_RT Configuration for %s\n", soc);
    printf("# Architecture: ARM64 / aarch64 (Cortex-A78AE / Carmel)\n");
    printf("# ==============================================================================\n\n");
    printf("# Kernel .config Fragment:\n");
    printf("CONFIG_PREEMPT_RT=y\n");
    printf("CONFIG_PREEMPT_RT_BASE=y\n");
    printf("CONFIG_HZ_1000=y\n");
    printf("CONFIG_HZ=1000\n");
    printf("CONFIG_HIGH_RES_TIMERS=y\n");
    printf("CONFIG_IRQ_FORCED_THREADING=y\n");
    printf("CONFIG_NO_HZ_FULL=y\n");
    printf("CONFIG_RCU_NOCB_CPU=y\n");
    printf("CONFIG_LOCKDEP=n\n");
    printf("CONFIG_PROVE_LOCKING=n\n");
    printf("CONFIG_DEBUG_RT_MUTEXES=y\n");
    printf("CONFIG_CPU_FREQ_DEFAULT_GOV_PERFORMANCE=y\n\n");
    printf("# Kernel Boot Command Line (extlinux.conf / cbo.dtb):\n");
    printf("isolcpus=2-7 nohz_full=2-7 rcu_nocbs=2-7 threadirqs cpufreq.default_governor=performance idle=poll processor.max_cstate=0 arm64.nopauth=1\n\n");
    printf("# Runtime /etc/sysctl.d/99-realtime.conf:\n");
    printf("kernel.sched_rt_runtime_us = 950000\n");
    printf("kernel.sched_rt_period_us = 1000000\n");
    printf("vm.swappiness = 0\n");
    printf("kernel.numa_balancing = 0\n");

    return EXIT_PASS;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_help();
        return EXIT_USAGE_ERROR;
    }

    if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0) {
        print_version();
        return EXIT_PASS;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_help();
        return EXIT_PASS;
    }

    if (strcmp(argv[1], "scan") == 0) {
        return handle_scan(argc, argv);
    }
    if (strcmp(argv[1], "verify-patches") == 0) {
        return handle_verify_patches(argc, argv);
    }
    if (strcmp(argv[1], "analyze-jitter") == 0) {
        return handle_analyze_jitter(argc, argv);
    }
    if (strcmp(argv[1], "gen-config") == 0) {
        return handle_gen_config(argc, argv);
    }

    fprintf(stderr, "Error: Unrecognized command '%s'.\n", argv[1]);
    print_help();
    return EXIT_USAGE_ERROR;
}
