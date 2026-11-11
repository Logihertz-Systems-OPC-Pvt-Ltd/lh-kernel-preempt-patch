#ifndef PREEMPT_TYPES_H
#define PREEMPT_TYPES_H

#include <stdbool.h>
#include <stddef.h>

#define LH_PREEMPT_VERSION "0.1.0"
#define LH_ORGANIZATION "Logihertz Systems (OPC) Private Limited"
#define LH_ORG_URL "https://logihertz.com/"
#define LH_REPO_URL "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-kernel-preempt-patch"
#define LH_DEFAULT_MAX_LATENCY_CEILING_US 50.0

#define EXIT_PASS 0
#define EXIT_POLICY_VIOLATION 1
#define EXIT_USAGE_ERROR 2

typedef struct {
    const char *id;
    const char *title;
    const char *description;
    const char *cwe;
    int weight;
    const char *severity;
    const char *recommendation;
} RuleDef;

typedef struct {
    char profile_name[128];
    char soc[64];
    char kernel_version[128];
    char config_preempt_rt[32];
    char preempt_mode[32];
    long sched_rt_runtime_us;
    long sched_rt_period_us;
    double max_latency_us;
    char isolcpus[128];
    char nohz_full[128];
    char rcu_nocbs[128];
    char config_irq_forced_threading[32];
    bool threadirqs;
    char cpufreq_governor[64];
    int max_cstate;
    int vm_swappiness;
    bool numa_balancing_enabled;
    int config_hz;
    bool high_res_timers_enabled;
    bool efi_runtime_enabled;
    bool ras_daemon_irq_on_rt_cores;
    bool hardware_watchdog_enabled;
    bool rt_mutex_debug_verified;
} KernelConfig;

typedef struct {
    char rule_id[32];
    char severity[16];
    char cwe[16];
    char title[128];
    char description[256];
    char recommendation[256];
    char evidence[128];
} AuditFinding;

typedef struct {
    char target[256];
    int posture_score;
    int total_findings;
    int critical_count;
    int high_count;
    int medium_count;
    int low_count;
    AuditFinding findings[16];
} AuditResult;

typedef struct {
    char benchmark[64];
    char version[32];
    char kernel[128];
    char cpu_model[128];
    char isolated_cpus[64];
    int threads;
    int priority;
    int interval_us;
    long loops;
    double min_latency_us;
    double mean_latency_us;
    double max_latency_us;
    double stddev_us;
    double p99_latency_us;
    double p99_999_latency_us;
    double peak_jitter_us;
    int sample_count;
    double samples[128];
    int smi_spikes;
} CyclictestResult;

typedef struct {
    char filename[128];
    bool valid_dco;
    bool valid_diff_headers;
    int hunk_count;
    char from_author[128];
    char subject[256];
    char signed_off_by[128];
    unsigned long checksum;
    char error_msg[256];
    bool valid;
} PatchValidationResult;

typedef struct {
    char series_path[256];
    int total_patches;
    int valid_patches;
    PatchValidationResult patch_results[16];
    bool all_valid;
} SeriesValidationSummary;

#endif /* PREEMPT_TYPES_H */
