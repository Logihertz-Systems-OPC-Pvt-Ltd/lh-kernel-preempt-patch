#include "config_parser.h"
#include "latency_math.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static const char *skip_whitespace(const char *p)
{
    while (*p && isspace((unsigned char)*p)) {
        p++;
    }
    return p;
}

static const char *find_key_colon(const char *json, const char *key)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);

    const char *pos = strstr(json, needle);
    if (!pos) {
        return NULL;
    }

    pos += strlen(needle);
    pos = skip_whitespace(pos);
    if (*pos != ':') {
        return NULL;
    }
    pos++;
    return skip_whitespace(pos);
}

static int extract_string(const char *json, const char *key, char *out, size_t max_len)
{
    const char *p = find_key_colon(json, key);
    if (!p) {
        if (max_len > 0) out[0] = '\0';
        return -1;
    }

    if (*p == '\"') {
        p++;
        size_t idx = 0;
        while (*p && *p != '\"' && idx + 1 < max_len) {
            if (*p == '\\' && *(p + 1)) {
                p++;
            }
            out[idx++] = *p++;
        }
        out[idx] = '\0';
        return 0;
    }

    /* Unquoted token */
    size_t idx = 0;
    while (*p && *p != ',' && *p != '}' && !isspace((unsigned char)*p) && idx + 1 < max_len) {
        out[idx++] = *p++;
    }
    out[idx] = '\0';
    return 0;
}

static long extract_long(const char *json, const char *key, long default_val)
{
    const char *p = find_key_colon(json, key);
    if (!p) {
        return default_val;
    }

    char *endptr = NULL;
    long val = strtol(p, &endptr, 10);
    if (endptr == p) {
        return default_val;
    }
    return val;
}

static double extract_double(const char *json, const char *key, double default_val)
{
    const char *p = find_key_colon(json, key);
    if (!p) {
        return default_val;
    }

    char *endptr = NULL;
    double val = strtod(p, &endptr);
    if (endptr == p) {
        return default_val;
    }
    return val;
}

static bool extract_bool(const char *json, const char *key, bool default_val)
{
    const char *p = find_key_colon(json, key);
    if (!p) {
        return default_val;
    }

    if (*p == '\"') {
        p++;
    }

    if (strncmp(p, "true", 4) == 0 || strncmp(p, "y", 1) == 0 || strncmp(p, "1", 1) == 0) {
        return true;
    }
    if (strncmp(p, "false", 5) == 0 || strncmp(p, "n", 1) == 0 || strncmp(p, "0", 1) == 0) {
        return false;
    }
    return default_val;
}

static int extract_double_array(const char *json, const char *key, double *out_arr, int max_count)
{
    const char *p = find_key_colon(json, key);
    if (!p) {
        return 0;
    }

    const char *bracket = strchr(p, '[');
    if (!bracket) {
        return 0;
    }
    bracket++;

    int count = 0;
    while (*bracket && *bracket != ']' && count < max_count) {
        bracket = skip_whitespace(bracket);
        if (*bracket == ']') break;

        char *endptr = NULL;
        double val = strtod(bracket, &endptr);
        if (endptr == bracket) {
            bracket++;
            continue;
        }

        out_arr[count++] = val;
        bracket = endptr;
        bracket = skip_whitespace(bracket);
        if (*bracket == ',') {
            bracket++;
        }
    }
    return count;
}

int parse_kernel_config_json(const char *json_text, KernelConfig *out)
{
    if (!json_text || !out) {
        return -1;
    }

    memset(out, 0, sizeof(*out));

    extract_string(json_text, "profile_name", out->profile_name, sizeof(out->profile_name));
    extract_string(json_text, "soc", out->soc, sizeof(out->soc));
    extract_string(json_text, "kernel_version", out->kernel_version, sizeof(out->kernel_version));
    extract_string(json_text, "CONFIG_PREEMPT_RT", out->config_preempt_rt, sizeof(out->config_preempt_rt));
    extract_string(json_text, "preempt_mode", out->preempt_mode, sizeof(out->preempt_mode));

    out->sched_rt_runtime_us = extract_long(json_text, "sched_rt_runtime_us", -1);
    out->sched_rt_period_us = extract_long(json_text, "sched_rt_period_us", 1000000);
    out->max_latency_us = extract_double(json_text, "max_latency_us", 999.0);

    extract_string(json_text, "isolcpus", out->isolcpus, sizeof(out->isolcpus));
    extract_string(json_text, "nohz_full", out->nohz_full, sizeof(out->nohz_full));
    extract_string(json_text, "rcu_nocbs", out->rcu_nocbs, sizeof(out->rcu_nocbs));
    extract_string(json_text, "CONFIG_IRQ_FORCED_THREADING", out->config_irq_forced_threading, sizeof(out->config_irq_forced_threading));

    out->threadirqs = extract_bool(json_text, "threadirqs", false);
    extract_string(json_text, "cpufreq_governor", out->cpufreq_governor, sizeof(out->cpufreq_governor));

    out->max_cstate = (int)extract_long(json_text, "max_cstate", 1);
    out->vm_swappiness = (int)extract_long(json_text, "vm_swappiness", 60);
    out->numa_balancing_enabled = extract_bool(json_text, "numa_balancing_enabled", true);
    out->config_hz = (int)extract_long(json_text, "CONFIG_HZ", 250);
    out->high_res_timers_enabled = extract_bool(json_text, "high_res_timers_enabled", false);
    out->efi_runtime_enabled = extract_bool(json_text, "efi_runtime_enabled", true);
    out->ras_daemon_irq_on_rt_cores = extract_bool(json_text, "ras_daemon_irq_on_rt_cores", true);
    out->hardware_watchdog_enabled = extract_bool(json_text, "hardware_watchdog_enabled", false);
    out->rt_mutex_debug_verified = extract_bool(json_text, "rt_mutex_debug_verified", false);

    return 0;
}

int load_kernel_config_file(const char *filepath, KernelConfig *out)
{
    if (!filepath || !out) {
        return -1;
    }

    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (sz <= 0 || sz > 1048576) {
        fclose(fp);
        return -2;
    }

    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(fp);
        return -2;
    }

    size_t read_bytes = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[read_bytes] = '\0';

    int rc = parse_kernel_config_json(buf, out);
    free(buf);
    return rc;
}

int parse_cyclictest_json(const char *json_text, CyclictestResult *out)
{
    if (!json_text || !out) {
        return -1;
    }

    memset(out, 0, sizeof(*out));

    extract_string(json_text, "benchmark", out->benchmark, sizeof(out->benchmark));
    extract_string(json_text, "version", out->version, sizeof(out->version));
    extract_string(json_text, "kernel", out->kernel, sizeof(out->kernel));
    extract_string(json_text, "cpu_model", out->cpu_model, sizeof(out->cpu_model));
    extract_string(json_text, "isolated_cpus", out->isolated_cpus, sizeof(out->isolated_cpus));

    out->threads = (int)extract_long(json_text, "threads", 1);
    out->priority = (int)extract_long(json_text, "priority", 98);
    out->interval_us = (int)extract_long(json_text, "interval_us", 1000);
    out->loops = extract_long(json_text, "loops", 100000);

    out->min_latency_us = extract_double(json_text, "min_latency_us", 0.0);
    out->mean_latency_us = extract_double(json_text, "mean_latency_us", 0.0);
    out->max_latency_us = extract_double(json_text, "max_latency_us", 0.0);
    out->stddev_us = extract_double(json_text, "stddev_us", 0.0);
    out->p99_latency_us = extract_double(json_text, "p99_latency_us", 0.0);
    out->p99_999_latency_us = extract_double(json_text, "p99_999_latency_us", 0.0);

    out->sample_count = extract_double_array(json_text, "samples", out->samples, 128);

    if (out->sample_count > 0 && out->max_latency_us <= 0.0) {
        double min_v, max_v, mean_v, stddev_v, jitter_v;
        int spikes;
        compute_cyclictest_stats(
            out->samples, out->sample_count,
            &min_v, &max_v, &mean_v, &stddev_v, &jitter_v, &spikes
        );
        out->min_latency_us = min_v;
        out->max_latency_us = max_v;
        out->mean_latency_us = mean_v;
        out->stddev_us = stddev_v;
        out->peak_jitter_us = jitter_v;
        out->smi_spikes = spikes;
    } else {
        out->peak_jitter_us = calc_peak_jitter(out->min_latency_us, out->max_latency_us);
        out->smi_spikes = detect_smi_spike(out->max_latency_us, LH_DEFAULT_MAX_LATENCY_CEILING_US) ? 1 : 0;
    }

    return 0;
}

int load_cyclictest_file(const char *filepath, CyclictestResult *out)
{
    if (!filepath || !out) {
        return -1;
    }

    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (sz <= 0 || sz > 1048576) {
        fclose(fp);
        return -2;
    }

    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(fp);
        return -2;
    }

    size_t read_bytes = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[read_bytes] = '\0';

    int rc = parse_cyclictest_json(buf, out);
    free(buf);
    return rc;
}
