#include "latency_math.h"
#include "preempt_types.h"
#include <math.h>

double calc_peak_jitter(double min_lat, double max_lat)
{
    if (max_lat < min_lat) {
        return 0.0;
    }
    return max_lat - min_lat;
}

double calc_rt_bandwidth_ratio(long runtime_us, long period_us)
{
    if (runtime_us < 0) {
        /* -1 indicates unlimited/unthrottled RT runtime (100% bandwidth or runaway risk) */
        return 1.0;
    }
    if (period_us <= 0) {
        return 0.0;
    }
    return (double)runtime_us / (double)period_us;
}

double calc_wcet_margin(double deadline_us, double max_irq_us, double ctx_switch_us)
{
    double total_overhead = max_irq_us + ctx_switch_us;
    return deadline_us - total_overhead;
}

bool detect_smi_spike(double max_latency_us, double threshold_us)
{
    return max_latency_us > threshold_us;
}

void compute_cyclictest_stats(
    const double *samples,
    int count,
    double *out_min,
    double *out_max,
    double *out_mean,
    double *out_stddev,
    double *out_jitter,
    int *out_spikes
) {
    if (count <= 0 || samples == NULL) {
        if (out_min) *out_min = 0.0;
        if (out_max) *out_max = 0.0;
        if (out_mean) *out_mean = 0.0;
        if (out_stddev) *out_stddev = 0.0;
        if (out_jitter) *out_jitter = 0.0;
        if (out_spikes) *out_spikes = 0;
        return;
    }

    double min_v = samples[0];
    double max_v = samples[0];
    double sum = 0.0;
    int spikes = 0;

    for (int i = 0; i < count; i++) {
        double v = samples[i];
        if (v < min_v) min_v = v;
        if (v > max_v) max_v = v;
        sum += v;
        if (v > LH_DEFAULT_MAX_LATENCY_CEILING_US) {
            spikes++;
        }
    }

    double mean = sum / (double)count;
    double var_sum = 0.0;
    for (int i = 0; i < count; i++) {
        double diff = samples[i] - mean;
        var_sum += diff * diff;
    }
    double stddev = sqrt(var_sum / (double)count);

    if (out_min) *out_min = min_v;
    if (out_max) *out_max = max_v;
    if (out_mean) *out_mean = mean;
    if (out_stddev) *out_stddev = stddev;
    if (out_jitter) *out_jitter = max_v - min_v;
    if (out_spikes) *out_spikes = spikes;
}
