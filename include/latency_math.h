#ifndef LATENCY_MATH_H
#define LATENCY_MATH_H

#include <stdbool.h>

/**
 * Calculate peak jitter (Delta J) between minimum and maximum observed latency.
 * Delta J = L_max - L_min
 */
double calc_peak_jitter(double min_lat, double max_lat);

/**
 * Calculate real-time CPU bandwidth utilization ratio.
 * U_RT = sched_rt_runtime_us / sched_rt_period_us
 */
double calc_rt_bandwidth_ratio(long runtime_us, long period_us);

/**
 * Calculate Worst-Case Execution Time (WCET) safety margin.
 * M_WCET = D_deadline_us - (L_max_irq_us + C_ctx_switch_us)
 */
double calc_wcet_margin(double deadline_us, double max_irq_us, double ctx_switch_us);

/**
 * Detect hardware System Management Interrupt (SMI) or Arm EL3 TrustZone latency spikes.
 */
bool detect_smi_spike(double max_latency_us, double threshold_us);

/**
 * Compute statistical metrics across cyclictest sample arrays.
 */
void compute_cyclictest_stats(
    const double *samples,
    int count,
    double *out_min,
    double *out_max,
    double *out_mean,
    double *out_stddev,
    double *out_jitter,
    int *out_spikes
);

#endif /* LATENCY_MATH_H */
