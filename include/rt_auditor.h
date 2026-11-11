#ifndef RT_AUDITOR_H
#define RT_AUDITOR_H

#include "preempt_types.h"

extern const RuleDef g_rt_rules[10];

/**
 * Audit a KernelConfig instance against the 10 real-time security rules.
 * Computes S_posture and generates finding records.
 * Returns 0 on success.
 */
int audit_kernel_config(const KernelConfig *cfg, const char *target_name, AuditResult *out);

#endif /* RT_AUDITOR_H */
