#ifndef EXPORTERS_H
#define EXPORTERS_H

#include "preempt_types.h"

/**
 * Render ANSI box table report for audit results.
 */
void render_table_report(const AuditResult *res, char *out_buf, size_t max_len);

/**
 * Render Canonical JSON report for audit results.
 */
void render_json_report(const AuditResult *res, char *out_buf, size_t max_len);

/**
 * Render OASIS SARIF v2.1.0 report for audit results.
 */
void render_sarif_report(const AuditResult *res, char *out_buf, size_t max_len);

/**
 * Render cyclictest jitter analysis terminal table.
 */
void render_cyclictest_table(const CyclictestResult *res, char *out_buf, size_t max_len);

/**
 * Render patch series validation summary table.
 */
void render_patch_series_table(const SeriesValidationSummary *summary, char *out_buf, size_t max_len);

#endif /* EXPORTERS_H */
