#include "exporters.h"
#include "rt_auditor.h"
#include <stdio.h>
#include <string.h>

void render_table_report(const AuditResult *res, char *out_buf, size_t max_len)
{
    if (!res || !out_buf || max_len == 0) return;

    const char *status_str = (res->total_findings == 0) ? "PASSED" : "POLICY VIOLATIONS DETECTED";
    const char *status_color = (res->total_findings == 0) ? "\033[32m" : "\033[31m";
    const char *reset = "\033[0m";

    int offset = snprintf(out_buf, max_len,
        "\n"
        "┌──────────────────────────────────────────────────────────────────────────────┐\n"
        "│              LOGIHERTZ PREEMPT_RT KERNEL POSTURE AUDITOR                     │\n"
        "├──────────────────────────────────────────────────────────────────────────────┤\n"
        "│ Target Config: %-61.61s │\n"
        "│ Posture Score: %s%-3d / 100%s   Status: %s%-35.35s%s │\n"
        "│ Findings:      Total: %-3d  Crit: %-3d  High: %-3d  Med: %-3d  Low: %-3d   │\n"
        "└──────────────────────────────────────────────────────────────────────────────┘\n\n",
        res->target,
        status_color, res->posture_score, reset,
        status_color, status_str, reset,
        res->total_findings, res->critical_count, res->high_count, res->medium_count, res->low_count
    );

    if (res->total_findings == 0) {
        snprintf(out_buf + offset, max_len - (size_t)offset,
            "\033[32m[✓] All 10 PREEMPT_RT kernel real-time controls passed without violations.\033[0m\n\n"
        );
        return;
    }

    offset += snprintf(out_buf + offset, max_len - (size_t)offset,
        "DETAILED SECURITY & TIMING FINDINGS:\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
        "%-12s %-10s %-10s %-45s\n"
        "────────────────────────────────────────────────────────────────────────────────\n",
        "RULE ID", "SEVERITY", "CWE", "TITLE"
    );

    for (int i = 0; i < res->total_findings && (size_t)offset < max_len - 512; i++) {
        const AuditFinding *f = &res->findings[i];
        const char *sev_color = "\033[36m";
        if (strcmp(f->severity, "CRITICAL") == 0) sev_color = "\033[1;31m";
        else if (strcmp(f->severity, "HIGH") == 0) sev_color = "\033[31m";
        else if (strcmp(f->severity, "MEDIUM") == 0) sev_color = "\033[33m";

        offset += snprintf(out_buf + offset, max_len - (size_t)offset,
            "%-12s %s%-10s%s %-10s %-45.45s\n"
            "  Description:    %s\n"
            "  Offending Conf: %s\n"
            "  Remediation:    %s\n"
            "────────────────────────────────────────────────────────────────────────────────\n",
            f->rule_id, sev_color, f->severity, reset, f->cwe, f->title,
            f->description, f->evidence, f->recommendation
        );
    }
}

void render_json_report(const AuditResult *res, char *out_buf, size_t max_len)
{
    if (!res || !out_buf || max_len == 0) return;

    int offset = snprintf(out_buf, max_len,
        "{\n"
        "  \"target\": \"%s\",\n"
        "  \"posture_score\": %d,\n"
        "  \"summary\": {\n"
        "    \"total_findings\": %d,\n"
        "    \"critical\": %d,\n"
        "    \"high\": %d,\n"
        "    \"medium\": %d,\n"
        "    \"low\": %d\n"
        "  },\n"
        "  \"findings\": [\n",
        res->target, res->posture_score,
        res->total_findings, res->critical_count, res->high_count, res->medium_count, res->low_count
    );

    for (int i = 0; i < res->total_findings && (size_t)offset < max_len - 512; i++) {
        const AuditFinding *f = &res->findings[i];
        offset += snprintf(out_buf + offset, max_len - (size_t)offset,
            "    {\n"
            "      \"rule_id\": \"%s\",\n"
            "      \"severity\": \"%s\",\n"
            "      \"cwe\": \"%s\",\n"
            "      \"title\": \"%s\",\n"
            "      \"description\": \"%s\",\n"
            "      \"recommendation\": \"%s\",\n"
            "      \"evidence\": \"%s\"\n"
            "    }%s\n",
            f->rule_id, f->severity, f->cwe, f->title, f->description, f->recommendation, f->evidence,
            (i + 1 < res->total_findings) ? "," : ""
        );
    }

    snprintf(out_buf + offset, max_len - (size_t)offset, "  ]\n}\n");
}

void render_sarif_report(const AuditResult *res, char *out_buf, size_t max_len)
{
    if (!res || !out_buf || max_len == 0) return;

    int offset = snprintf(out_buf, max_len,
        "{\n"
        "  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",\n"
        "  \"version\": \"2.1.0\",\n"
        "  \"runs\": [\n"
        "    {\n"
        "      \"tool\": {\n"
        "        \"driver\": {\n"
        "          \"name\": \"lh-kernel-preempt-patch\",\n"
        "          \"version\": \"0.1.0\",\n"
        "          \"organization\": \"Logihertz Systems (OPC) Private Limited\",\n"
        "          \"informationUri\": \"" LH_REPO_URL "\",\n"
        "          \"rules\": [\n"
    );

    for (int i = 0; i < 10 && (size_t)offset < max_len - 512; i++) {
        const RuleDef *r = &g_rt_rules[i];
        const char *level = (strcmp(r->severity, "CRITICAL") == 0 || strcmp(r->severity, "HIGH") == 0) ? "error" :
                            (strcmp(r->severity, "MEDIUM") == 0 ? "warning" : "note");
        const char *sec_sev = (strcmp(r->severity, "CRITICAL") == 0) ? "10" :
                              (strcmp(r->severity, "HIGH") == 0 ? "7" :
                              (strcmp(r->severity, "MEDIUM") == 0 ? "4" : "1"));

        offset += snprintf(out_buf + offset, max_len - (size_t)offset,
            "            {\n"
            "              \"id\": \"%s\",\n"
            "              \"name\": \"%s\",\n"
            "              \"shortDescription\": { \"text\": \"%s\" },\n"
            "              \"fullDescription\": { \"text\": \"%s (%s, Weight: %d)\" },\n"
            "              \"defaultConfiguration\": { \"level\": \"%s\" },\n"
            "              \"helpUri\": \"" LH_REPO_URL "#core-detection-rules\",\n"
            "              \"properties\": { \"cwe\": [\"%s\"], \"precision\": \"very-high\", \"security-severity\": \"%s\" }\n"
            "            }%s\n",
            r->id, r->id, r->title, r->title, r->cwe, r->weight, level, r->cwe, sec_sev,
            (i + 1 < 10) ? "," : ""
        );
    }

    offset += snprintf(out_buf + offset, max_len - (size_t)offset,
        "          ]\n"
        "        }\n"
        "      },\n"
        "      \"results\": [\n"
    );

    for (int i = 0; i < res->total_findings && (size_t)offset < max_len - 512; i++) {
        const AuditFinding *f = &res->findings[i];
        const char *level = (strcmp(f->severity, "CRITICAL") == 0 || strcmp(f->severity, "HIGH") == 0) ? "error" :
                            (strcmp(f->severity, "MEDIUM") == 0 ? "warning" : "note");

        offset += snprintf(out_buf + offset, max_len - (size_t)offset,
            "        {\n"
            "          \"ruleId\": \"%s\",\n"
            "          \"level\": \"%s\",\n"
            "          \"message\": { \"text\": \"%s - Offending: %s. Remediation: %s\" },\n"
            "          \"locations\": [{ \"physicalLocation\": { \"artifactLocation\": { \"uri\": \"%s\" } } }]\n"
            "        }%s\n",
            f->rule_id, level, f->title, f->evidence, f->recommendation, res->target,
            (i + 1 < res->total_findings) ? "," : ""
        );
    }

    snprintf(out_buf + offset, max_len - (size_t)offset,
        "      ]\n"
        "    }\n"
        "  ]\n"
        "}\n"
    );
}

void render_cyclictest_table(const CyclictestResult *res, char *out_buf, size_t max_len)
{
    if (!res || !out_buf || max_len == 0) return;

    const char *status_str = (res->max_latency_us <= LH_DEFAULT_MAX_LATENCY_CEILING_US) ? "DETERMINISTIC" : "NON-DETERMINISTIC JITTER EXCEEDED";
    const char *status_color = (res->max_latency_us <= LH_DEFAULT_MAX_LATENCY_CEILING_US) ? "\033[32m" : "\033[31m";
    const char *reset = "\033[0m";

    snprintf(out_buf, max_len,
        "\n"
        "┌──────────────────────────────────────────────────────────────────────────────┐\n"
        "│                 REAL-TIME CYCLICTEST JITTER & LATENCY REPORT                 │\n"
        "├──────────────────────────────────────────────────────────────────────────────┤\n"
        "│ Benchmark:   %-15.15s Version: %-12.12s Status: %s%-18.18s%s │\n"
        "│ Kernel:      %-61.61s │\n"
        "│ CPU Model:   %-61.61s │\n"
        "│ Isolated:    %-15.15s Threads: %-2d            Priority: %-3d              │\n"
        "├──────────────────────────────────────────────────────────────────────────────┤\n"
        "│ Min Latency: %6.1fus       Mean Latency: %6.1fus    Max Latency: %6.1fus       │\n"
        "│ Peak Jitter: %6.1fus       Std Deviation:%6.2fus    SMI Spikes:  %-3d            │\n"
        "│ P99 Latency: %6.1fus       P99.999:      %6.1fus    Ceiling:     %6.1fus       │\n"
        "└──────────────────────────────────────────────────────────────────────────────┘\n\n",
        res->benchmark, res->version, status_color, status_str, reset,
        res->kernel, res->cpu_model, res->isolated_cpus, res->threads, res->priority,
        res->min_latency_us, res->mean_latency_us, res->max_latency_us,
        res->peak_jitter_us, res->stddev_us, res->smi_spikes,
        res->p99_latency_us, res->p99_999_latency_us, LH_DEFAULT_MAX_LATENCY_CEILING_US
    );
}

void render_patch_series_table(const SeriesValidationSummary *summary, char *out_buf, size_t max_len)
{
    if (!summary || !out_buf || max_len == 0) return;

    const char *status_str = summary->all_valid ? "ALL PATCHES VALIDATED" : "PATCH VALIDATION FAILED";
    const char *status_color = summary->all_valid ? "\033[32m" : "\033[31m";
    const char *reset = "\033[0m";

    int offset = snprintf(out_buf, max_len,
        "\n"
        "┌──────────────────────────────────────────────────────────────────────────────┐\n"
        "│           LINUX 6.6 LTS TEGRA234 PREEMPT_RT PATCH SERIES VALIDATION          │\n"
        "├──────────────────────────────────────────────────────────────────────────────┤\n"
        "│ Series File: %-61.61s │\n"
        "│ Verified:    %d / %-2d Patches Valid      Status: %s%-27.27s%s │\n"
        "├──────────────────────────────────────────────────────────────────────────────┤\n"
        "│ %-38.38s │ DCO │ HUNKS │ %-20.20s │\n"
        "├────────────────────────────────────────┼─────┼───────┼──────────────────────┤\n",
        summary->series_path,
        summary->valid_patches, summary->total_patches,
        status_color, status_str, reset,
        "PATCH FILE", "STATUS"
    );

    for (int i = 0; i < summary->total_patches && (size_t)offset < max_len - 256; i++) {
        const PatchValidationResult *p = &summary->patch_results[i];
        const char *p_color = p->valid ? "\033[32m" : "\033[31m";
        const char *p_status = p->valid ? "VALID" : "INVALID";

        offset += snprintf(out_buf + offset, max_len - (size_t)offset,
            "│ %-38.38s │ %s │ %-5d │ %s%-20.20s%s │\n",
            p->filename,
            p->valid_dco ? "YES" : "NO ",
            p->hunk_count,
            p_color, p_status, reset
        );
    }

    snprintf(out_buf + offset, max_len - (size_t)offset,
        "└────────────────────────────────────────┴─────┴───────┴──────────────────────┘\n\n"
    );
}
