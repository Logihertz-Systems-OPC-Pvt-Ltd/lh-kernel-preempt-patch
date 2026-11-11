#include "patch_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static void trim_trailing_newline(char *s)
{
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\r' || s[len - 1] == '\n' || isspace((unsigned char)s[len - 1]))) {
        s[--len] = '\0';
    }
}

static const char *get_basename(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

int verify_patch_file(const char *filepath, PatchValidationResult *out)
{
    if (!filepath || !out) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    snprintf(out->filename, sizeof(out->filename), "%s", get_basename(filepath));

    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        snprintf(out->error_msg, sizeof(out->error_msg), "Cannot open patch file: %s", filepath);
        out->valid = false;
        return -1;
    }

    char line[1024];
    bool has_minus_header = false;
    bool has_plus_header = false;
    unsigned long hash = 2166136261UL;

    while (fgets(line, sizeof(line), fp)) {
        /* Update FNV-1a checksum */
        for (const char *p = line; *p; p++) {
            hash = (hash ^ (unsigned char)*p) * 16777619UL;
        }

        if (strncmp(line, "From: ", 6) == 0 && out->from_author[0] == '\0') {
            snprintf(out->from_author, sizeof(out->from_author), "%.127s", line + 6);
            trim_trailing_newline(out->from_author);
        } else if (strncmp(line, "Subject: ", 9) == 0 && out->subject[0] == '\0') {
            snprintf(out->subject, sizeof(out->subject), "%.255s", line + 9);
            trim_trailing_newline(out->subject);
        } else if (strncmp(line, "Signed-off-by: ", 15) == 0) {
            snprintf(out->signed_off_by, sizeof(out->signed_off_by), "%.127s", line + 15);
            trim_trailing_newline(out->signed_off_by);
            out->valid_dco = true;
        } else if (strncmp(line, "--- ", 4) == 0) {
            has_minus_header = true;
        } else if (strncmp(line, "+++ ", 4) == 0) {
            has_plus_header = true;
        } else if (strncmp(line, "@@ ", 3) == 0 && strstr(line + 3, " @@")) {
            out->hunk_count++;
        }
    }

    fclose(fp);

    out->checksum = hash;
    out->valid_diff_headers = has_minus_header && has_plus_header;

    if (!out->valid_dco) {
        snprintf(out->error_msg, sizeof(out->error_msg), "Missing Developer Certificate of Origin (Signed-off-by:)");
        out->valid = false;
        return 1;
    }

    if (!out->valid_diff_headers) {
        snprintf(out->error_msg, sizeof(out->error_msg), "Missing unified diff headers (--- a/ and +++ b/)");
        out->valid = false;
        return 1;
    }

    if (out->hunk_count == 0) {
        snprintf(out->error_msg, sizeof(out->error_msg), "No unified diff hunks (@@ -l,s +l,s @@) detected");
        out->valid = false;
        return 1;
    }

    out->valid = true;
    snprintf(out->error_msg, sizeof(out->error_msg), "Valid");
    return 0;
}

int verify_patch_series(const char *patches_dir, SeriesValidationSummary *out)
{
    if (!patches_dir || !out) {
        return -1;
    }

    memset(out, 0, sizeof(*out));

    char series_file[512];
    snprintf(series_file, sizeof(series_file), "%s/series", patches_dir);
    snprintf(out->series_path, sizeof(out->series_path), "%.255s", series_file);

    FILE *fp = fopen(series_file, "r");
    if (!fp) {
        out->all_valid = false;
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        trim_trailing_newline(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        if (out->total_patches >= 16) {
            break;
        }

        char patch_path[512];
        snprintf(patch_path, sizeof(patch_path), "%s/%s", patches_dir, line);

        PatchValidationResult *p_res = &out->patch_results[out->total_patches];
        int rc = verify_patch_file(patch_path, p_res);
        if (rc == 0 && p_res->valid) {
            out->valid_patches++;
        }
        out->total_patches++;
    }

    fclose(fp);

    out->all_valid = (out->total_patches > 0) && (out->valid_patches == out->total_patches);
    return out->all_valid ? 0 : 1;
}
