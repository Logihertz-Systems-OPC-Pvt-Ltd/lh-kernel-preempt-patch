#ifndef PATCH_ENGINE_H
#define PATCH_ENGINE_H

#include "preempt_types.h"

/**
 * Verify a single patch file for DCO Signed-off-by, unified diff headers, and hunks.
 * Returns 0 on success, negative value on failure.
 */
int verify_patch_file(const char *filepath, PatchValidationResult *out);

/**
 * Verify an entire patch series defined by a series manifest file.
 * Returns 0 on success, negative value on failure.
 */
int verify_patch_series(const char *patches_dir, SeriesValidationSummary *out);

#endif /* PATCH_ENGINE_H */
