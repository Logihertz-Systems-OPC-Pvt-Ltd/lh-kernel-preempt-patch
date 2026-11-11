#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include "preempt_types.h"

/**
 * Parse a JSON string containing an RT kernel policy into a KernelConfig struct.
 * Returns 0 on success, negative value on failure.
 */
int parse_kernel_config_json(const char *json_text, KernelConfig *out);

/**
 * Load and parse a kernel configuration JSON file.
 * Returns 0 on success, negative value on failure.
 */
int load_kernel_config_file(const char *filepath, KernelConfig *out);

/**
 * Parse a cyclictest JSON telemetry document into a CyclictestResult struct.
 * Returns 0 on success, negative value on failure.
 */
int parse_cyclictest_json(const char *json_text, CyclictestResult *out);

/**
 * Load and parse a cyclictest JSON file.
 * Returns 0 on success, negative value on failure.
 */
int load_cyclictest_file(const char *filepath, CyclictestResult *out);

#endif /* CONFIG_PARSER_H */
