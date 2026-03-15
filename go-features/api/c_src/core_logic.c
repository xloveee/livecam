#include "core_logic.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static char  g_whitelist[MAX_ALLOWED_KEYS][STREAM_KEY_EXACT_LEN + 1];
static int32_t g_whitelist_count = 0;

static size_t bounded_strlen(const char *s, size_t max_len)
{
    size_t i = 0;
    for (; i < max_len; i++) {
        if (s[i] == '\0') {
            return i;
        }
    }
    return max_len;
}

static int32_t is_alnum(char c)
{
    if (c >= 'a' && c <= 'z') { return 1; }
    if (c >= 'A' && c <= 'Z') { return 1; }
    if (c >= '0' && c <= '9') { return 1; }
    return 0;
}

static int32_t is_format_valid(const char *key)
{
    if (key == NULL) {
        return 0;
    }

    const size_t len = bounded_strlen(key, MAX_STREAM_KEY_LEN + 1);

    if (len != STREAM_KEY_EXACT_LEN) {
        return 0;
    }

    for (size_t i = 0; i < STREAM_KEY_EXACT_LEN; i++) {
        if (is_alnum(key[i]) == 0) {
            return 0;
        }
    }

    return 1;
}

/*
 * Parse a comma-separated list of allowed stream keys into the
 * static whitelist. Call once at startup. Passing NULL or "" leaves
 * the whitelist empty, which disables enforcement (open mode).
 */
void init_stream_key_whitelist(const char *csv)
{
    g_whitelist_count = 0;

    if (csv == NULL) {
        return;
    }

    const size_t csv_len = bounded_strlen(csv, MAX_ALLOWED_KEYS * (STREAM_KEY_EXACT_LEN + 1));
    if (csv_len == 0) {
        return;
    }

    size_t start = 0;
    for (size_t i = 0; i <= csv_len && g_whitelist_count < MAX_ALLOWED_KEYS; i++) {
        if (i == csv_len || csv[i] == ',') {
            const size_t token_len = i - start;
            if (token_len == STREAM_KEY_EXACT_LEN) {
                memcpy(g_whitelist[g_whitelist_count], &csv[start], STREAM_KEY_EXACT_LEN);
                g_whitelist[g_whitelist_count][STREAM_KEY_EXACT_LEN] = '\0';

                if (is_format_valid(g_whitelist[g_whitelist_count])) {
                    g_whitelist_count++;
                }
            }
            start = i + 1;
        }
    }
}

/*
 * Validate a stream key. When the whitelist is loaded (count > 0),
 * the key must match an entry exactly. When the whitelist is empty,
 * any format-valid key is accepted (local dev / open mode).
 * Returns 1 if valid, 0 if rejected.
 */
int32_t validate_stream_key(const char *key)
{
    if (is_format_valid(key) == 0) {
        return 0;
    }

    if (g_whitelist_count == 0) {
        return 1;
    }

    for (int32_t i = 0; i < g_whitelist_count; i++) {
        if (memcmp(key, g_whitelist[i], STREAM_KEY_EXACT_LEN) == 0) {
            return 1;
        }
    }

    return 0;
}

/*
 * Check whether a viewer IP is allowed to connect.
 * Returns 1 if allowed, 0 if rate-limited or invalid.
 *
 * Current implementation: validates IP format length only.
 * Production: replace with a token-bucket over a static array of
 * per-IP counters (no heap allocation, fixed table size).
 */
int32_t check_viewer_rate_limit(const char *ip_address)
{
    if (ip_address == NULL) {
        return 0;
    }

    const size_t len = bounded_strlen(ip_address, MAX_IP_ADDR_LEN + 1);

    if (len == 0 || len > MAX_IP_ADDR_LEN) {
        return 0;
    }

    return 1;
}

/*
 * Check whether the room can accept another viewer.
 * Returns 1 if allowed, 0 if at capacity.
 *
 * max_viewers == VIEWER_CAP_UNLIMITED (0) means no limit.
 * Negative values for either argument are rejected.
 */
int32_t check_viewer_cap(int32_t current_viewers, int32_t max_viewers)
{
    if (current_viewers < 0) {
        return 0;
    }

    if (max_viewers < 0) {
        return 0;
    }

    if (max_viewers == VIEWER_CAP_UNLIMITED) {
        return 1;
    }

    if (current_viewers >= max_viewers) {
        return 0;
    }

    return 1;
}
