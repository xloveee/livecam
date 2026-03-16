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

    int32_t matched = 0;
    for (int32_t i = 0; i < g_whitelist_count; i++) {
        volatile int32_t diff = 0;
        for (size_t j = 0; j < STREAM_KEY_EXACT_LEN; j++) {
            diff |= (key[j] ^ g_whitelist[i][j]);
        }
        matched |= (diff == 0) ? 1 : 0;
    }

    return matched;
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

#define SESSION_SECRET_LEN 32
static char g_session_secret[SESSION_SECRET_LEN + 1] = {0};
static int32_t g_session_secret_set = 0;

static const char hex_chars[16] = "0123456789abcdef";

void init_session_secret(const char *secret)
{
    g_session_secret_set = 0;
    if (secret == NULL) {
        return;
    }
    const size_t len = bounded_strlen(secret, SESSION_SECRET_LEN + 1);
    if (len < 16) {
        return;
    }
    size_t copy_len = (len > SESSION_SECRET_LEN) ? SESSION_SECRET_LEN : len;
    for (size_t i = 0; i < copy_len; i++) {
        g_session_secret[i] = secret[i];
    }
    g_session_secret[copy_len] = '\0';
    g_session_secret_set = 1;
}

/*
 * Generate a session token from a validated stream key.
 * Token = hex(XOR-fold(key, secret) with byte mixing).
 * out_hex must be at least SESSION_TOKEN_HEX_LEN + 1 bytes.
 */
void generate_session_token(const char *stream_key, char *out_hex)
{
    uint8_t digest[STREAM_KEY_EXACT_LEN];
    const size_t secret_len = bounded_strlen(g_session_secret, SESSION_SECRET_LEN + 1);

    for (size_t i = 0; i < STREAM_KEY_EXACT_LEN; i++) {
        uint8_t k = (uint8_t)stream_key[i];
        uint8_t s = (secret_len > 0) ? (uint8_t)g_session_secret[i % secret_len] : 0x5A;
        digest[i] = (uint8_t)((k ^ s) + (uint8_t)(i * 7 + 0x3B));
    }

    for (size_t i = 0; i < STREAM_KEY_EXACT_LEN; i++) {
        out_hex[i * 2]     = hex_chars[(digest[i] >> 4) & 0x0F];
        out_hex[i * 2 + 1] = hex_chars[digest[i] & 0x0F];
    }
    out_hex[SESSION_TOKEN_HEX_LEN] = '\0';
}

/*
 * Validate a session token against all whitelisted keys.
 * If a match is found, writes the matching stream key to out_key
 * (must be at least STREAM_KEY_EXACT_LEN + 1 bytes).
 * Returns 1 on match, 0 on failure. Constant-time per key.
 */
int32_t extract_stream_key_from_token(const char *token_hex, char *out_key)
{
    if (token_hex == NULL || out_key == NULL) {
        return 0;
    }

    const size_t token_len = bounded_strlen(token_hex, SESSION_TOKEN_HEX_LEN + 1);
    if (token_len != SESSION_TOKEN_HEX_LEN) {
        return 0;
    }

    char candidate[SESSION_TOKEN_HEX_LEN + 1];
    int32_t found = 0;

    for (int32_t i = 0; i < g_whitelist_count; i++) {
        generate_session_token(g_whitelist[i], candidate);

        volatile int32_t diff = 0;
        for (size_t j = 0; j < SESSION_TOKEN_HEX_LEN; j++) {
            diff |= (token_hex[j] ^ candidate[j]);
        }

        if (diff == 0 && found == 0) {
            for (size_t j = 0; j < STREAM_KEY_EXACT_LEN; j++) {
                out_key[j] = g_whitelist[i][j];
            }
            out_key[STREAM_KEY_EXACT_LEN] = '\0';
            found = 1;
        }
    }

    if (g_whitelist_count == 0) {
        return 0;
    }

    return found;
}

#define MAX_ROOM_PASSWORD_LEN 128

/*
 * Constant-time comparison of a submitted room password against
 * the stored password. Returns 1 if access is granted, 0 if denied.
 *
 * If stored is NULL or empty, no password is set — always allow.
 * If submitted is NULL or empty when a password is required — deny.
 */
int32_t check_room_password(const char *submitted, const char *stored)
{
    if (stored == NULL) {
        return 1;
    }

    const size_t stored_len = bounded_strlen(stored, MAX_ROOM_PASSWORD_LEN + 1);
    if (stored_len == 0) {
        return 1;
    }

    if (submitted == NULL) {
        return 0;
    }

    const size_t submitted_len = bounded_strlen(submitted, MAX_ROOM_PASSWORD_LEN + 1);

    /* Length mismatch — still iterate to preserve constant time */
    volatile int32_t diff = 0;
    const size_t cmp_len = (stored_len > submitted_len) ? stored_len : submitted_len;

    for (size_t i = 0; i < cmp_len && i < MAX_ROOM_PASSWORD_LEN; i++) {
        const char a = (i < submitted_len) ? submitted[i] : '\0';
        const char b = (i < stored_len)    ? stored[i]    : '\0';
        diff |= (a ^ b);
    }

    if (submitted_len != stored_len) {
        diff |= 1;
    }

    return (diff == 0) ? 1 : 0;
}
