#include "core_logic.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/random.h>
#include <pthread.h>

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
int32_t init_stream_key_whitelist(const char *csv)
{
    g_whitelist_count = 0;

    if (csv == NULL) {
        return 0;
    }

    const size_t csv_len = bounded_strlen(csv, MAX_ALLOWED_KEYS * (STREAM_KEY_EXACT_LEN + 1));
    if (csv_len == 0) {
        return 0;
    }

    size_t start = 0;
    for (size_t i = 0; i <= csv_len && g_whitelist_count < MAX_ALLOWED_KEYS; i++) {
        if (i == csv_len || csv[i] == ',') {
            size_t tok_start = start;
            size_t tok_end = i;
            while (tok_start < tok_end &&
                   (csv[tok_start] == ' ' || csv[tok_start] == '\t' ||
                    csv[tok_start] == '\n' || csv[tok_start] == '\r')) {
                tok_start++;
            }
            while (tok_end > tok_start &&
                   (csv[tok_end - 1] == ' ' || csv[tok_end - 1] == '\t' ||
                    csv[tok_end - 1] == '\n' || csv[tok_end - 1] == '\r')) {
                tok_end--;
            }
            const size_t token_len = tok_end - tok_start;
            if (token_len == STREAM_KEY_EXACT_LEN) {
                memcpy(g_whitelist[g_whitelist_count], &csv[tok_start], STREAM_KEY_EXACT_LEN);
                g_whitelist[g_whitelist_count][STREAM_KEY_EXACT_LEN] = '\0';

                if (is_format_valid(g_whitelist[g_whitelist_count])) {
                    g_whitelist_count++;
                }
            }
            start = i + 1;
        }
    }
    return g_whitelist_count;
}

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

/* ── Token-bucket rate limiter ────────────────────────────── */

#define RATE_TABLE_SIZE     4096
#define RATE_MAX_TOKENS     3
#define RATE_REFILL_SEC     2
#define RATE_ENTRY_TTL_SEC  60

typedef struct {
    uint32_t ip_hash;
    char     ip[MAX_IP_ADDR_LEN + 1];
    int32_t  tokens;
    int64_t  last_refill_sec;
    int32_t  occupied;
} rate_entry_t;

static rate_entry_t g_rate_table[RATE_TABLE_SIZE];
static pthread_mutex_t g_rate_mu = PTHREAD_MUTEX_INITIALIZER;

static uint32_t fnv1a_hash(const char *data, size_t len)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)data[i];
        h *= 16777619u;
    }
    return h;
}

/*
 * Check whether a viewer IP is allowed to connect.
 * Returns 1 if allowed, 0 if rate-limited or invalid.
 *
 * Token-bucket: each IP gets RATE_MAX_TOKENS tokens, refilling
 * 1 token per RATE_REFILL_SEC. Entries expire after RATE_ENTRY_TTL_SEC.
 * 4096-slot static table (~80 KB), hash collisions evict stale entries.
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

    const uint32_t h = fnv1a_hash(ip_address, len);
    const uint32_t idx = h % RATE_TABLE_SIZE;
    const int64_t now = (int64_t)time(NULL);

    /* M10: serialize bucket updates — table was racy across viewers. */
    pthread_mutex_lock(&g_rate_mu);
    rate_entry_t *const entry = &g_rate_table[idx];

    if (entry->occupied != 0 && entry->ip_hash == h &&
        strncmp(entry->ip, ip_address, MAX_IP_ADDR_LEN) != 0) {
        /* M34: hash collision with a live different IP — do not refill; deny. */
        pthread_mutex_unlock(&g_rate_mu);
        return 0;
    }
    if (entry->occupied == 0 ||
        strncmp(entry->ip, ip_address, MAX_IP_ADDR_LEN) != 0 ||
        (now - entry->last_refill_sec) > RATE_ENTRY_TTL_SEC) {
        entry->ip_hash = h;
        memset(entry->ip, 0, sizeof(entry->ip));
        memcpy(entry->ip, ip_address, len);
        entry->ip[len] = 0;
        entry->tokens = RATE_MAX_TOKENS - 1;
        entry->last_refill_sec = now;
        entry->occupied = 1;
        pthread_mutex_unlock(&g_rate_mu);
        return 1;
    }

    const int64_t elapsed = now - entry->last_refill_sec;
    if (elapsed > 0) {
        const int32_t refill = (int32_t)(elapsed / RATE_REFILL_SEC);
        if (refill > 0) {
            entry->tokens += refill;
            if (entry->tokens > RATE_MAX_TOKENS) {
                entry->tokens = RATE_MAX_TOKENS;
            }
            entry->last_refill_sec = now;
        }
    }

    if (entry->tokens > 0) {
        entry->tokens--;
        pthread_mutex_unlock(&g_rate_mu);
        return 1;
    }

    pthread_mutex_unlock(&g_rate_mu);

    return 0;
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

#define BROADCAST_PASSWORD_MAX_LEN 128
static char g_broadcast_password[BROADCAST_PASSWORD_MAX_LEN + 1] = {0};
static size_t g_broadcast_password_len = 0;

int32_t init_broadcast_password(const char *password)
{
    g_broadcast_password_len = 0;
    g_broadcast_password[0] = '\0';
    if (password == NULL || password[0] == '\0') {
        return 1;
    }
    const size_t len = bounded_strlen(password, BROADCAST_PASSWORD_MAX_LEN + 1);
    if (len == 0) {
        return 1;
    }
    if (len > BROADCAST_PASSWORD_MAX_LEN) {
        /* H24: do not silently clear and open the gate. */
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        g_broadcast_password[i] = password[i];
    }
    g_broadcast_password[len] = '\0';
    g_broadcast_password_len = len;
    return 1;
}

int32_t stream_key_whitelist_count(void)
{
    return g_whitelist_count;
}

int32_t broadcast_password_is_set(void)
{
    return (g_broadcast_password_len > 0) ? 1 : 0;
}

int32_t check_broadcast_password(const char *submitted)
{
    if (g_broadcast_password_len == 0) {
        return 1;
    }

    if (submitted == NULL) {
        return 0;
    }

    const size_t submitted_len = bounded_strlen(submitted, BROADCAST_PASSWORD_MAX_LEN + 1);
    const size_t cmp_len = (g_broadcast_password_len > submitted_len)
                           ? g_broadcast_password_len : submitted_len;

    volatile int32_t diff = 0;
    for (size_t i = 0; i < cmp_len && i < BROADCAST_PASSWORD_MAX_LEN; i++) {
        const char a = (i < submitted_len) ? submitted[i] : '\0';
        const char b = (i < g_broadcast_password_len) ? g_broadcast_password[i] : '\0';
        diff |= (a ^ b);
    }

    if (submitted_len != g_broadcast_password_len) {
        diff |= 1;
    }

    return (diff == 0) ? 1 : 0;
}

#define SESSION_SECRET_LEN 32
#define SESSION_TOKEN_NONCE_LEN 16
#define SESSION_TOKEN_EXP_LEN 8
#define SESSION_TOKEN_MAC_LEN 32
#define SESSION_TOKEN_RAW_LEN (SESSION_TOKEN_NONCE_LEN + SESSION_TOKEN_EXP_LEN + STREAM_KEY_EXACT_LEN + SESSION_TOKEN_MAC_LEN)
#define SESSION_TOKEN_TTL_SECS 86400

static char g_session_secret[SESSION_SECRET_LEN + 1] = {0};
static size_t g_session_secret_len = 0;
static int32_t g_session_secret_set = 0;

static const char hex_chars[16] = "0123456789abcdef";

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

static void bytes_to_hex(const uint8_t *in, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++) {
        out[i * 2]     = hex_chars[(in[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex_chars[in[i] & 0x0F];
    }
    out[n * 2] = '\0';
}

static int32_t hex_to_bytes(const char *hex, size_t hex_len, uint8_t *out)
{
    if ((hex_len % 2) != 0) {
        return 0;
    }
    const size_t n = hex_len / 2;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

static void store_be64(uint8_t out[8], uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        out[i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
}

static uint64_t load_be64(const uint8_t in[8])
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | (uint64_t)in[i];
    }
    return v;
}

static int32_t fill_random(uint8_t *buf, size_t n)
{
    if (buf == NULL || n == 0) {
        return 0;
    }
    if (getentropy(buf, n) == 0) {
        return 1;
    }
    FILE *f = fopen("/dev/urandom", "rb");
    if (f == NULL) {
        return 0;
    }
    size_t got = fread(buf, 1, n, f);
    fclose(f);
    return (got == n) ? 1 : 0;
}

/* Compact SHA-256 (FIPS 180-4). */
static uint32_t rotr32(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

static void sha256_compress(uint32_t state[8], const uint8_t block[64])
{
    static const uint32_t K[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    };
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    uint32_t state[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    uint8_t block[64];
    size_t offset = 0;
    uint64_t bit_len = (uint64_t)len * 8u;

    while (len - offset >= 64) {
        sha256_compress(state, data + offset);
        offset += 64;
    }

    size_t rem = len - offset;
    memset(block, 0, 64);
    if (rem > 0) {
        memcpy(block, data + offset, rem);
    }
    block[rem] = 0x80;
    if (rem >= 56) {
        sha256_compress(state, block);
        memset(block, 0, 64);
    }
    for (int i = 0; i < 8; i++) {
        block[63 - i] = (uint8_t)(bit_len >> (8 * i));
    }
    sha256_compress(state, block);

    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (uint8_t)(state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)state[i];
    }
}

static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t out[32])
{
    uint8_t kpad[64];
    uint8_t khash[32];
    const uint8_t *k = key;
    size_t klen = key_len;

    if (klen > 64) {
        sha256(key, key_len, khash);
        k = khash;
        klen = 32;
    }
    memset(kpad, 0, 64);
    if (klen > 0) {
        memcpy(kpad, k, klen);
    }

    uint8_t ipad[64];
    uint8_t opad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i] = (uint8_t)(kpad[i] ^ 0x36);
        opad[i] = (uint8_t)(kpad[i] ^ 0x5c);
    }

    /* msg is nonce+exp+key (56 bytes). Keep a bounded stack buffer. */
    uint8_t inner_fixed[64 + 56];
    memcpy(inner_fixed, ipad, 64);
    if (msg_len > 56) {
        memset(out, 0, 32);
        return;
    }
    memcpy(inner_fixed + 64, msg, msg_len);
    uint8_t inner_hash[32];
    sha256(inner_fixed, 64 + msg_len, inner_hash);

    uint8_t outer[64 + 32];
    memcpy(outer, opad, 64);
    memcpy(outer + 64, inner_hash, 32);
    sha256(outer, 96, out);
}

static int32_t ct_memeq(const uint8_t *a, const uint8_t *b, size_t n)
{
    volatile int32_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (int32_t)(a[i] ^ b[i]);
    }
    return diff == 0 ? 1 : 0;
}

int32_t init_session_secret(const char *secret)
{
    memset(g_session_secret, 0, sizeof(g_session_secret));
    g_session_secret_len = 0;
    g_session_secret_set = 0;
    if (secret == NULL) {
        return 0;
    }
    const size_t len = bounded_strlen(secret, SESSION_SECRET_LEN + 1);
    if (len < 16) {
        return 0;
    }
    size_t copy_len = (len > SESSION_SECRET_LEN) ? SESSION_SECRET_LEN : len;
    memcpy(g_session_secret, secret, copy_len);
    g_session_secret[copy_len] = '\0';
    g_session_secret_len = copy_len;
    g_session_secret_set = 1;
    return 1;
}

/*
 * Token = hex(nonce || expiry_be64 || stream_key || HMAC-SHA256(secret, nonce||expiry||key)).
 * Never reversible to SESSION_SECRET. Open mode still requires the secret to mint.
 * out_hex must be at least SESSION_TOKEN_HEX_LEN + 1 bytes.
 */

/* Public watch/HLS/chat id. 32 hex chars of SHA-256(stream_key). Not reversible to the key. */
void public_slug_from_key(const char *stream_key, char *out_hex)
{
    if (out_hex == NULL) {
        return;
    }
    out_hex[0] = '\0';
    if (is_format_valid(stream_key) == 0) {
        return;
    }
    uint8_t digest[32];
    sha256((const uint8_t *)stream_key, STREAM_KEY_EXACT_LEN, digest);
    bytes_to_hex(digest, 16, out_hex);
}

void generate_session_token(const char *stream_key, char *out_hex)
{
    if (out_hex == NULL) {
        return;
    }
    out_hex[0] = '\0';

    if (g_session_secret_set == 0 || g_session_secret_len < 16) {
        return;
    }
    /* L5: assert format inside C — never assume a 32-byte key. */
    if (is_format_valid(stream_key) == 0) {
        return;
    }

    uint8_t nonce[SESSION_TOKEN_NONCE_LEN];
    if (fill_random(nonce, SESSION_TOKEN_NONCE_LEN) == 0) {
        return;
    }

    uint8_t expb[SESSION_TOKEN_EXP_LEN];
    uint64_t exp = (uint64_t)time(NULL) + (uint64_t)SESSION_TOKEN_TTL_SECS;
    store_be64(expb, exp);

    uint8_t msg[SESSION_TOKEN_NONCE_LEN + SESSION_TOKEN_EXP_LEN + STREAM_KEY_EXACT_LEN];
    memcpy(msg, nonce, SESSION_TOKEN_NONCE_LEN);
    memcpy(msg + SESSION_TOKEN_NONCE_LEN, expb, SESSION_TOKEN_EXP_LEN);
    memcpy(msg + SESSION_TOKEN_NONCE_LEN + SESSION_TOKEN_EXP_LEN, stream_key, STREAM_KEY_EXACT_LEN);

    uint8_t mac[SESSION_TOKEN_MAC_LEN];
    hmac_sha256((const uint8_t *)g_session_secret, g_session_secret_len, msg, sizeof(msg), mac);

    uint8_t raw[SESSION_TOKEN_RAW_LEN];
    memcpy(raw, msg, sizeof(msg));
    memcpy(raw + sizeof(msg), mac, SESSION_TOKEN_MAC_LEN);
    bytes_to_hex(raw, SESSION_TOKEN_RAW_LEN, out_hex);
}

/*
 * Verify HMAC + expiry, then return the authenticated stream key.
 * Whitelist (when loaded) is a second gate; open mode does not invert the token.
 */
int32_t extract_stream_key_from_token(const char *token_hex, char *out_key)
{
    if (token_hex == NULL || out_key == NULL) {
        return 0;
    }
    if (g_session_secret_set == 0 || g_session_secret_len < 16) {
        return 0;
    }

    const size_t token_len = bounded_strlen(token_hex, SESSION_TOKEN_HEX_LEN + 1);
    if (token_len != SESSION_TOKEN_HEX_LEN) {
        return 0;
    }

    uint8_t raw[SESSION_TOKEN_RAW_LEN];
    if (hex_to_bytes(token_hex, token_len, raw) == 0) {
        return 0;
    }

    const uint8_t *msg = raw;
    const size_t msg_len = SESSION_TOKEN_NONCE_LEN + SESSION_TOKEN_EXP_LEN + STREAM_KEY_EXACT_LEN;
    const uint8_t *mac = raw + msg_len;
    uint8_t expect[SESSION_TOKEN_MAC_LEN];
    hmac_sha256((const uint8_t *)g_session_secret, g_session_secret_len, msg, msg_len, expect);
    if (ct_memeq(mac, expect, SESSION_TOKEN_MAC_LEN) == 0) {
        return 0;
    }

    uint64_t exp = load_be64(raw + SESSION_TOKEN_NONCE_LEN);
    uint64_t now = (uint64_t)time(NULL);
    if (now > exp) {
        return 0;
    }

    char key[STREAM_KEY_EXACT_LEN + 1];
    memcpy(key, raw + SESSION_TOKEN_NONCE_LEN + SESSION_TOKEN_EXP_LEN, STREAM_KEY_EXACT_LEN);
    key[STREAM_KEY_EXACT_LEN] = '\0';
    if (is_format_valid(key) == 0) {
        return 0;
    }

    if (g_whitelist_count > 0) {
        int32_t found = 0;
        for (int32_t i = 0; i < g_whitelist_count; i++) {
            volatile int32_t diff = 0;
            for (size_t j = 0; j < STREAM_KEY_EXACT_LEN; j++) {
                diff |= (int32_t)((uint8_t)key[j] ^ (uint8_t)g_whitelist[i][j]);
            }
            if (diff == 0 && found == 0) {
                memcpy(out_key, key, STREAM_KEY_EXACT_LEN + 1);
                found = 1;
            }
        }
        return found;
    }

    memcpy(out_key, key, STREAM_KEY_EXACT_LEN + 1);
    return 1;
}

int32_t validate_session_token_for_key(const char *token_hex, const char *stream_key)
{
    if (token_hex == NULL || stream_key == NULL) {
        return 0;
    }
    if (is_format_valid(stream_key) == 0) {
        return 0;
    }

    char got[STREAM_KEY_EXACT_LEN + 1];
    if (extract_stream_key_from_token(token_hex, got) == 0) {
        return 0;
    }

    volatile int32_t diff = 0;
    for (size_t j = 0; j < STREAM_KEY_EXACT_LEN; j++) {
        diff |= (int32_t)((uint8_t)got[j] ^ (uint8_t)stream_key[j]);
    }
    return (diff == 0) ? 1 : 0;
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
    /* M33: reject over-long (no NUL within MAX) — do not compare truncated. */
    if (stored_len > MAX_ROOM_PASSWORD_LEN) {
        return 0;
    }
    if (stored_len == 0) {
        return 1;
    }

    if (submitted == NULL) {
        return 0;
    }

    const size_t submitted_len = bounded_strlen(submitted, MAX_ROOM_PASSWORD_LEN + 1);
    if (submitted_len > MAX_ROOM_PASSWORD_LEN) {
        return 0;
    }

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
