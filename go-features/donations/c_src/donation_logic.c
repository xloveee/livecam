#include "donation_logic.h"
#include <stdint.h>
#include <stddef.h>

/* ── Helpers ─────────────────────────────────────────────── */

static size_t donation_bounded_strlen(const char *s, size_t max_len)
{
    size_t i = 0;
    for (; i < max_len; i++) {
        if (s[i] == '\0') {
            return i;
        }
    }
    return max_len;
}

static int32_t is_hex_char(char c)
{
    if (c >= '0' && c <= '9') { return 1; }
    if (c >= 'a' && c <= 'f') { return 1; }
    if (c >= 'A' && c <= 'F') { return 1; }
    return 0;
}

static int32_t is_base58_char(char c)
{
    if (c >= '1' && c <= '9') { return 1; }
    if (c >= 'a' && c <= 'z' && c != 'l') { return 1; }
    if (c >= 'A' && c <= 'Z' && c != 'I' && c != 'O') { return 1; }
    return 0;
}

static int32_t is_bech32_char(char c)
{
    if (c >= '0' && c <= '9') { return 1; }
    if (c >= 'a' && c <= 'z') { return 1; }
    return 0;
}

/* ── Amount validation ───────────────────────────────────── */

int32_t validate_donation_amount(int64_t amount, int64_t min_amount,
                                 int64_t max_amount)
{
    if (amount <= 0) { return 0; }
    if (min_amount > 0 && amount < min_amount) { return 0; }
    if (max_amount > 0 && amount > max_amount) { return 0; }
    return 1;
}

/* ── Message sanitization ────────────────────────────────── */

int32_t sanitize_donation_message(const char *text, char *out,
                                  int32_t max_len)
{
    if (text == NULL || out == NULL || max_len <= 0) {
        if (out != NULL && max_len > 0) { out[0] = '\0'; }
        return 0;
    }

    const size_t text_len = donation_bounded_strlen(
        text, DONATION_MSG_MAX_LEN + 1);

    int32_t w = 0;
    for (size_t i = 0; i < text_len && w < max_len - 1; i++) {
        const unsigned char c = (unsigned char)text[i];
        if (c < 0x20 || c == 0x7F) { continue; }
        out[w++] = text[i];
    }
    out[w] = '\0';

    int32_t start = 0;
    for (; start < w && out[start] == ' '; start++) {}

    int32_t end = w;
    for (; end > start && out[end - 1] == ' '; end--) {}

    const int32_t final_len = end - start;
    if (final_len <= 0) {
        out[0] = '\0';
        return 0;
    }

    if (start > 0) {
        for (int32_t i = 0; i < final_len; i++) {
            out[i] = out[start + i];
        }
    }
    out[final_len] = '\0';
    return final_len;
}

/* ── Rate limiting ───────────────────────────────────────── */

int32_t check_donation_rate_limit(int64_t last_donation_sec,
                                  int64_t now_sec,
                                  int32_t cooldown_sec)
{
    if (cooldown_sec <= 0) { return 1; }
    if (now_sec - last_donation_sec >= (int64_t)cooldown_sec) { return 1; }
    return 0;
}

/* ── BTC address validation ──────────────────────────────── */

int32_t validate_btc_address(const char *addr)
{
    if (addr == NULL) { return 0; }

    const size_t len = donation_bounded_strlen(addr, DONATION_ADDR_MAX_LEN + 1);
    if (len < 26 || len > 62) { return 0; }

    /* Legacy P2PKH (1...) or P2SH (3...): Base58Check */
    if (addr[0] == '1' || addr[0] == '3') {
        for (size_t i = 0; i < len; i++) {
            if (is_base58_char(addr[i]) == 0) { return 0; }
        }
        return 1;
    }

    /* Bech32 native segwit (bc1...) */
    if (len >= 4 && addr[0] == 'b' && addr[1] == 'c' &&
        addr[2] == '1') {
        for (size_t i = 3; i < len; i++) {
            if (is_bech32_char(addr[i]) == 0) { return 0; }
        }
        return 1;
    }

    return 0;
}

/* ── ETH address validation ──────────────────────────────── */

int32_t validate_eth_address(const char *addr)
{
    if (addr == NULL) { return 0; }

    const size_t len = donation_bounded_strlen(addr, DONATION_ADDR_MAX_LEN + 1);
    if (len != 42) { return 0; }
    if (addr[0] != '0' || addr[1] != 'x') { return 0; }

    for (size_t i = 2; i < 42; i++) {
        if (is_hex_char(addr[i]) == 0) { return 0; }
    }

    return 1;
}
