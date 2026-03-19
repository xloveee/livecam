#include "chat_logic.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ── Helpers ─────────────────────────────────────────────── */

static size_t chat_bounded_strlen(const char *s, size_t max_len)
{
    size_t i = 0;
    for (; i < max_len; i++) {
        if (s[i] == '\0') {
            return i;
        }
    }
    return max_len;
}

static int32_t is_nick_char(char c)
{
    if (c >= 'a' && c <= 'z') { return 1; }
    if (c >= 'A' && c <= 'Z') { return 1; }
    if (c >= '0' && c <= '9') { return 1; }
    if (c == '_') { return 1; }
    return 0;
}

static size_t skip_spaces(const char *text, size_t len, size_t pos)
{
    for (; pos < len && text[pos] == ' '; pos++) {}
    return pos;
}

static size_t extract_word(const char *text, size_t text_len, size_t pos,
                           char *out, size_t out_max)
{
    pos = skip_spaces(text, text_len, pos);
    size_t w = 0;
    for (; pos < text_len && text[pos] != ' ' && w < out_max; pos++) {
        out[w++] = text[pos];
    }
    out[w] = '\0';
    return skip_spaces(text, text_len, pos);
}

static int32_t parse_positive_int(const char *s, int32_t default_val)
{
    if (s == NULL || s[0] == '\0') { return default_val; }

    int32_t result = 0;
    for (int32_t i = 0; s[i] != '\0' && i < 10; i++) {
        if (s[i] < '0' || s[i] > '9') { return default_val; }
        int32_t digit = s[i] - '0';
        if (result > (2147483647 - digit) / 10) { return default_val; }
        result = result * 10 + digit;
    }
    return result;
}

static int32_t cmd_name_eq(const char *a, size_t a_len,
                           const char *b, size_t b_len)
{
    if (a_len != b_len) { return 0; }
    for (size_t i = 0; i < a_len; i++) {
        if (a[i] != b[i]) { return 0; }
    }
    return 1;
}

/* ── Nickname validation ─────────────────────────────────── */

int32_t is_nickname_valid(const char *nick)
{
    if (nick == NULL) { return 0; }

    const size_t len = chat_bounded_strlen(nick, CHAT_MAX_NICK_LEN + 1);
    if (len == 0 || len > CHAT_MAX_NICK_LEN) { return 0; }

    for (size_t i = 0; i < len; i++) {
        if (is_nick_char(nick[i]) == 0) { return 0; }
    }
    return 1;
}

/* ── Command parser ──────────────────────────────────────── */

int32_t parse_chat_command(const char *text, chat_command_t *out)
{
    if (text == NULL || out == NULL) { return 0; }

    out->type    = CMD_NONE;
    out->arg1[0] = '\0';
    out->arg2    = 0;

    const size_t len = chat_bounded_strlen(text, CHAT_MAX_MSG_LEN + 1);
    if (len < 2 || text[0] != '/') { return 0; }

    char cmd[16] = {0};
    size_t pos = extract_word(text, len, 0, cmd, 15);
    const size_t cmd_len = chat_bounded_strlen(cmd, 16);

    char word1[CHAT_MAX_CMD_ARG_LEN + 1] = {0};
    char word2[16] = {0};

    if (cmd_name_eq(cmd, cmd_len, "/ban", 4)) {
        pos = extract_word(text, len, pos, out->arg1, CHAT_MAX_CMD_ARG_LEN);
        out->type = (out->arg1[0] != '\0') ? CMD_BAN : CMD_NONE;

    } else if (cmd_name_eq(cmd, cmd_len, "/unban", 6)) {
        pos = extract_word(text, len, pos, out->arg1, CHAT_MAX_CMD_ARG_LEN);
        out->type = (out->arg1[0] != '\0') ? CMD_UNBAN : CMD_NONE;

    } else if (cmd_name_eq(cmd, cmd_len, "/timeout", 8)) {
        pos = extract_word(text, len, pos, out->arg1, CHAT_MAX_CMD_ARG_LEN);
        if (out->arg1[0] == '\0') { return 0; }
        extract_word(text, len, pos, word2, 15);
        out->arg2 = parse_positive_int(word2, 300);
        out->type = CMD_TIMEOUT;

    } else if (cmd_name_eq(cmd, cmd_len, "/slow", 5)) {
        extract_word(text, len, pos, word1, 15);
        out->arg2 = parse_positive_int(word1, 0);
        out->type = CMD_SLOW;

    } else if (cmd_name_eq(cmd, cmd_len, "/subscribers", 12)) {
        out->type = CMD_SUBSCRIBERS;

    } else if (cmd_name_eq(cmd, cmd_len, "/clear", 6)) {
        out->type = CMD_CLEAR;

    } else if (cmd_name_eq(cmd, cmd_len, "/mod", 4)) {
        extract_word(text, len, pos, out->arg1, CHAT_MAX_CMD_ARG_LEN);
        out->type = (out->arg1[0] != '\0') ? CMD_MOD : CMD_NONE;

    } else if (cmd_name_eq(cmd, cmd_len, "/unmod", 6)) {
        extract_word(text, len, pos, out->arg1, CHAT_MAX_CMD_ARG_LEN);
        out->type = (out->arg1[0] != '\0') ? CMD_UNMOD : CMD_NONE;

    } else {
        return 0;
    }

    return (out->type != CMD_NONE) ? 1 : 0;
}

/* ── Rate limiting (stateless — caller tracks timestamps) ── */

int32_t check_chat_rate_limit(int64_t last_msg_sec, int64_t now_sec,
                              int32_t slow_seconds)
{
    if (slow_seconds <= 0) { return 1; }
    if (now_sec - last_msg_sec >= (int64_t)slow_seconds) { return 1; }
    return 0;
}

/* ── Message moderation ──────────────────────────────────── */

int32_t apply_moderation(const char *text, char *out, int32_t max_len)
{
    if (text == NULL || out == NULL || max_len <= 0) {
        if (out != NULL && max_len > 0) { out[0] = '\0'; }
        return 0;
    }

    const size_t text_len = chat_bounded_strlen(text, CHAT_MAX_MSG_LEN + 1);

    /* Strip control characters (0x00–0x1F, 0x7F) */
    int32_t w = 0;
    for (size_t i = 0; i < text_len && w < max_len - 1; i++) {
        const unsigned char c = (unsigned char)text[i];
        if (c < 0x20 || c == 0x7F) { continue; }
        out[w++] = text[i];
    }
    out[w] = '\0';

    /* Trim leading whitespace */
    int32_t start = 0;
    for (; start < w && out[start] == ' '; start++) {}

    /* Trim trailing whitespace */
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
