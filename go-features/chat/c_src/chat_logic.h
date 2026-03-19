#ifndef CHAT_LOGIC_H
#define CHAT_LOGIC_H

#include <stdint.h>

#define CHAT_MAX_MSG_LEN       500
#define CHAT_MAX_NICK_LEN       25
#define CHAT_MAX_CMD_ARG_LEN    64

#define CMD_NONE          0
#define CMD_BAN           1
#define CMD_UNBAN         2
#define CMD_TIMEOUT       3
#define CMD_SLOW          4
#define CMD_SUBSCRIBERS   5
#define CMD_CLEAR         6
#define CMD_MOD           7
#define CMD_UNMOD         8

typedef struct {
    int32_t type;
    char    arg1[CHAT_MAX_CMD_ARG_LEN + 1];
    int32_t arg2;
} chat_command_t;

int32_t is_nickname_valid(const char *nick);
int32_t parse_chat_command(const char *text, chat_command_t *out);
int32_t check_chat_rate_limit(int64_t last_msg_sec, int64_t now_sec,
                              int32_t slow_seconds);
int32_t apply_moderation(const char *text, char *out, int32_t max_len);

#endif /* CHAT_LOGIC_H */
