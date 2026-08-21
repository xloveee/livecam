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
#define CMD_IPBAN         9

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

/* Per-IP / per-session flood ladder (stateless C, caller owns chat_flood_t). */
#define FLOOD_WINDOW_SEC        10
#define FLOOD_MAX_IN_WINDOW     5
#define FLOOD_DECAY_SEC         120
#define FLOOD_MUTE_STRIKE1      30
#define FLOOD_MUTE_STRIKE2      120
#define FLOOD_MUTE_STRIKE3      600
#define FLOOD_BAN_STRIKE        4
#define FLOOD_STAMP_CAP         8

#define FLOOD_ALLOW   0
#define FLOOD_MUTED   1
#define FLOOD_STRIKE  2
#define FLOOD_BAN     3

typedef struct chat_flood {
    int64_t stamps[FLOOD_STAMP_CAP];
    int32_t count;
    int32_t strikes;
    int64_t mute_until;
    int64_t last_seen;
} chat_flood_t;

int32_t flood_mute_seconds(int32_t strikes);
int32_t check_chat_flood(chat_flood_t *st, int64_t now_sec, int32_t *mute_left);

#endif /* CHAT_LOGIC_H */
