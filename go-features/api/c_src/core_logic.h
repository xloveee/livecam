#ifndef CORE_LOGIC_H
#define CORE_LOGIC_H

#include <stdint.h>

#define MAX_STREAM_KEY_LEN   64
#define STREAM_KEY_EXACT_LEN 32
#define MAX_IP_ADDR_LEN      45
#define MAX_ALLOWED_KEYS     64
#define VIEWER_CAP_UNLIMITED 0
#define SESSION_TOKEN_HEX_LEN 176

int32_t init_stream_key_whitelist(const char *csv);
int32_t stream_key_whitelist_count(void);
int32_t broadcast_password_is_set(void);
int32_t init_session_secret(const char *secret);
int32_t init_broadcast_password(const char *password);
int32_t check_broadcast_password(const char *submitted);
int32_t validate_stream_key(const char *key);
int32_t check_viewer_rate_limit(const char *ip_address);
int32_t check_viewer_cap(int32_t current_viewers, int32_t max_viewers);
int32_t check_room_password(const char *submitted, const char *stored);
void    public_slug_from_key(const char *stream_key, char *out_hex);
void    generate_session_token(const char *stream_key, char *out_hex);
int32_t extract_stream_key_from_token(const char *token_hex, char *out_key);
int32_t validate_session_token_for_key(const char *token_hex, const char *stream_key);

#endif /* CORE_LOGIC_H */
