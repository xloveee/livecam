#ifndef DONATION_LOGIC_H
#define DONATION_LOGIC_H

#include <stdint.h>

#define DONATION_MSG_MAX_LEN      200
#define DONATION_CURRENCY_MAX_LEN   8
#define DONATION_ADDR_MAX_LEN     128

/*
 * Validate a donation amount.
 * Returns 1 if amount is within [min_amount, max_amount] and positive.
 * Returns 0 if invalid.
 */
int32_t validate_donation_amount(int64_t amount, int64_t min_amount,
                                 int64_t max_amount);

/*
 * Sanitize a donation message: strip control characters, trim whitespace,
 * enforce length cap. Reuses the same logic pattern as apply_moderation()
 * in chat_logic.c.
 *
 * Returns the sanitized length, or 0 if empty after sanitization.
 * out must be at least max_len bytes.
 */
int32_t sanitize_donation_message(const char *text, char *out,
                                  int32_t max_len);

/*
 * Stateless rate limit check for donations.
 * Returns 1 if allowed, 0 if cooldown has not elapsed.
 */
int32_t check_donation_rate_limit(int64_t last_donation_sec,
                                  int64_t now_sec,
                                  int32_t cooldown_sec);

/*
 * Basic BTC address format validation.
 * Checks length (26–62 chars) and allowed character set.
 * Returns 1 if plausible, 0 if obviously invalid.
 */
int32_t validate_btc_address(const char *addr);

/*
 * Basic ETH address format validation.
 * Checks "0x" prefix and 40 hex characters (42 total).
 * Returns 1 if plausible, 0 if obviously invalid.
 */
int32_t validate_eth_address(const char *addr);

#endif /* DONATION_LOGIC_H */
