#ifndef __HEV_SOCKS5_LOG_HISTORY_INTERNAL_H__
#define __HEV_SOCKS5_LOG_HISTORY_INTERNAL_H__

int hev_socks5_log_history_enabled (void);
int hev_socks5_log_history_acquire (void);
void hev_socks5_log_history_release (void);
int hev_socks5_log_history_active (void);
void hev_socks5_log_history_write (const char *level, const char *message);

#endif /* __HEV_SOCKS5_LOG_HISTORY_INTERNAL_H__ */
