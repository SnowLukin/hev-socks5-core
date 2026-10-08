#ifndef __HEV_SOCKS5_LOG_HISTORY_H__
#define __HEV_SOCKS5_LOG_HISTORY_H__

#include <stddef.h>

typedef struct
{
    size_t max_segment_bytes;
    size_t max_source_bytes;
    unsigned int max_segments;
} HevSocks5LogHistoryPolicy;

int hev_socks5_tunnel_log_history_configure (const char *directory,
                                              const char *connection_id,
                                              const HevSocks5LogHistoryPolicy *policy);
int hev_socks5_tunnel_log_history_state (char *buffer, size_t buffer_size);

#endif /* __HEV_SOCKS5_LOG_HISTORY_H__ */

