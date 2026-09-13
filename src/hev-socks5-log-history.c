#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "hev-socks5-log-history.h"
#include "hev-socks5-log-history-internal.h"

#define HEV_LOG_HISTORY_DEFAULT_SEGMENT_BYTES (2u * 1024u * 1024u)
#define HEV_LOG_HISTORY_DEFAULT_SOURCE_BYTES (8u * 1024u * 1024u)
#define HEV_LOG_HISTORY_DEFAULT_SEGMENTS 4u
#define HEV_LOG_HISTORY_MAX_STATE_BYTES 4096u
#define HEV_LOG_HISTORY_MIN_SEGMENT_BYTES 512u
#define HEV_LOG_HISTORY_MAX_DIRECTORY_BYTES 1024u
#define HEV_LOG_HISTORY_MAX_CONNECTION_ID_BYTES 512u

struct log_part {
    char *path;
    off_t bytes;
    uint64_t ordinal;
    int legacy;
    int active;
};

static pthread_mutex_t history_lock = PTHREAD_MUTEX_INITIALIZER;
static char *history_directory;
static char *history_connection_id;
static HevSocks5LogHistoryPolicy history_policy;
static char history_state[HEV_LOG_HISTORY_MAX_STATE_BYTES];
static int history_configured;
static int history_failed;
static int history_fd = -1;
static int history_refs;
static uint64_t history_next_number = 1;
static off_t history_active_bytes;
static char history_active_path[PATH_MAX];

static char *
copy_string (const char *value, size_t limit)
{
    size_t length;
    char *copy;

    if (!value)
        return NULL;

    length = strnlen (value, limit + 1);
    if (length > limit)
        return NULL;

    copy = malloc (length + 1);
    if (!copy)
        return NULL;

    memcpy (copy, value, length + 1);
    return copy;
}

static char *
json_string (const char *value)
{
    const unsigned char *source = (const unsigned char *)(value ? value : "");
    char *escaped;
    char *target;
    size_t length = strlen ((const char *)source);
    size_t index;

    if (length > (SIZE_MAX - 3) / 6)
        return NULL;

    escaped = malloc (length * 6 + 3);
    if (!escaped)
        return NULL;

    target = escaped;
    *target++ = '"';
    for (index = 0; index < length; index++) {
        unsigned char c = source[index];

        switch (c) {
        case '"':
            *target++ = '\\';
            *target++ = '"';
            break;
        case '\\':
            *target++ = '\\';
            *target++ = '\\';
            break;
        case '\b':
            *target++ = '\\';
            *target++ = 'b';
            break;
        case '\f':
            *target++ = '\\';
            *target++ = 'f';
            break;
        case '\n':
            *target++ = '\\';
            *target++ = 'n';
            break;
        case '\r':
            *target++ = '\\';
            *target++ = 'r';
            break;
        case '\t':
            *target++ = '\\';
            *target++ = 't';
            break;
        default:
            if (c < 0x20) {
                static const char hex[] = "0123456789abcdef";
                *target++ = '\\';
                *target++ = 'u';
                *target++ = '0';
                *target++ = '0';
                *target++ = hex[c >> 4];
                *target++ = hex[c & 0x0f];
            } else {
                *target++ = (char)c;
            }
            break;
        }
    }
    *target++ = '"';
    *target = '\0';

    return escaped;
}

static char *
build_record (const char *level, const char *kind, const char *message, int truncated)
{
    char timestamp[40];
    struct timeval now;
    struct tm utc;
    char *escaped_message;
    char *escaped_connection;
    char *record;
    int length;

    if (gettimeofday (&now, NULL) < 0)
        return NULL;
    if (!gmtime_r (&now.tv_sec, &utc))
        return NULL;
    if (0 == strftime (timestamp, sizeof (timestamp), "%Y-%m-%dT%H:%M:%S", &utc))
        return NULL;
    snprintf (timestamp + strlen (timestamp),
              sizeof (timestamp) - strlen (timestamp), ".%06dZ", (int)now.tv_usec);

    escaped_message = json_string (message);
    escaped_connection = history_connection_id ? json_string (history_connection_id) : NULL;
    if (!escaped_message || (history_connection_id && !escaped_connection)) {
        free (escaped_message);
        free (escaped_connection);
        return NULL;
    }

    length = snprintf (NULL, 0,
                       "{\"v\":1,\"timestamp\":\"%s\",\"source\":\"tun2socks\",\"level\":\"%s\",\"connectionId\":%s,\"kind\":\"%s\",\"message\":%s%s}\n",
                       timestamp, level, escaped_connection ? escaped_connection : "null",
                       kind, escaped_message, truncated ? ",\"truncated\":true" : "");
    if (length < 0) {
        free (escaped_message);
        free (escaped_connection);
        return NULL;
    }

    record = malloc ((size_t)length + 1);
    if (record) {
        snprintf (record, (size_t)length + 1,
                  "{\"v\":1,\"timestamp\":\"%s\",\"source\":\"tun2socks\",\"level\":\"%s\",\"connectionId\":%s,\"kind\":\"%s\",\"message\":%s%s}\n",
                  timestamp, level, escaped_connection ? escaped_connection : "null",
                  kind, escaped_message, truncated ? ",\"truncated\":true" : "");
    }
    free (escaped_message);
    free (escaped_connection);

    return record;
}

static int
write_state_locked (const char *status, const char *error_code)
{
    char *escaped_connection;
    char state[HEV_LOG_HISTORY_MAX_STATE_BYTES];
    char temporary[PATH_MAX];
    int fd;
    int length;

    escaped_connection = history_connection_id ? json_string (history_connection_id) : NULL;
    if (history_connection_id && !escaped_connection)
        return -1;

    if (error_code) {
        length = snprintf (state, sizeof (state),
                           "{\"v\":1,\"status\":\"%s\",\"connectionId\":%s,\"errorCode\":\"%s\"}\n",
                           status, escaped_connection ? escaped_connection : "null", error_code);
    } else {
        length = snprintf (state, sizeof (state),
                           "{\"v\":1,\"status\":\"%s\",\"connectionId\":%s}\n",
                           status, escaped_connection ? escaped_connection : "null");
    }
    free (escaped_connection);

    if (length <= 0 || (size_t)length >= sizeof (state))
        return -1;

    memcpy (history_state, state, (size_t)length + 1);
    if (!history_directory)
        return 0;

    snprintf (temporary, sizeof (temporary), "%s/.tun2socks.state.%ld",
              history_directory, (long)getpid ());
    fd = open (temporary, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (fd < 0)
        return -1;
    if (write (fd, state, (size_t)length) != length) {
        close (fd);
        unlink (temporary);
        return -1;
    }
    if (close (fd) < 0) {
        unlink (temporary);
        return -1;
    }
    {
        char path[PATH_MAX];
        snprintf (path, sizeof (path), "%s/tun2socks.state.json", history_directory);
        if (rename (temporary, path) < 0) {
            unlink (temporary);
            return -1;
        }
    }
    return 0;
}

static void
fail_locked (const char *error_code)
{
    if (history_fd >= 0) {
        close (history_fd);
        history_fd = -1;
    }
    history_failed = 1;
    write_state_locked ("failed", error_code);
}

static int
is_part_name (const char *name, uint64_t *number)
{
    const char *digits = name + strlen ("tun2socks.");
    char *end;
    size_t index;

    if (strncmp (name, "tun2socks.", strlen ("tun2socks.")) != 0 ||
        strlen (digits) != 20 + strlen (".jsonl") ||
        strcmp (digits + 20, ".jsonl") != 0)
        return 0;
    for (index = 0; index < 20; index++) {
        if (digits[index] < '0' || digits[index] > '9')
            return 0;
    }
    errno = 0;
    *number = strtoull (digits, &end, 10);
    if (errno == ERANGE || end != digits + 20)
        return 0;
    return 1;
}

static int
is_legacy_name (const char *name)
{
    return 0 == strcmp (name, "tun2socks.log") ||
           0 == strcmp (name, "tun2socks.log.old");
}

static int
append_part (struct log_part **parts, size_t *count, size_t *capacity,
             const char *path, const struct stat *st, uint64_t ordinal,
             int legacy, int active)
{
    struct log_part *expanded;
    char *copy;

    if (*count == *capacity) {
        size_t new_capacity = *capacity ? *capacity * 2 : 8;
        expanded = realloc (*parts, new_capacity * sizeof (**parts));
        if (!expanded)
            return -1;
        *parts = expanded;
        *capacity = new_capacity;
    }

    copy = strdup (path);
    if (!copy)
        return -1;

    (*parts)[*count].path = copy;
    (*parts)[*count].bytes = st->st_size;
    (*parts)[*count].ordinal = ordinal;
    (*parts)[*count].legacy = legacy;
    (*parts)[*count].active = active;
    (*count)++;
    return 0;
}

static void
free_parts (struct log_part *parts, size_t count)
{
    size_t index;

    for (index = 0; index < count; index++)
        free (parts[index].path);
    free (parts);
}

static int
part_compare (const void *left, const void *right)
{
    const struct log_part *a = left;
    const struct log_part *b = right;

    if (a->legacy && !b->legacy)
        return -1;
    if (!a->legacy && b->legacy)
        return 1;
    if (a->legacy || b->legacy) {
        if (a->ordinal < b->ordinal)
            return -1;
        if (a->ordinal > b->ordinal)
            return 1;
        return strcmp (a->path, b->path);
    }
    if (a->ordinal < b->ordinal)
        return -1;
    if (a->ordinal > b->ordinal)
        return 1;
    return strcmp (a->path, b->path);
}

static int
collect_parts_locked (struct log_part **parts, size_t *count, uint64_t *highest)
{
    struct dirent *entry;
    struct stat st;
    char path[PATH_MAX];
    DIR *dir;
    size_t capacity = 0;

    *parts = NULL;
    *count = 0;
    *highest = 0;

    dir = opendir (history_directory);
    if (!dir)
        return -1;

    while ((entry = readdir (dir))) {
        uint64_t number = 0;
        int numbered;

        numbered = is_part_name (entry->d_name, &number);
        if (!numbered && !is_legacy_name (entry->d_name))
            continue;
        if (snprintf (path, sizeof (path), "%s/%s", history_directory, entry->d_name) >=
            (int)sizeof (path))
            continue;
        if (stat (path, &st) < 0 || !S_ISREG (st.st_mode))
            continue;
        if (append_part (parts, count, &capacity, path, &st,
                         numbered ? number : (0 == strcmp (entry->d_name, "tun2socks.log.old") ? 0 : 1),
                         !numbered,
                         0 == strcmp (path, history_active_path)) < 0) {
            closedir (dir);
            free_parts (*parts, *count);
            return -1;
        }
        if (numbered && number > *highest)
            *highest = number;
    }
    closedir (dir);
    return 0;
}

static int
part_has_newline (const char *path, off_t bytes)
{
    char last;
    int fd;

    if (bytes == 0)
        return 1;
    fd = open (path, O_RDONLY);
    if (fd < 0)
        return 0;
    if (pread (fd, &last, 1, bytes - 1) != 1) {
        close (fd);
        return 0;
    }
    close (fd);
    return last == '\n';
}

static int
cleanup_locked (off_t reserved_bytes)
{
    struct log_part *parts;
    uint64_t highest;
    size_t count;
    size_t original_count;
    size_t index;
    size_t remaining;
    off_t bytes = 0;

    if (reserved_bytes < 0 || reserved_bytes > (off_t)history_policy.max_source_bytes)
        return -1;
    if (collect_parts_locked (&parts, &count, &highest) < 0)
        return -1;
    original_count = count;
    remaining = count;
    for (index = 0; index < count; index++)
        bytes += parts[index].bytes;
    bytes += reserved_bytes;
    qsort (parts, count, sizeof (*parts), part_compare);

    for (index = 0; index < original_count &&
         (remaining > history_policy.max_segments || bytes > (off_t)history_policy.max_source_bytes);
         index++) {
        if (parts[index].active)
            continue;
        if (unlink (parts[index].path) < 0) {
            free_parts (parts, original_count);
            return -1;
        }
        bytes -= parts[index].bytes;
        remaining--;
    }
    if (remaining > history_policy.max_segments ||
        bytes > (off_t)history_policy.max_source_bytes) {
        free_parts (parts, original_count);
        return -1;
    }
    free_parts (parts, original_count);
    return 0;
}

static int
open_new_part_locked (void)
{
    char path[PATH_MAX];
    int fd;

    if (history_next_number == 0)
        return -1;
    if (snprintf (path, sizeof (path), "%s/tun2socks.%020llu.jsonl", history_directory,
                  (unsigned long long)history_next_number) >= (int)sizeof (path))
        return -1;
    fd = open (path, O_WRONLY | O_APPEND | O_CREAT | O_EXCL, 0640);
    if (fd < 0)
        return -1;

    history_fd = fd;
    history_active_bytes = 0;
    memcpy (history_active_path, path, strlen (path) + 1);
    if (history_next_number == UINT64_MAX)
        history_next_number = 0;
    else
        history_next_number++;
    return 0;
}

static void
discard_active_part_locked (void)
{
    if (history_fd >= 0) {
        close (history_fd);
        history_fd = -1;
    }
    if (history_active_path[0])
        unlink (history_active_path);
    history_active_path[0] = '\0';
    history_active_bytes = 0;
}

static int
open_history_locked (void)
{
    struct log_part *parts;
    uint64_t highest;
    size_t count;
    size_t index;
    size_t last_index = 0;
    uint64_t last_number = 0;
    int found = 0;
    int opened_new = 0;
    int fd;

    if (mkdir (history_directory, 0700) < 0 && errno != EEXIST)
        return -1;
    if (collect_parts_locked (&parts, &count, &highest) < 0)
        return -1;

    for (index = 0; index < count; index++) {
        uint64_t number;
        const char *name = strrchr (parts[index].path, '/');

        if (!name || !is_part_name (name + 1, &number))
            continue;
        if (!found || number > last_number) {
            last_number = number;
            last_index = index;
            found = 1;
        }
    }

    history_next_number = found && highest == UINT64_MAX ? 0 : highest + 1;
    if (found && parts[last_index].bytes < (off_t)history_policy.max_segment_bytes &&
        part_has_newline (parts[last_index].path, parts[last_index].bytes)) {
        fd = open (parts[last_index].path, O_WRONLY | O_APPEND);
        if (fd < 0) {
            free_parts (parts, count);
            return -1;
        }
        history_fd = fd;
        history_active_bytes = parts[last_index].bytes;
        memcpy (history_active_path, parts[last_index].path,
                strlen (parts[last_index].path) + 1);
    } else {
        if (open_new_part_locked () < 0) {
            free_parts (parts, count);
            return -1;
        }
        opened_new = 1;
    }
    free_parts (parts, count);

    if (cleanup_locked (0) < 0) {
        if (opened_new)
            discard_active_part_locked ();
        else if (history_fd >= 0) {
            close (history_fd);
            history_fd = -1;
        }
        return -1;
    }
    return 0;
}

static int
write_all (int fd, const char *data, size_t length)
{
    while (length > 0) {
        ssize_t written = write (fd, data, length);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return -1;
        data += written;
        length -= (size_t)written;
    }
    return 0;
}

static int
write_record_locked (const char *record, size_t length)
{
    if (write_all (history_fd, record, length) < 0)
        return -1;
    history_active_bytes += (off_t)length;
    return 0;
}

int
hev_socks5_tunnel_log_history_configure (const char *directory,
                                         const char *connection_id,
                                         const HevSocks5LogHistoryPolicy *policy)
{
    HevSocks5LogHistoryPolicy resolved = {
        HEV_LOG_HISTORY_DEFAULT_SEGMENT_BYTES,
        HEV_LOG_HISTORY_DEFAULT_SOURCE_BYTES,
        HEV_LOG_HISTORY_DEFAULT_SEGMENTS,
    };
    char *directory_copy = NULL;
    char *connection_copy = NULL;

    if (policy)
        resolved = *policy;
    if (resolved.max_segment_bytes < HEV_LOG_HISTORY_MIN_SEGMENT_BYTES ||
        resolved.max_source_bytes < resolved.max_segment_bytes ||
        resolved.max_segments == 0 ||
        resolved.max_segments > resolved.max_source_bytes / resolved.max_segment_bytes)
        return -1;

    if (directory && directory[0]) {
        directory_copy = copy_string (directory, HEV_LOG_HISTORY_MAX_DIRECTORY_BYTES);
        if (!directory_copy)
            return -1;
        connection_copy = copy_string (connection_id, HEV_LOG_HISTORY_MAX_CONNECTION_ID_BYTES);
        if (connection_id && !connection_copy) {
            free (directory_copy);
            return -1;
        }
    }

    pthread_mutex_lock (&history_lock);
    if (history_refs > 0) {
        if (!directory_copy) {
            int state_failed = 0;
            int close_failed = 0;
            int previous_failed = history_failed;

            if (history_fd >= 0) {
                if (close (history_fd) < 0)
                    close_failed = 1;
                history_fd = -1;
            }
            if (close_failed) {
                history_failed = 1;
                write_state_locked ("failed", "write-failed");
                state_failed = 1;
            } else if (!previous_failed && write_state_locked ("closed", NULL) < 0) {
                history_failed = 1;
                write_state_locked ("failed", "state-write-failed");
                state_failed = 1;
            }
            free (history_directory);
            free (history_connection_id);
            history_directory = NULL;
            history_connection_id = NULL;
            history_configured = 0;
            history_active_path[0] = '\0';
            pthread_mutex_unlock (&history_lock);
            return state_failed ? -1 : 0;
        }
        pthread_mutex_unlock (&history_lock);
        free (directory_copy);
        free (connection_copy);
        return -1;
    }
    free (history_directory);
    free (history_connection_id);
    history_directory = directory_copy;
    history_connection_id = connection_copy;
    history_policy = resolved;
    history_configured = directory_copy != NULL;
    history_failed = 0;
    history_state[0] = '\0';
    history_active_path[0] = '\0';
    pthread_mutex_unlock (&history_lock);

    return 0;
}

int
hev_socks5_tunnel_log_history_state (char *buffer, size_t buffer_size)
{
    if (!buffer || buffer_size == 0)
        return -1;

    pthread_mutex_lock (&history_lock);
    if (history_state[0]) {
        snprintf (buffer, buffer_size, "%s", history_state);
        pthread_mutex_unlock (&history_lock);
        return 0;
    }
    pthread_mutex_unlock (&history_lock);
    return -1;
}

int
hev_socks5_log_history_enabled (void)
{
    int enabled;

    pthread_mutex_lock (&history_lock);
    enabled = history_configured;
    pthread_mutex_unlock (&history_lock);
    return enabled;
}

int
hev_socks5_log_history_acquire (void)
{
    int result = 0;

    pthread_mutex_lock (&history_lock);
    if (!history_configured) {
        result = -1;
    } else if (history_failed) {
        result = -1;
    } else if (history_refs == 0) {
        if (open_history_locked () < 0) {
            fail_locked ("open-failed");
            result = -1;
        } else if (write_state_locked ("active", NULL) < 0) {
            fail_locked ("state-write-failed");
            result = -1;
        }
    }
    if (result == 0)
        history_refs++;
    pthread_mutex_unlock (&history_lock);

    return result;
}

void
hev_socks5_log_history_release (void)
{
    pthread_mutex_lock (&history_lock);
    if (history_refs > 0)
        history_refs--;
    if (history_refs == 0 && history_fd >= 0) {
        int close_failed = close (history_fd) < 0;

        history_fd = -1;
        if (close_failed)
            fail_locked ("write-failed");
        else if (write_state_locked ("closed", NULL) < 0)
            fail_locked ("state-write-failed");
    }
    pthread_mutex_unlock (&history_lock);
}

int
hev_socks5_log_history_active (void)
{
    int active;

    pthread_mutex_lock (&history_lock);
    active = history_fd >= 0 && !history_failed;
    pthread_mutex_unlock (&history_lock);
    return active;
}

void
hev_socks5_log_history_write (const char *level, const char *message)
{
    char *record;
    size_t length;

    pthread_mutex_lock (&history_lock);
    if (history_fd < 0 || history_failed) {
        pthread_mutex_unlock (&history_lock);
        return;
    }

    record = build_record (level, "log", message, 0);
    if (!record) {
        fail_locked ("encode-failed");
        pthread_mutex_unlock (&history_lock);
        return;
    }
    length = strlen (record);
    if (length > history_policy.max_segment_bytes) {
        free (record);
        record = build_record (level, "log", "record exceeds maxSegmentBytes", 1);
        if (!record) {
            fail_locked ("encode-failed");
            pthread_mutex_unlock (&history_lock);
            return;
        }
        length = strlen (record);
        if (length > history_policy.max_segment_bytes) {
            free (record);
            fail_locked ("record-too-large");
            pthread_mutex_unlock (&history_lock);
            return;
        }
    }

    if (history_active_bytes > 0 &&
        history_active_bytes + (off_t)length > (off_t)history_policy.max_segment_bytes) {
        close (history_fd);
        history_fd = -1;
        if (open_new_part_locked () < 0) {
            free (record);
            fail_locked ("rotate-failed");
            pthread_mutex_unlock (&history_lock);
            return;
        }
        if (cleanup_locked ((off_t)length) < 0) {
            discard_active_part_locked ();
            free (record);
            fail_locked ("cleanup-failed");
            pthread_mutex_unlock (&history_lock);
            return;
        }
        if (write_record_locked (record, length) < 0) {
            free (record);
            fail_locked ("write-failed");
            pthread_mutex_unlock (&history_lock);
            return;
        }
    } else if (write_record_locked (record, length) < 0) {
        free (record);
        fail_locked ("write-failed");
        pthread_mutex_unlock (&history_lock);
        return;
    }
    free (record);
    pthread_mutex_unlock (&history_lock);
}
