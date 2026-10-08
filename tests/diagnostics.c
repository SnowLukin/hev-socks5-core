#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <hev-task-system.h>
#include <hev-task.h>
#include <hev-task-io.h>

#include <hev-task-io-socket.h>
#include "hev-socks5-client-tcp.h"
#include "hev-socks5-client-udp.h"
#include "hev-socks5-server.h"
#include "hev-socks5-misc.h"
#include "hev-socks5-misc-priv.h"
#include "hev-socks5-logger.h"

static const char *log_path;
static char log_text[16384];

static void
begin_log (void)
{
    FILE *file = fopen (log_path, "w");
    assert (file);
    fclose (file);
    assert (!hev_socks5_logger_init (HEV_SOCKS5_LOGGER_INFO, log_path));
}

static void
expect_log (const char *target, const char *reason)
{
    FILE *file;
    size_t len;
    char *failure;
    hev_socks5_logger_fini ();
    file = fopen (log_path, "r");
    assert (file);
    len = fread (log_text, 1, sizeof (log_text) - 1, file);
    log_text[len] = 0;
    fclose (file);
    if (!strstr (log_text, target) || !strstr (log_text, reason)) {
        fprintf (stderr, "Expected target=%s reason=%s; got:\n%s", target,
                 reason, log_text);
        abort ();
    }
    failure = strstr (log_text, "socks5 failure");
    assert (failure && !strstr (failure + 1, "socks5 failure"));
    assert (!strstr (log_text, "private-user"));
    assert (!strstr (log_text, "private-password"));
}

static HevSocks5ClientTCP *
new_client (int ipv6)
{
    unsigned char addr[16];
    assert (inet_pton (ipv6 ? AF_INET6 : AF_INET,
                       ipv6 ? "2001:db8::1" : "203.0.113.9", addr) == 1);
    return ipv6 ? hev_socks5_client_tcp_new_ipv6 (addr, htons (443)) :
                  hev_socks5_client_tcp_new_ipv4 (addr, htons (443));
}

static void
handshake_case (const unsigned char *reply, size_t len, const char *reason,
                int ipv6, int pipeline)
{
    HevSocks5ClientTCP *client;
    int fd[2];
    begin_log ();
    client = new_client (ipv6);
    assert (client);
    hev_socks5_client_set_auth (HEV_SOCKS5_CLIENT (client), "private-user",
                                "private-password");
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, fd));
    assert (!hev_task_add_fd (hev_task_self (), fd[0], POLLIN | POLLOUT));
    HEV_SOCKS5 (client)->fd = fd[0];
    assert (write (fd[1], reply, len) == (ssize_t)len);
    shutdown (fd[1], SHUT_WR);
    errno = EACCES;
    assert (hev_socks5_client_handshake (HEV_SOCKS5_CLIENT (client), pipeline) <
            0);
    expect_log (ipv6 ? "target=[2001:db8::1]:443" : "target=[203.0.113.9]:443",
                reason);
    hev_object_unref (HEV_OBJECT (client));
    close (fd[1]);
}

static void
expect_silent_failure (void)
{
    FILE *file;
    size_t len;
    hev_socks5_logger_fini ();
    file = fopen (log_path, "r");
    assert (file);
    len = fread (log_text, 1, sizeof (log_text) - 1, file);
    log_text[len] = 0;
    fclose (file);
    assert (!strstr (log_text, "failure"));
    assert (!strstr (log_text, "timeout"));
}

static void
connection_refusal (void)
{
    struct sockaddr_in6 addr = { 0 };
    socklen_t len = sizeof (addr);
    HevSocks5ClientTCP *client;
    int fd;
    begin_log ();
    client = new_client (0);
    fd = socket (AF_INET6, SOCK_STREAM, 0);
    assert (fd >= 0);
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_loopback;
    assert (!bind (fd, (struct sockaddr *)&addr, sizeof (addr)));
    assert (!getsockname (fd, (struct sockaddr *)&addr, &len));
    close (fd);
    errno = EACCES;
    assert (hev_socks5_client_connect (HEV_SOCKS5_CLIENT (client), "::1",
                                       ntohs (addr.sin6_port)) < 0);
    expect_log ("target=[203.0.113.9]:443", "operation=proxy-connect");
    assert (strstr (log_text, strerror (ECONNREFUSED)));
    hev_object_unref (HEV_OBJECT (client));
}

static void
connection_timeout (int server_mode)
{
    struct sockaddr_in6 addr = { 0 };
    socklen_t len = sizeof (addr);
    HevSocks5 *connection;
    int peer = -1;
    int queued[16], count = 0, pending = 0;
    int listener, i;
    char code[32];
#ifndef CORE_LEGACY_UDP
    int previous_timeout = hev_socks5_get_connect_timeout ();
#endif

    listener = socket (AF_INET6, SOCK_STREAM, 0);
    assert (listener >= 0);
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_loopback;
    assert (!bind (listener, (struct sockaddr *)&addr, sizeof (addr)));
    assert (!getsockname (listener, (struct sockaddr *)&addr, &len));
    assert (!listen (listener, 1));

    while (count < 16) {
        struct pollfd poll_fd;
        int error = 0;
        socklen_t error_len = sizeof (error);
        int fd = hev_task_io_socket_socket (AF_INET6, SOCK_STREAM, 0);
        assert (fd >= 0);
        queued[count++] = fd;
        if (connect (fd, (struct sockaddr *)&addr, sizeof (addr)) == 0)
            continue;
        assert (errno == EINPROGRESS);
        poll_fd.fd = fd;
        poll_fd.events = POLLOUT;
        poll_fd.revents = 0;
        i = poll (&poll_fd, 1, 10);
        assert (i >= 0);
        if (i == 0) {
            pending = 1;
            break;
        }
        assert (!getsockopt (fd, SOL_SOCKET, SO_ERROR, &error, &error_len));
        assert (!error);
    }
    assert (pending);

    begin_log ();
    if (server_mode) {
        unsigned char request[25] = { 5, 1, 0, 5, 1, 0, 4 };
        int fd[2];
        assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, fd));
        connection = HEV_SOCKS5 (hev_socks5_server_new (fd[0]));
        peer = fd[1];
        memcpy (request + 7, &addr.sin6_addr, 16);
        memcpy (request + 23, &addr.sin6_port, 2);
        assert (write (peer, request, sizeof (request)) == sizeof (request));
    } else {
        connection = HEV_SOCKS5 (new_client (1));
    }
#ifdef CORE_LEGACY_UDP
    hev_socks5_set_timeout (connection, 10);
    if (server_mode)
        hev_socks5_server_set_connect_timeout (HEV_SOCKS5_SERVER (connection),
                                               10);
#else
    hev_socks5_set_connect_timeout (10);
#endif
    errno = EACCES;
    if (server_mode)
        assert (hev_socks5_server_run (HEV_SOCKS5_SERVER (connection)) < 0);
    else
        assert (hev_socks5_client_connect (HEV_SOCKS5_CLIENT (connection),
                                           "::1", ntohs (addr.sin6_port)) < 0);
#ifndef CORE_LEGACY_UDP
    hev_socks5_set_connect_timeout (previous_timeout);
#endif
    expect_log (server_mode ? "target=unknown" : "target=[2001:db8::1]:443",
                server_mode ? "operation=server-connect reason=timeout" :
                              "operation=proxy-connect reason=timeout");
    snprintf (code, sizeof (code), "code=%d", ETIMEDOUT);
    assert (strstr (log_text, code));
    assert (!strstr (log_text, strerror (EACCES)));
    hev_object_unref (HEV_OBJECT (connection));
    if (peer >= 0)
        close (peer);
    for (i = 0; i < count; i++)
        close (queued[i]);
    close (listener);
}

static HevSocks5 *cancel_client;
static HevTask *waiting_task;

static void
cancel_wait (void *data)
{
    (void)data;
    hev_task_sleep (5);
    hev_socks5_set_timeout (cancel_client, 0);
    hev_task_wakeup (waiting_task);
}

static void
server_handshake_wait (int cancel)
{
    HevSocks5Server *server;
    int fd[2];
#ifndef CORE_LEGACY_UDP
    int previous_timeout = hev_socks5_get_tcp_timeout ();
    hev_socks5_set_tcp_timeout (15);
#endif
    begin_log ();
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, fd));
    server = hev_socks5_server_new (fd[0]);
    hev_socks5_set_timeout (HEV_SOCKS5 (server), cancel == 1 ? 0 : 15);
    if (cancel == 2) {
        HevTask *task = hev_task_new (16384);
        cancel_client = HEV_SOCKS5 (server);
        waiting_task = hev_task_self ();
        hev_task_run (task, cancel_wait, NULL);
    }
    errno = EACCES;
    assert (hev_socks5_server_run (server) < 0);
#ifndef CORE_LEGACY_UDP
    hev_socks5_set_tcp_timeout (previous_timeout);
#endif
    if (cancel) {
        expect_silent_failure ();
    } else {
        char code[32];
        expect_log ("target=unknown",
                    "operation=server-handshake reason=timeout");
        snprintf (code, sizeof (code), "code=%d", ETIMEDOUT);
        assert (strstr (log_text, code));
        assert (!strstr (log_text, strerror (EACCES)));
    }
    hev_object_unref (HEV_OBJECT (server));
    close (fd[1]);
}

static void
wait_case (int cancel)
{
    HevSocks5ClientTCP *client;
    int fd[2];
    begin_log ();
    client = new_client (0);
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, fd));
    assert (!hev_task_add_fd (hev_task_self (), fd[0], POLLIN | POLLOUT));
    HEV_SOCKS5 (client)->fd = fd[0];
#ifndef CORE_LEGACY_UDP
    hev_socks5_set_tcp_timeout (20);
#endif
    hev_socks5_set_timeout (HEV_SOCKS5 (client), 20);
    if (cancel == 1) {
        hev_socks5_set_timeout (HEV_SOCKS5 (client), 0);
    } else if (cancel == 2) {
        HevTask *task = hev_task_new (16384);
        cancel_client = HEV_SOCKS5 (client);
        waiting_task = hev_task_self ();
        hev_task_run (task, cancel_wait, NULL);
    }
    errno = EACCES;
    assert (hev_socks5_client_handshake (HEV_SOCKS5_CLIENT (client), 0) < 0);
    if (cancel) {
        assert (!HEV_SOCKS5 (client)->timed_out);
        expect_silent_failure ();
    } else {
        char code[32];
        snprintf (code, sizeof (code), "code=%d", ETIMEDOUT);
        expect_log ("target=[203.0.113.9]:443", "reason=timeout");
        assert (strstr (log_text, code));
        assert (!strstr (log_text, strerror (EACCES)));
    }
    hev_object_unref (HEV_OBJECT (client));
    close (fd[1]);
#ifndef CORE_LEGACY_UDP
    hev_socks5_set_tcp_timeout (300000);
#endif
}

static void
helper_cases (void)
{
    HevSocks5ClientTCP *client;
    HevSocks5ClientUDP *udp;
    char target[512];
    begin_log ();
    client = new_client (0);
    errno = EACCES;
    assert (hev_socks5_client_handshake (HEV_SOCKS5_CLIENT (client), 0) < 0);
    hev_socks5_log_failure (HEV_SOCKS5 (client), "duplicate", "duplicate", 0);
    expect_log ("target=[203.0.113.9]:443", "operation=write-auth-methods");
    assert (strstr (log_text, strerror (EBADF)));
    hev_object_unref (HEV_OBJECT (client));

    begin_log ();
    udp = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_UDP);
    hev_socks5_set_diagnostic_target (HEV_SOCKS5 (udp), NULL);
    hev_socks5_log_failure (HEV_SOCKS5 (udp), "udp-connect", "explicit reason",
                            -3);
    expect_log ("target=udp-association", "reason=explicit reason code=-3");
    assert (!strstr (log_text, "0:0"));
    hev_object_unref (HEV_OBJECT (udp));

    begin_log ();
    client = new_client (0);
    memset (target, 'a', sizeof (target));
    target[sizeof (target) - 1] = 0;
    hev_socks5_set_diagnostic_target (HEV_SOCKS5 (client), target);
    hev_socks5_log_failure (HEV_SOCKS5 (client), "test", "bounded target", 0);
    expect_log ("target=aaaa", "operation=test reason=bounded target");
    assert (strstr (log_text, " operation=") - strstr (log_text, "target=") ==
            278);
    hev_object_unref (HEV_OBJECT (client));
}

static int
refuse_bind (HevSocks5 *self, int fd, const struct sockaddr *addr)
{
    (void)self;
    (void)fd;
    (void)addr;
    errno = EADDRNOTAVAIL;
    return -1;
}

static void
udp_bind_failure (void)
{
    static const unsigned char reply[] = {
        5, 0, 5, 0, 0, 1, 127, 0, 0, 1, 0, 53
    };
    HevSocks5ClientUDP *client;
    HevSocks5ClientUDPClass klass;
    int fd[2];
    begin_log ();
    client = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_UDP);
    memcpy (&klass, HEV_OBJECT_GET_CLASS (client), sizeof (klass));
    HEV_SOCKS5_CLASS (&klass)->binder = refuse_bind;
    HEV_OBJECT (client)->klass = HEV_OBJECT_CLASS (&klass);
    hev_socks5_set_addr_family (HEV_SOCKS5 (client),
                                HEV_SOCKS5_ADDR_FAMILY_IPV4);
    hev_socks5_set_diagnostic_target (HEV_SOCKS5 (client), "[203.0.113.10]:53");
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, fd));
    assert (!hev_task_add_fd (hev_task_self (), fd[0], POLLIN | POLLOUT));
    HEV_SOCKS5 (client)->fd = fd[0];
    assert (write (fd[1], reply, sizeof (reply)) == sizeof (reply));
    assert (hev_socks5_client_handshake (HEV_SOCKS5_CLIENT (client), 0) < 0);
    expect_log ("target=[203.0.113.10]:53", "operation=udp-bind");
    assert (strstr (log_text, strerror (EADDRNOTAVAIL)));
    hev_object_unref (HEV_OBJECT (client));
    close (fd[1]);
}

static int
udp_send (HevSocks5ClientUDP *client, HevSocks5Addr *addr)
{
#ifdef CORE_LEGACY_UDP
    return hev_socks5_udp_sendto (HEV_SOCKS5_UDP (client), "x", 1, addr);
#else
    HevSocks5UDPMsg msg = { .addr = addr, .buf = "x", .len = 1 };
    return hev_socks5_udp_sendmmsg (HEV_SOCKS5_UDP (client), &msg, 1);
#endif
}

static int
udp_receive (HevSocks5ClientUDP *client)
{
    char buf[1500];
#ifdef CORE_LEGACY_UDP
    HevSocks5Addr addr;
    return hev_socks5_udp_recvfrom (HEV_SOCKS5_UDP (client), buf, sizeof (buf),
                                    &addr);
#else
    HevSocks5UDPMsg msg = { .buf = buf, .len = sizeof (buf) };
    return hev_socks5_udp_recvmmsg (HEV_SOCKS5_UDP (client), &msg, 1, 0);
#endif
}

static void
udp_io_cases (void)
{
    HevSocks5ClientUDP *client;
    HevSocks5Addr invalid_addr = { .atype = 99 };
    int fd[2], control[2];
    const unsigned char invalid[] = { 0, 0, 0, 99, 0 };
    begin_log ();
    client = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_UDP);
    assert (udp_send (client, &invalid_addr) < 0);
#ifdef CORE_LEGACY_UDP
    assert (errno == EINVAL);
    expect_silent_failure ();
#else
    expect_log ("target=udp-association", "reason=invalid UDP address");
#endif
    hev_object_unref (HEV_OBJECT (client));

    begin_log ();
    client = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_UDP);
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_DGRAM, 0, fd));
    client->fd = fd[0];
    HEV_SOCKS5 (client)->udp_associated = 1;
    assert (write (fd[1], invalid, sizeof (invalid)) == sizeof (invalid));
    errno = EACCES;
    assert (udp_receive (client) < 0);
    expect_log ("target=udp-association", "reason=invalid UDP address code=99");
    hev_object_unref (HEV_OBJECT (client));
    close (fd[1]);

    begin_log ();
    client = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_UDP);
    errno = EACCES;
    assert (udp_receive (client) < 0);
    expect_log ("target=udp-association", "operation=udp-read");
    assert (strstr (log_text, strerror (EBADF)));
    hev_object_unref (HEV_OBJECT (client));

    begin_log ();
    client = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_UDP);
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_DGRAM, 0, fd));
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, control));
    client->fd = fd[0];
    HEV_SOCKS5 (client)->fd = control[0];
    assert (!hev_task_add_fd (hev_task_self (), fd[0], POLLIN));
    close (control[1]);
    errno = EACCES;
    assert (udp_receive (client) < 0);
    expect_log ("target=udp-association",
                "operation=udp-control reason=unexpected EOF code=0");
    assert (!strstr (log_text, "reason=timeout"));
    hev_object_unref (HEV_OBJECT (client));
    close (fd[1]);
}

static void
successful_handshake (int ipv6, int pipeline)
{
    static const unsigned char reply[] = { 5, 2,   1, 0, 5, 0, 0,
                                           1, 127, 0, 0, 1, 0, 1 };
    HevSocks5ClientTCP *client;
    int fd[2];
    begin_log ();
    client = new_client (ipv6);
    hev_socks5_client_set_auth (HEV_SOCKS5_CLIENT (client), "private-user",
                                "private-password");
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, fd));
    HEV_SOCKS5 (client)->fd = fd[0];
    assert (write (fd[1], reply, sizeof (reply)) == sizeof (reply));
    assert (
        !hev_socks5_client_handshake (HEV_SOCKS5_CLIENT (client), pipeline));
    assert (!HEV_SOCKS5 (client)->failure_logged);
    hev_socks5_log_failure (HEV_SOCKS5 (client), "tcp-read",
                            "post-handshake failure", 0);
    expect_log (ipv6 ? "target=[2001:db8::1]:443" : "target=[203.0.113.9]:443",
                "reason=post-handshake failure");
    hev_object_unref (HEV_OBJECT (client));
    close (fd[1]);
}

static void
successful_udp (void)
{
    HevSocks5ClientUDP *client;
    HevSocks5Addr addr;
    unsigned char ipv4[4] = { 203, 0, 113, 10 };
    char packet[1500];
    int fd[2], i;
    ssize_t len;
    begin_log ();
    client = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_UDP);
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_DGRAM, 0, fd));
    client->fd = fd[0];
    HEV_SOCKS5 (client)->udp_associated = 1;
    hev_socks5_addr_from_ipv4 (&addr, ipv4, htons (53));
    for (i = 0; i < 20; i++) {
        assert (udp_send (client, &addr) > 0);
        len = read (fd[1], packet, sizeof (packet));
        assert (len == 11);
        assert (write (fd[1], packet, len) == len);
        assert (udp_receive (client) > 0);
    }
    expect_silent_failure ();
    assert (!strstr (log_text, "send") && !strstr (log_text, "read"));
    hev_object_unref (HEV_OBJECT (client));
    close (fd[1]);
}

static void
tcp_pair (int fd[2])
{
    struct sockaddr_in addr = { 0 };
    socklen_t len = sizeof (addr);
    int listener = socket (AF_INET, SOCK_STREAM, 0);
    int nonblock = 1;
    assert (listener >= 0);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    assert (!bind (listener, (struct sockaddr *)&addr, sizeof (addr)));
    assert (!getsockname (listener, (struct sockaddr *)&addr, &len));
    assert (!listen (listener, 1));
    fd[0] = socket (AF_INET, SOCK_STREAM, 0);
    assert (fd[0] >= 0);
    assert (!connect (fd[0], (struct sockaddr *)&addr, sizeof (addr)));
    fd[1] = accept (listener, NULL, NULL);
    assert (fd[1] >= 0);
    close (listener);
    assert (!ioctl (fd[0], FIONBIO, &nonblock));
}

static void
reset_peer (void *data)
{
    int fd = *(int *)data;
    struct linger reset = { 1, 0 };
    hev_task_sleep (10);
    assert (!setsockopt (fd, SOL_SOCKET, SO_LINGER, &reset, sizeof (reset)));
    close (fd);
}

static void
partial_reset (int stage)
{
    static const unsigned char replies[][7] = {
        { 5 },
        { 5, 2, 1 },
        { 5, 0, 5 },
        { 5, 0, 5, 0, 0, 1, 127 },
    };
    static const int sizes[] = { 1, 3, 3, 7 };
    static const char *operations[] = { "read-auth-method", "read-auth-creds",
                                        "read-response",
                                        "read-response-address" };
    HevSocks5ClientTCP *client;
    HevTask *task;
    int fd[2];
    begin_log ();
    client = new_client (0);
    tcp_pair (fd);
    HEV_SOCKS5 (client)->fd = fd[0];
    hev_socks5_client_set_auth (HEV_SOCKS5_CLIENT (client), "private-user",
                                "private-password");
    assert (!hev_task_add_fd (hev_task_self (), fd[0], POLLIN | POLLOUT));
    assert (write (fd[1], replies[stage], sizes[stage]) == sizes[stage]);
    task = hev_task_new (16384);
    hev_task_run (task, reset_peer, &fd[1]);
    assert (hev_socks5_client_handshake (HEV_SOCKS5_CLIENT (client), 0) < 0);
    expect_log ("target=[203.0.113.9]:443", strerror (ECONNRESET));
    assert (strstr (log_text, operations[stage]));
    assert (!strstr (log_text, "unexpected EOF"));
    hev_object_unref (HEV_OBJECT (client));
}

static void
core_tcp_splice_case (int finish)
{
    HevSocks5ClientTCP *client;
    int proxy[2], local[2];
    begin_log ();
    client = new_client (0);
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, proxy));
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, local));
    HEV_SOCKS5 (client)->fd = proxy[0];
    hev_socks5_set_timeout (HEV_SOCKS5 (client), 15);
    assert (!hev_task_add_fd (hev_task_self (), proxy[0], POLLIN | POLLOUT));
    if (finish == 1) {
        shutdown (proxy[1], SHUT_WR);
        shutdown (local[1], SHUT_WR);
    } else if (finish == 2) {
        HevTask *task = hev_task_new (16384);
        cancel_client = HEV_SOCKS5 (client);
        waiting_task = hev_task_self ();
        hev_task_run (task, cancel_wait, NULL);
    }
    assert (!hev_socks5_tcp_splice (HEV_SOCKS5_TCP (client), local[0]));
    if (finish)
        expect_silent_failure ();
    else
        expect_log ("target=[203.0.113.9]:443",
                    "operation=tcp-relay reason=timeout");
    hev_object_unref (HEV_OBJECT (client));
    hev_task_del_fd (hev_task_self (), local[0]);
    close (local[0]);
    close (local[1]);
    close (proxy[1]);
}

static void
empty_udp (void)
{
    HevSocks5ClientUDP *client;
    int fd[2], control[2];
    begin_log ();
    client = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_UDP);
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_DGRAM, 0, fd));
    client->fd = fd[0];
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, control));
    HEV_SOCKS5 (client)->fd = control[0];
    HEV_SOCKS5 (client)->udp_associated = 1;
    assert (write (fd[1], "", 0) == 0);
    udp_receive (client);
#ifdef CORE_LEGACY_UDP
    expect_log ("target=udp-association", "reason=invalid UDP length code=0");
    assert (!strstr (log_text, "unexpected EOF"));
#else
    assert (!HEV_SOCKS5 (client)->failure_logged);
    shutdown (control[1], SHUT_WR);
    assert (udp_receive (client) < 0);
    expect_log ("target=udp-association",
                "operation=udp-control reason=unexpected EOF code=0");
#endif
    hev_object_unref (HEV_OBJECT (client));
    close (fd[1]);
    close (control[1]);
}

static void
core_udp_splice_case (int cancel)
{
    HevSocks5ClientUDP *client;
    int fd[2], control[2], local[2];
    begin_log ();
    client = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_UDP);
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_DGRAM, 0, fd));
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, control));
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_DGRAM, 0, local));
    client->fd = fd[0];
    HEV_SOCKS5 (client)->fd = control[0];
    HEV_SOCKS5 (client)->udp_associated = 1;
    hev_socks5_set_timeout (HEV_SOCKS5 (client), 15);
    if (cancel)
        hev_socks5_set_timeout (HEV_SOCKS5 (client), 0);
    assert (!hev_socks5_udp_splice (HEV_SOCKS5_UDP (client), local[0]));
    if (cancel)
        expect_silent_failure ();
    else
        expect_log ("target=udp-association",
                    "operation=udp-relay reason=timeout");
    hev_object_unref (HEV_OBJECT (client));
    hev_task_del_fd (hev_task_self (), local[0]);
    close (local[0]);
    close (local[1]);
    close (fd[1]);
    close (control[1]);
}

#ifdef CORE_LEGACY_UDP
static void
recoverable_udp_send (void)
{
    HevSocks5ClientUDP *client;
    HevSocks5Addr addr;
    unsigned char ip[4] = { 203, 0, 113, 9 };
    char *oversized = calloc (1, 70000);
    int fd[2], control[2];
    begin_log ();
    client = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_UDP);
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_DGRAM, 0, fd));
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, control));
    client->fd = fd[0];
    HEV_SOCKS5 (client)->fd = control[0];
    hev_socks5_addr_from_ipv4 (&addr, ip, htons (53));
    assert (hev_socks5_udp_sendto (HEV_SOCKS5_UDP (client), oversized, 70000,
                                   &addr) == -1);
    assert (errno == EMSGSIZE);
    assert (!HEV_SOCKS5 (client)->failure_logged);
    assert (udp_send (client, &addr) > 0);
    close (control[1]);
    assert (udp_receive (client) < 0);
    expect_log ("target=udp-association",
                "operation=udp-control reason=unexpected EOF code=0");
    hev_object_unref (HEV_OBJECT (client));
    close (fd[1]);
    free (oversized);
}
#else
static void
successful_udp_tcp (int type)
{
    HevSocks5ClientUDP *client;
    HevSocks5Addr addr;
    HevSocks5UDPMsg msg;
    unsigned char ip[16] = { 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0,
                             0, 0, 0, 0, 0, 0, 0, 1 };
    unsigned char packet[32];
    char buf[1500];
    int fd[2], length;

    begin_log ();
    client = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_TCP);
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, fd));
    HEV_SOCKS5 (client)->fd = fd[0];
    if (type == 0)
        hev_socks5_addr_from_ipv4 (&addr, ip, htons (53));
    else if (type == 1)
        hev_socks5_addr_from_ipv6 (&addr, ip, htons (53));
    else
        hev_socks5_addr_from_name (&addr, "example.org", htons (53));
    msg.addr = &addr;
    msg.buf = "x";
    msg.len = 1;
    assert (hev_socks5_udp_sendmmsg (HEV_SOCKS5_UDP (client), &msg, 1) == 1);
    length = read (fd[1], packet, sizeof (packet));
    assert (length > 0);
    assert (write (fd[1], packet, length) == length);
    msg.addr = NULL;
    msg.buf = buf;
    msg.len = sizeof (buf);
    assert (hev_socks5_udp_recvmmsg (HEV_SOCKS5_UDP (client), &msg, 1, 0) == 1);
    assert (msg.len == 1 && *(char *)msg.buf == 'x');
    assert (!memcmp (msg.addr, &addr, hev_socks5_addr_len (&addr)));
    expect_silent_failure ();
    hev_object_unref (HEV_OBJECT (client));
    close (fd[1]);
}

static void
truncated_udp_tcp (int payload, int end)
{
    static const unsigned char packet[] = {
        0, 1, 10, 1, 127, 0, 0, 1, 0, 53, 42
    };
    HevSocks5ClientUDP *client;
    HevSocks5UDPMsg msg;
    HevTask *task;
    char buf[1500];
    int fd[2], res;
    size_t length = payload ? 6 : end == 2 ? 2 : 1;

    begin_log ();
    client = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_TCP);
    if (end == 1)
        tcp_pair (fd);
    else
        assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, fd));
    HEV_SOCKS5 (client)->fd = fd[0];
    assert (!hev_task_add_fd (hev_task_self (), fd[0], POLLIN | POLLOUT));
    assert (write (fd[1], packet, length) == (ssize_t)length);
    if (end == 1) {
        task = hev_task_new (16384);
        hev_task_run (task, reset_peer, &fd[1]);
    } else if (end == 2) {
        hev_socks5_set_timeout (HEV_SOCKS5 (client), 15);
    } else if (end == 3) {
        task = hev_task_new (16384);
        cancel_client = HEV_SOCKS5 (client);
        waiting_task = hev_task_self ();
        hev_task_run (task, cancel_wait, NULL);
    } else {
        shutdown (fd[1], SHUT_WR);
    }
    msg.addr = NULL;
    msg.buf = buf;
    msg.len = sizeof (buf);
    errno = EACCES;
    res = hev_socks5_udp_recvmmsg (HEV_SOCKS5_UDP (client), &msg, 1, 0);
    assert (res < 0);
    assert (res != -1 || errno != EAGAIN);
    if (end == 3) {
        assert (!HEV_SOCKS5 (client)->timed_out);
        expect_silent_failure ();
    } else {
        expect_log ("target=udp-association",
                    end == 2 ? "operation=udp-read reason=timeout" :
                    end == 1 ? strerror (ECONNRESET) :
                               "operation=udp-read reason=unexpected EOF code=0");
        assert (!strstr (log_text, strerror (EACCES)));
    }
    if (end == 2)
        assert (HEV_SOCKS5 (client)->timed_out);
    hev_object_unref (HEV_OBJECT (client));
    if (end != 1)
        close (fd[1]);
}

static void
invalid_udp_tcp_header (int type)
{
    unsigned char packet[] = { 0, 1, 5, 4, 127, 42 };
    if (type == 0)
        packet[2] = 4;
    else if (type == 1)
        packet[3] = HEV_SOCKS5_ADDR_TYPE_IPV4;
    else if (type == 2)
        packet[3] = HEV_SOCKS5_ADDR_TYPE_NAME;
    HevSocks5ClientUDP *client;
    HevSocks5UDPMsg msg;
    char buf[1500];
    int fd[2], res;

    begin_log ();
    client = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_TCP);
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, fd));
    HEV_SOCKS5 (client)->fd = fd[0];
    assert (write (fd[1], packet, sizeof (packet)) == sizeof (packet));
    msg.addr = NULL;
    msg.buf = buf;
    msg.len = sizeof (buf);
    errno = EAGAIN;
    res = hev_socks5_udp_recvmmsg (HEV_SOCKS5_UDP (client), &msg, 1, 1);
    assert (res < 0 && (res != -1 || errno != EAGAIN));
    expect_log ("target=udp-association", "reason=invalid UDP header length");
    hev_object_unref (HEV_OBJECT (client));
    close (fd[1]);
}

static void
truncated_udp_tcp_second_frame (void)
{
    static const unsigned char packet[] = {
        0, 1, 10, 1, 127, 0, 0, 1, 0, 53, 42, 0
    };
    HevSocks5ClientUDP *client;
    HevSocks5UDPMsg batch[2];
    char buffers[2][1500];
    int fd[2], i;

    begin_log ();
    client = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_TCP);
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, fd));
    HEV_SOCKS5 (client)->fd = fd[0];
    assert (write (fd[1], packet, sizeof (packet)) == sizeof (packet));
    shutdown (fd[1], SHUT_WR);
    for (i = 0; i < 2; i++) {
        batch[i].addr = NULL;
        batch[i].buf = buffers[i];
        batch[i].len = sizeof (buffers[i]);
    }
    assert (hev_socks5_udp_recvmmsg (HEV_SOCKS5_UDP (client), batch, 2, 0) < 0);
    expect_log ("target=udp-association",
                "operation=udp-read reason=unexpected EOF code=0");
    hev_object_unref (HEV_OBJECT (client));
    close (fd[1]);
}

static void
partial_udp_tcp_write (void)
{
    HevSocks5ClientUDP *client;
    HevSocks5Addr addr;
    unsigned char ip[4] = { 203, 0, 113, 9 };
    HevSocks5UDPMsg batch[64];
    char payload[4096] = { 0 };
    int fd[2], size = 4096, i, res;

    begin_log ();
    client = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_TCP);
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, fd));
    HEV_SOCKS5 (client)->fd = fd[0];
    hev_socks5_set_timeout (HEV_SOCKS5 (client), 15);
    assert (!hev_task_add_fd (hev_task_self (), fd[0], POLLIN | POLLOUT));
    assert (!setsockopt (fd[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof (size)));
    assert (!setsockopt (fd[1], SOL_SOCKET, SO_RCVBUF, &size, sizeof (size)));
    hev_socks5_addr_from_ipv4 (&addr, ip, htons (53));
    for (i = 0; i < 64; i++) {
        batch[i].addr = &addr;
        batch[i].buf = payload;
        batch[i].len = sizeof (payload);
    }
    errno = EACCES;
    res = hev_socks5_udp_sendmmsg (HEV_SOCKS5_UDP (client), batch, 64);
    assert (res < 0);
    assert (HEV_SOCKS5 (client)->timed_out);
    expect_log ("target=udp-association", "operation=udp-write reason=timeout");
    assert (!strstr (log_text, strerror (EACCES)));
    hev_object_unref (HEV_OBJECT (client));
    close (fd[1]);
}

static void
partial_udp_batch (int receive)
{
    HevSocks5ClientUDP *client;
    HevSocks5Addr addr;
    unsigned char ip[4] = { 203, 0, 113, 9 };
    HevSocks5UDPMsg batch[64];
    char payload[4096] = { 0 };
    char buffers[64][1024];
    int fd[2], control[2], size = 4096, i, res;
    begin_log ();
    client = hev_socks5_client_udp_new (receive ? HEV_SOCKS5_TYPE_UDP_IN_TCP :
                                                  HEV_SOCKS5_TYPE_UDP_IN_UDP);
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, fd));
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, control));
    client->fd = fd[0];
    HEV_SOCKS5 (client)->fd = receive ? fd[0] : control[0];
    if (receive)
        client->fd = -1;
    HEV_SOCKS5 (client)->udp_associated = 1;
    hev_socks5_set_timeout (HEV_SOCKS5 (client), 15);
    assert (!hev_task_add_fd (hev_task_self (), fd[0], POLLIN | POLLOUT));
    assert (!setsockopt (fd[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof (size)));
    assert (!setsockopt (fd[1], SOL_SOCKET, SO_RCVBUF, &size, sizeof (size)));
    hev_socks5_addr_from_ipv4 (&addr, ip, htons (53));
    for (i = 0; i < 64; i++) {
        batch[i].addr = &addr;
        batch[i].buf = receive ? buffers[i] : payload;
        batch[i].len = receive ? sizeof (buffers[i]) : sizeof (payload);
    }
    if (receive) {
        static const unsigned char packet[] = { 0, 1, 10, 1,  127, 0,
                                                0, 1, 0,  53, 1 };
        assert (write (fd[1], packet, sizeof (packet)) == sizeof (packet));
        res = hev_socks5_udp_recvmmsg (HEV_SOCKS5_UDP (client), batch, 64, 0);
    } else {
        res = hev_socks5_udp_sendmmsg (HEV_SOCKS5_UDP (client), batch, 64);
    }
    assert (res > 0 && res < 64);
    if (receive) {
        shutdown (fd[1], SHUT_WR);
        assert (udp_receive (client) == 0);
        expect_log ("target=udp-association",
                    "operation=udp-read reason=unexpected EOF code=0");
        close (control[0]);
    } else {
        close (control[1]);
        control[1] = -1;
        assert (udp_receive (client) < 0);
        expect_log ("target=udp-association",
                    "operation=udp-control reason=unexpected EOF code=0");
    }
    assert (!strstr (log_text, "reason=timeout"));
    hev_object_unref (HEV_OBJECT (client));
    close (fd[1]);
    if (control[1] >= 0)
        close (control[1]);
}
#endif

static void
raw_udp_timeout (void)
{
    HevSocks5ClientUDP *client;
    int fd[2], control[2];
    begin_log ();
    client = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_UDP);
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_DGRAM, 0, fd));
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, control));
    client->fd = fd[0];
    HEV_SOCKS5 (client)->fd = control[0];
    HEV_SOCKS5 (client)->udp_associated = 1;
    hev_socks5_set_timeout (HEV_SOCKS5 (client), 15);
    assert (!hev_task_add_fd (hev_task_self (), fd[0], POLLIN));
    assert (udp_receive (client) < -1);
#ifdef CORE_LEGACY_UDP
    /* The caller still has to decide whether the other direction is alive. */
    expect_silent_failure ();
#else
    expect_log ("target=udp-association", "operation=udp-read reason=timeout");
#endif
    hev_object_unref (HEV_OBJECT (client));
    close (fd[1]);
    close (control[1]);
}

#ifdef CORE_LEGACY_UDP
static void
terminal_udp_send (void)
{
    HevSocks5ClientUDP *client;
    struct sockaddr_in6 addr = { 0 };
    socklen_t len = sizeof (addr);
    int control[2], local, sender;
    begin_log ();
    client = hev_socks5_client_udp_new (HEV_SOCKS5_TYPE_UDP_IN_UDP);
    assert (!hev_task_io_socket_socketpair (AF_UNIX, SOCK_STREAM, 0, control));
    HEV_SOCKS5 (client)->fd = control[0];
    local = hev_task_io_socket_socket (AF_INET6, SOCK_DGRAM, 0);
    sender = socket (AF_INET6, SOCK_DGRAM, 0);
    assert (local >= 0 && sender >= 0);
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_loopback;
    assert (!bind (local, (struct sockaddr *)&addr, sizeof (addr)));
    assert (!getsockname (local, (struct sockaddr *)&addr, &len));
    assert (sendto (sender, "x", 1, 0, (struct sockaddr *)&addr, len) == 1);
    assert (!hev_socks5_udp_splice (HEV_SOCKS5_UDP (client), local));
    expect_log ("target=udp-association", "operation=udp-write");
    assert (strstr (log_text, strerror (EBADF)));
    hev_object_unref (HEV_OBJECT (client));
    hev_task_del_fd (hev_task_self (), local);
    close (local);
    close (sender);
    close (control[1]);
}
#endif

static void
regressions (const char *selected)
{
    if (!strcmp (selected, "server-timeout")) {
        server_handshake_wait (0);
        server_handshake_wait (1);
        server_handshake_wait (2);
        connection_timeout (1);
    } else if (!strcmp (selected, "server-connect")) {
        connection_timeout (1);
    } else if (!strcmp (selected, "partial-reset")) {
        int i;
        for (i = 0; i < 4; i++)
            partial_reset (i);
    } else if (!strcmp (selected, "tcp-splice")) {
        core_tcp_splice_case (0);
        core_tcp_splice_case (1);
        core_tcp_splice_case (2);
    } else if (!strcmp (selected, "empty-udp")) {
        empty_udp ();
    } else if (!strcmp (selected, "udp-splice")) {
        core_udp_splice_case (0);
        core_udp_splice_case (1);
        raw_udp_timeout ();
#ifdef CORE_LEGACY_UDP
        terminal_udp_send ();
#endif
    } else if (!strcmp (selected, "udp-progress")) {
#ifdef CORE_LEGACY_UDP
        recoverable_udp_send ();
#else
        partial_udp_batch (0);
        partial_udp_batch (1);
#endif
    } else if (!strcmp (selected, "udp-tcp-truncated")) {
#ifndef CORE_LEGACY_UDP
        successful_udp_tcp (0);
        successful_udp_tcp (1);
        successful_udp_tcp (2);
        truncated_udp_tcp (0, 0);
        truncated_udp_tcp (0, 1);
        truncated_udp_tcp (0, 2);
        truncated_udp_tcp (0, 3);
        truncated_udp_tcp (1, 0);
        truncated_udp_tcp (1, 1);
        truncated_udp_tcp (1, 2);
        truncated_udp_tcp (1, 3);
        invalid_udp_tcp_header (0);
        invalid_udp_tcp_header (1);
        invalid_udp_tcp_header (2);
        invalid_udp_tcp_header (3);
        truncated_udp_tcp_second_frame ();
#endif
    } else if (!strcmp (selected, "udp-tcp-short-write")) {
#ifndef CORE_LEGACY_UDP
        partial_udp_tcp_write ();
#endif
    } else {
        assert (!"unknown regression");
    }
    printf ("PASS regression %s\n", selected);
}

static void
run (void *data)
{
    static const unsigned char refused[] = { 5, 0, 5, 5, 0, 1 };
    static const unsigned char denied[] = { 5, 255 };
    static const unsigned char auth[] = { 5, 2, 1, 1 };
    static const unsigned char short_header[] = { 5, 0, 5 };
    static const unsigned char short_addr[] = { 5, 0, 5, 0, 0, 4, 0 };
    static const unsigned char short_auth[] = { 5 };
    unsigned char response[] = { 5, 0, 5, 0, 0, 1 };
    const char *reasons[] = { "",
                              "general server failure",
                              "connection not allowed",
                              "network unreachable",
                              "host unreachable",
                              "connection refused",
                              "TTL expired",
                              "command not supported",
                              "address type not supported" };
    int i, pipeline;
    (void)data;
    if (getenv ("REGRESSION")) {
        regressions (getenv ("REGRESSION"));
        return;
    }
    for (pipeline = 0; pipeline <= 1; pipeline++) {
        handshake_case (refused, sizeof (refused),
                        "reason=connection refused code=5", 0, pipeline);
        handshake_case (refused, sizeof (refused), "operation=read-response", 1,
                        pipeline);
        handshake_case (denied, sizeof (denied),
                        "reason=authentication method rejected code=255", 0,
                        pipeline);
        handshake_case (auth, sizeof (auth),
                        "reason=authentication rejected code=1", 0, pipeline);
        handshake_case (short_header, sizeof (short_header),
                        "reason=unexpected EOF", 0, pipeline);
        handshake_case (short_addr, sizeof (short_addr),
                        "reason=unexpected EOF", 1, pipeline);
        handshake_case (short_auth, sizeof (short_auth),
                        "reason=unexpected EOF", 0, pipeline);
    }
    for (i = 1; i <= 8; i++) {
        response[3] = i;
        handshake_case (response, sizeof (response), reasons[i], 0, 0);
    }
    response[3] = 99;
    handshake_case (response, sizeof (response),
                    "reason=unknown SOCKS5 reply code=99", 0, 0);
    successful_handshake (0, 0);
    successful_handshake (1, 1);
    successful_udp ();
    connection_refusal ();
    connection_timeout (0);
    wait_case (0);
    wait_case (1);
    wait_case (2);
    helper_cases ();
    udp_bind_failure ();
    udp_io_cases ();
    regressions ("server-timeout");
    regressions ("partial-reset");
    regressions ("tcp-splice");
    regressions ("empty-udp");
    regressions ("udp-splice");
    regressions ("udp-progress");
    regressions ("udp-tcp-truncated");
    regressions ("udp-tcp-short-write");
    puts (
        "PASS core diagnostics: handshake, retained targets, errno, timeout, cancellation, deduplication, UDP");
}

int
main (int argc, char **argv)
{
    HevTask *task;
    assert (argc == 2);
    log_path = argv[1];
    assert (!hev_task_system_init ());
    task = hev_task_new (262144);
    assert (task);
    hev_task_run (task, run, NULL);
    hev_task_system_run ();
    hev_task_system_fini ();
    return 0;
}
