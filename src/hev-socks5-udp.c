/*
 ============================================================================
 Name        : hev-socks5-udp.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2025 hev
 Description : Socks5 UDP
 ============================================================================
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>

#include "hev-socks5.h"
#include "hev-socks5-misc-priv.h"
#include "hev-socks5-logger-priv.h"

#include "hev-socks5-udp.h"

typedef enum _HevSocks5UDPAlive HevSocks5UDPAlive;
typedef struct _HevSocks5UDPSplice HevSocks5UDPSplice;

enum _HevSocks5UDPAlive
{
    HEV_SOCKS5_UDP_ALIVE_F = (1 << 0),
    HEV_SOCKS5_UDP_ALIVE_B = (1 << 1),
};

struct _HevSocks5UDPSplice
{
    HevSocks5UDP *udp;
    HevSocks5UDPAlive alive;
    int bind;
    int fd;
};

static int
task_io_yielder (HevTaskYieldType type, void *data)
{
    HevSocks5 *self = data;

    if (self->type == HEV_SOCKS5_TYPE_UDP_IN_UDP) {
        ssize_t res;
        char buf;

        res = recv (self->fd, &buf, sizeof (buf), 0);
        if ((res == 0) || ((res < 0) && (errno != EAGAIN))) {
            int error_code = errno;
            hev_socks5_log_failure (self, "udp-control",
                                    res < 0 ? NULL : "unexpected EOF",
                                    res < 0 ? error_code : 0);
            hev_socks5_set_timeout (self, 0);
            return -1;
        }
    }

    return hev_socks5_task_io_yielder (type, data);
}

static void
hev_socks5_udp_log_io_failure (HevSocks5UDP *self, const char *operation,
                               int result, int error_code)
{
    if (result == -1 && error_code != EAGAIN && error_code != EWOULDBLOCK)
        hev_socks5_log_failure (HEV_SOCKS5 (self), operation, NULL, error_code);
    else if (result == 0) {
        const char *reason = HEV_SOCKS5 (self)->type ==
                                     HEV_SOCKS5_TYPE_UDP_IN_UDP ?
                                 "invalid UDP length" :
                                 "unexpected EOF";
        hev_socks5_log_failure (HEV_SOCKS5 (self), operation, reason, 0);
    }
}

int
hev_socks5_udp_get_fd (HevSocks5UDP *self)
{
    HevSocks5UDPIface *iface;

    iface = HEV_OBJECT_GET_IFACE (self, HEV_SOCKS5_UDP_TYPE);
    return iface->get_fd (self);
}

int
hev_socks5_udp_sendto (HevSocks5UDP *self, const void *buf, size_t len,
                       const HevSocks5Addr *addr)
{
    HevSocks5UDPHdr udp;
    struct iovec iov[3];
    struct msghdr mh;
    int addrlen;
    int res;

    LOG_D ("%p socks5 udp sendto", self);

    addrlen = hev_socks5_addr_len (addr);
    if (addrlen <= 0) {
        if (HEV_SOCKS5 (self)->type == HEV_SOCKS5_TYPE_UDP_IN_TCP)
            hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-address",
                                    "invalid UDP address", addr->atype);
        errno = EINVAL;
        return -1;
    }

    switch (HEV_SOCKS5 (self)->type) {
    case HEV_SOCKS5_TYPE_UDP_IN_TCP:
        udp.datlen = htons (len);
        udp.hdrlen = 3 + addrlen;
        break;
    case HEV_SOCKS5_TYPE_UDP_IN_UDP:
        udp.datlen = 0;
        udp.hdrlen = 0;
        break;
    default:
        return -1;
    }

    memset (&mh, 0, sizeof (mh));
    mh.msg_iov = iov;
    mh.msg_iovlen = 3;

    iov[0].iov_base = &udp;
    iov[0].iov_len = 3;
    iov[1].iov_base = (void *)addr;
    iov[1].iov_len = addrlen;
    iov[2].iov_base = (void *)buf;
    iov[2].iov_len = len;

    HEV_SOCKS5 (self)->timed_out = 0;
    res = hev_task_io_socket_sendmsg (hev_socks5_udp_get_fd (self), &mh,
                                      MSG_WAITALL, task_io_yielder, self);
    if (HEV_SOCKS5 (self)->type == HEV_SOCKS5_TYPE_UDP_IN_TCP &&
        res != 3 + addrlen + len) {
        int error_code = errno;
        const char *reason = NULL;
        if (res >= 0 && (!error_code || error_code == EAGAIN ||
                         error_code == EWOULDBLOCK))
            reason = "incomplete write";
        hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-write", reason,
                                error_code);
        /* A retry could append a new header inside the unfinished frame. */
        hev_socks5_set_timeout (HEV_SOCKS5 (self), 0);
        return -1;
    }
    if (res > 0)
        HEV_SOCKS5 (self)->timed_out = 0;

    return res;
}

static int
hev_socks5_udp_read_exact (HevSocks5UDP *self, void *buf, size_t len,
                           size_t *received)
{
    size_t offset = 0;

    while (offset < len) {
        int res;
        int error_code;

        res = hev_task_io_socket_recv (hev_socks5_udp_get_fd (self),
                                       (char *)buf + offset, len - offset, 0,
                                       task_io_yielder, self);
        error_code = errno;
        if (res <= 0) {
            if (res != -2 || *received) {
                hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-read",
                                        res < 0 ? NULL : "unexpected EOF",
                                        res < 0 ? error_code : 0);
                /* Only an idle timeout before a frame can be retried. */
                hev_socks5_set_timeout (HEV_SOCKS5 (self), 0);
                return -1;
            }
            return res;
        }
        offset += res;
        *received += res;
    }
    return 0;
}

static int
hev_socks5_udp_recvfrom_tcp (HevSocks5UDP *self, void *buf, size_t len,
                             HevSocks5Addr *addr)
{
    HevSocks5UDPHdr udp;
    size_t received = 0;
    int addrlen;
    int res;

    LOG_D ("%p socks5 udp recvfrom tcp", self);

    res = hev_socks5_udp_read_exact (self, &udp, 5, &received);
    if (res < 0)
        return res;

    udp.datlen = ntohs (udp.datlen);
    addrlen = hev_socks5_addr_len (&udp.addr);
    if (addrlen <= 0 || udp.hdrlen != 3 + addrlen || udp.datlen > len) {
        hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-read",
                                "invalid UDP length", udp.datlen);
        hev_socks5_set_timeout (HEV_SOCKS5 (self), 0);
        return -1;
    }

    res = hev_socks5_udp_read_exact (self, &udp.addr.domain.addr,
                                     addrlen - 2, &received);
    if (res < 0)
        return res;
    res = hev_socks5_udp_read_exact (self, buf, udp.datlen, &received);
    if (res < 0)
        return res;

    memcpy (addr, &udp.addr, addrlen);
    return udp.datlen;
}

static int
hev_socks5_udp_recvfrom_udp (HevSocks5UDP *self, void *buf, size_t len,
                             HevSocks5Addr *addr)
{
    struct sockaddr *saddr = NULL;
    struct sockaddr_in6 taddr;
    HevSocks5UDPHdr *udp;
    uint8_t rbuf[1500];
    socklen_t alen = 0;
    ssize_t rlen;
    int addrlen;
    int doff;
    int res;
    int fd;

    LOG_D ("%p socks5 udp recvfrom udp", self);

    if (!HEV_SOCKS5 (self)->udp_associated) {
        saddr = (struct sockaddr *)&taddr;
        alen = sizeof (struct sockaddr_in6);
        HEV_SOCKS5 (self)->udp_associated = 1;
    }

    fd = hev_socks5_udp_get_fd (self);
    rlen = hev_task_io_socket_recvfrom (fd, rbuf, sizeof (rbuf), 0, saddr,
                                        &alen, task_io_yielder, self);
    if (rlen < 4) {
        if (rlen > 0)
            hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-read",
                                    "invalid UDP length", rlen);
        else
            hev_socks5_udp_log_io_failure (self, "udp-read", rlen, errno);
        return rlen > 0 ? -1 : rlen;
    }

    if (saddr) {
        res = connect (fd, saddr, alen);
        if (res < 0) {
            int error_code = errno;
            hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-connect", NULL,
                                    error_code);
            return -1;
        }
    }

    udp = (HevSocks5UDPHdr *)rbuf;
    if (udp->addr.atype == HEV_SOCKS5_ADDR_TYPE_NAME && rlen < 5) {
        hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-read",
                                "invalid UDP length", rlen);
        return -1;
    }
    addrlen = hev_socks5_addr_len (&udp->addr);
    if (addrlen <= 0) {
        hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-address",
                                "invalid UDP address", udp->addr.atype);
        return -1;
    }

    doff = 3 + addrlen;
    if (doff > rlen) {
        hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-read",
                                "invalid UDP length", rlen);
        return -1;
    }

    rlen -= doff;
    if (len < rlen)
        rlen = len;
    memcpy (buf, rbuf + doff, rlen);
    memcpy (addr, &udp->addr, addrlen);

    return rlen;
}

int
hev_socks5_udp_recvfrom (HevSocks5UDP *self, void *buf, size_t len,
                         HevSocks5Addr *addr)
{
    int res;

    HEV_SOCKS5 (self)->timed_out = 0;
    switch (HEV_SOCKS5 (self)->type) {
    case HEV_SOCKS5_TYPE_UDP_IN_TCP:
        res = hev_socks5_udp_recvfrom_tcp (self, buf, len, addr);
        break;
    case HEV_SOCKS5_TYPE_UDP_IN_UDP:
        res = hev_socks5_udp_recvfrom_udp (self, buf, len, addr);
        break;
    default:
        return -1;
    }

    return res;
}

static int
hev_socks5_udp_fwd_f (HevSocks5UDP *self, HevSocks5UDPSplice *splice)
{
    struct sockaddr_in6 addr;
    struct sockaddr *saddr;
    HevSocks5Addr taddr;
    uint8_t buf[1500];
    int addr_family;
    ssize_t res;
    int ret;

    LOG_D ("%p socks5 udp fwd f", self);

    res = hev_socks5_udp_recvfrom (self, buf, sizeof (buf), &taddr);
    if (res <= 0) {
        if (res < -1) {
            splice->alive &= ~HEV_SOCKS5_UDP_ALIVE_F;
            if (splice->alive && hev_socks5_get_timeout (HEV_SOCKS5 (self))) {
                HEV_SOCKS5 (self)->timed_out = 0;
                return 0;
            }
        }
        if (HEV_SOCKS5 (self)->timed_out)
            hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-relay", "timeout",
                                    0);
        if (HEV_SOCKS5 (self)->type == HEV_SOCKS5_TYPE_UDP_IN_TCP)
            hev_socks5_set_timeout (HEV_SOCKS5 (self), 0);
        LOG_D ("%p socks5 udp fwd f recv", self);
        return -1;
    }

    saddr = (struct sockaddr *)&addr;
    addr_family = hev_socks5_get_addr_family (HEV_SOCKS5 (self));
    ret = hev_socks5_addr_into_sockaddr6 (&taddr, &addr, &addr_family);
    if (ret < 0) {
        LOG_D ("%p socks5 udp to sockaddr", self);
        return -1;
    }

    if (!splice->bind) {
        HevSocks5Class *skptr = HEV_OBJECT_GET_CLASS (self);
        ret = skptr->binder (HEV_SOCKS5 (self), splice->fd, saddr);
        if (ret < 0) {
            LOG_E ("%p socks5 udp bind", self);
            return -1;
        }
        splice->bind = 1;
    }

    res = sendto (splice->fd, buf, res, 0, saddr, sizeof (addr));
    if (res <= 0) {
        if ((res < 0) && (errno == EAGAIN))
            return 0;
        LOG_D ("%p socks5 udp fwd f send", self);
        return -1;
    }

    splice->alive |= HEV_SOCKS5_UDP_ALIVE_F;

    return 0;
}

static int
hev_socks5_udp_fwd_b (HevSocks5UDP *self, HevSocks5UDPSplice *splice)
{
    struct sockaddr_in6 addr;
    socklen_t addrlen;
    uint8_t buf[1500];
    ssize_t res;
    int error_code;
    const char *operation = "udp-read";

    LOG_D ("%p socks5 udp fwd b", self);

    addrlen = sizeof (addr);
    res = hev_task_io_socket_recvfrom (splice->fd, buf, sizeof (buf), 0,
                                       (struct sockaddr *)&addr, &addrlen,
                                       task_io_yielder, self);
    error_code = errno;
    if (res > 0) {
        HevSocks5Addr taddr;
        hev_socks5_addr_from_sockaddr6 (&taddr, &addr);
        operation = "udp-write";
        res = hev_socks5_udp_sendto (self, buf, res, &taddr);
        error_code = errno;
    }
    if (res <= 0) {
        if (res < -1) {
            splice->alive &= ~HEV_SOCKS5_UDP_ALIVE_B;
            if (splice->alive && hev_socks5_get_timeout (HEV_SOCKS5 (self))) {
                HEV_SOCKS5 (self)->timed_out = 0;
                return 0;
            }
        }
        hev_socks5_udp_log_io_failure (self, operation, res, error_code);
        if (HEV_SOCKS5 (self)->timed_out)
            hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-relay", "timeout",
                                    0);
        if (HEV_SOCKS5 (self)->type == HEV_SOCKS5_TYPE_UDP_IN_TCP)
            hev_socks5_set_timeout (HEV_SOCKS5 (self), 0);
        LOG_D ("%p socks5 udp fwd b recv send", self);
        return -1;
    }

    splice->alive |= HEV_SOCKS5_UDP_ALIVE_B;

    return 0;
}

static void
splice_task_entry (void *data)
{
    HevSocks5UDPSplice *splice = data;
    HevSocks5UDP *self = splice->udp;
    HevTask *task = hev_task_self ();
    int fd;

    fd = hev_task_io_dup (hev_socks5_udp_get_fd (self));
    if (fd < 0)
        return;

    if (hev_task_add_fd (task, fd, POLLIN) < 0)
        hev_task_mod_fd (task, fd, POLLIN);

    for (;;) {
        if (hev_socks5_udp_fwd_f (self, splice) < 0)
            break;
    }

    splice->alive &= ~HEV_SOCKS5_UDP_ALIVE_F;
    hev_task_del_fd (task, fd);
    close (fd);
}

static int
hev_socks5_udp_splicer (HevSocks5UDP *self, int fd)
{
    HevTask *task = hev_task_self ();
    HevSocks5UDPSplice splice;
    int stack_size;
    int ufd;

    LOG_D ("%p socks5 udp splicer", self);

    splice.udp = self;
    splice.alive = HEV_SOCKS5_UDP_ALIVE_F | HEV_SOCKS5_UDP_ALIVE_B;
    splice.bind = 0;
    splice.fd = fd;

    if (hev_task_add_fd (task, fd, POLLIN) < 0)
        hev_task_mod_fd (task, fd, POLLIN);

    ufd = hev_socks5_udp_get_fd (self);
    if (hev_task_mod_fd (task, ufd, POLLOUT) < 0)
        hev_task_add_fd (task, ufd, POLLOUT);

    stack_size = hev_socks5_get_task_stack_size ();
    task = hev_task_new (stack_size);
    hev_task_ref (task);
    hev_task_run (task, splice_task_entry, &splice);

    for (;;) {
        if (hev_socks5_udp_fwd_b (self, &splice) < 0)
            break;
    }

    splice.alive &= ~HEV_SOCKS5_UDP_ALIVE_B;
    hev_task_join (task);
    hev_task_unref (task);

    return 0;
}

int
hev_socks5_udp_splice (HevSocks5UDP *self, int fd)
{
    HevSocks5UDPIface *iface;

    iface = HEV_OBJECT_GET_IFACE (self, HEV_SOCKS5_UDP_TYPE);
    return iface->splicer (self, fd);
}

void *
hev_socks5_udp_iface (void)
{
    static HevSocks5UDPIface type = {
        .splicer = hev_socks5_udp_splicer,
    };

    return &type;
}
