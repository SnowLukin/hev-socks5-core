/*
 ============================================================================
 Name        : hev-socks5-udp.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2025 hev
 Description : Socks5 UDP
 ============================================================================
 */

#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-memory-allocator.h>

#include "hev-socks5.h"
#include "hev-socks5-misc-priv.h"
#include "hev-socks5-logger-priv.h"

#include "hev-socks5-udp.h"

#define UDP_BUF_SIZE 1500

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
    if (result < 0 && HEV_SOCKS5 (self)->timed_out)
        hev_socks5_log_failure (HEV_SOCKS5 (self), operation, "timeout", 0);
    else if (result == -1 && error_code != EAGAIN && error_code != EWOULDBLOCK)
        hev_socks5_log_failure (HEV_SOCKS5 (self), operation, NULL, error_code);
    else if (result == 0) {
        const char *reason = HEV_SOCKS5 (self)->type ==
                                     HEV_SOCKS5_TYPE_UDP_IN_UDP ?
                                 "invalid UDP length" :
                                 "unexpected EOF";
        hev_socks5_log_failure (HEV_SOCKS5 (self), operation, reason, 0);
    }
}

static int
hev_socks5_udp_read_exact (HevSocks5UDP *self, int fd, void *buf, size_t len,
                           int flags, size_t *received)
{
    size_t offset = 0;

    while (offset < len) {
        int res = hev_task_io_socket_recv (fd, (char *)buf + offset,
                                           len - offset, flags, task_io_yielder,
                                           self);
        if (res <= 0) {
            *received = offset;
            return res;
        }
        offset += res;
        flags = 0;
    }

    *received = offset;
    return 1;
}

int
hev_socks5_udp_get_fd (HevSocks5UDP *self)
{
    HevSocks5UDPIface *iface;

    iface = HEV_OBJECT_GET_IFACE (self, HEV_SOCKS5_UDP_TYPE);
    return iface->get_fd (self);
}

static int
hev_socks5_udp_sendmmsg_tcp (HevSocks5UDP *self, HevSocks5UDPMsg *msgv,
                             unsigned int num)
{
    struct iovec iov[num * 3];
    HevSocks5UDPHdr udp[num];
    struct msghdr mh;
    size_t length = 0;
    int i, res;

    mh.msg_name = NULL;
    mh.msg_namelen = 0;
    mh.msg_control = NULL;
    mh.msg_controllen = 0;
    mh.msg_iov = iov;
    mh.msg_iovlen = num * 3;

    for (i = 0; i < num; i++) {
        int addrlen;

        addrlen = hev_socks5_addr_len (msgv[i].addr);
        if (addrlen <= 0) {
            hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-address",
                                    "invalid UDP address", msgv[i].addr->atype);
            return -1;
        }

        udp[i].datlen = htons (msgv[i].len);
        udp[i].hdrlen = 3 + addrlen;

        iov[i * 3].iov_base = &udp[i];
        iov[i * 3].iov_len = 3;
        iov[i * 3 + 1].iov_base = msgv[i].addr;
        iov[i * 3 + 1].iov_len = addrlen;
        iov[i * 3 + 2].iov_base = msgv[i].buf;
        iov[i * 3 + 2].iov_len = msgv[i].len;
        length += 3 + addrlen + msgv[i].len;
    }

    res = hev_task_io_socket_sendmsg (hev_socks5_udp_get_fd (self), &mh,
                                      MSG_WAITALL, task_io_yielder, self);
    if (res != length) {
        int error_code = errno;
        if (res <= 0)
            hev_socks5_udp_log_io_failure (self, "udp-write", res, error_code);
        else if (error_code && error_code != EAGAIN &&
                 error_code != EWOULDBLOCK)
            hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-write", NULL,
                                    error_code);
        else
            hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-write",
                                    "incomplete write", 0);
        return -1;
    }

    HEV_SOCKS5 (self)->timed_out = 0;
    return num;
}

#if defined(__linux__) && defined(UDP_SEGMENT)
static int udp_gso_max_size = -1;

static int
hev_socks5_udp_gso_probe (void)
{
    int size = 1024;
    int fd, res;

    /* Kernels without UDP GSO would send the coalesced datagrams as one. */
    fd = socket (AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return 0;
    res = setsockopt (fd, SOL_UDP, UDP_SEGMENT, &size, sizeof (size));
    close (fd);

    return (res == 0) ? 65535 : 0;
}

static int
hev_socks5_udp_sendmmsg_udp_gso (HevSocks5UDP *self, HevSocks5UDPMsg *msgv,
                                 unsigned int num, struct iovec *iov)
{
    char ctrl[num][CMSG_SPACE (sizeof (uint16_t))];
    struct mmsghdr mvec[num];
    unsigned int segs[num];
    int i, n, g, res;

    /*
     * Coalesce runs of equal sized datagrams (socks5 header included) into a
     * single UDP GSO send, the kernel splits them into separate datagrams.
     */
    for (i = 0, g = 0; i < num; g++) {
        size_t size = iov[i * 3 + 1].iov_len + 3 + msgv[i].len;
        size_t total = size;
        struct cmsghdr *cm;

        for (n = 1; (i + n) < num && n < 64 && (int)size <= udp_gso_max_size;
             n++) {
            size_t s = iov[(i + n) * 3 + 1].iov_len + 3 + msgv[i + n].len;
            if ((s != size) || ((total + s) > 65000))
                break;
            total += s;
        }

        mvec[g].msg_hdr.msg_name = NULL;
        mvec[g].msg_hdr.msg_namelen = 0;
        mvec[g].msg_hdr.msg_iov = &iov[i * 3];
        mvec[g].msg_hdr.msg_iovlen = n * 3;
        mvec[g].msg_hdr.msg_flags = 0;
        mvec[g].msg_hdr.msg_control = NULL;
        mvec[g].msg_hdr.msg_controllen = 0;
        if (n > 1) {
            mvec[g].msg_hdr.msg_control = ctrl[g];
            mvec[g].msg_hdr.msg_controllen = sizeof (ctrl[g]);
            cm = CMSG_FIRSTHDR (&mvec[g].msg_hdr);
            cm->cmsg_level = SOL_UDP;
            cm->cmsg_type = UDP_SEGMENT;
            cm->cmsg_len = CMSG_LEN (sizeof (uint16_t));
            *(uint16_t *)CMSG_DATA (cm) = size;
        }
        segs[g] = n;
        i += n;
    }

    res = hev_task_io_socket_sendmmsg (hev_socks5_udp_get_fd (self), mvec, g,
                                       MSG_WAITALL, task_io_yielder, self);
    if (res <= 0) {
        /* Segments larger than the path MTU are rejected, don't retry them. */
        if (((errno == EINVAL) || (errno == EMSGSIZE)) && (segs[0] > 1)) {
            size_t size = iov[1].iov_len + 3 + msgv[0].len;
            if ((int)size <= udp_gso_max_size)
                udp_gso_max_size = size - 1;
        }
        return res;
    }

    for (i = 0, n = 0; i < res; i++)
        n += segs[i];

    return n;
}
#endif /* __linux__ && UDP_SEGMENT */

static int
hev_socks5_udp_sendmmsg_udp (HevSocks5UDP *self, HevSocks5UDPMsg *msgv,
                             unsigned int num)
{
    struct iovec iov[num * 3];
    struct mmsghdr mvec[num];
    HevSocks5UDPHdr udp[num];
    int i, res;

    for (i = 0; i < num; i++) {
        int addrlen;

        addrlen = hev_socks5_addr_len (msgv[i].addr);
        if (addrlen <= 0) {
            hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-address",
                                    "invalid UDP address", msgv[i].addr->atype);
            return -1;
        }

        udp[i].datlen = 0;
        udp[i].hdrlen = 0;

        iov[i * 3].iov_base = &udp[i];
        iov[i * 3].iov_len = 3;
        iov[i * 3 + 1].iov_base = msgv[i].addr;
        iov[i * 3 + 1].iov_len = addrlen;
        iov[i * 3 + 2].iov_base = msgv[i].buf;
        iov[i * 3 + 2].iov_len = msgv[i].len;

        mvec[i].msg_hdr.msg_name = NULL;
        mvec[i].msg_hdr.msg_namelen = 0;
        mvec[i].msg_hdr.msg_control = NULL;
        mvec[i].msg_hdr.msg_controllen = 0;
        mvec[i].msg_hdr.msg_iov = &iov[i * 3];
        mvec[i].msg_hdr.msg_iovlen = 3;
    }

#if defined(__linux__) && defined(UDP_SEGMENT)
    if (udp_gso_max_size < 0)
        udp_gso_max_size = hev_socks5_udp_gso_probe ();

    if ((num > 1) && udp_gso_max_size) {
        res = hev_socks5_udp_sendmmsg_udp_gso (self, msgv, num, iov);
        if (res > 0) {
            HEV_SOCKS5 (self)->timed_out = 0;
            return res;
        }
        if ((errno != EINVAL) && (errno != EMSGSIZE)) {
            hev_socks5_udp_log_io_failure (self, "udp-write", res, errno);
            return res;
        }
    }
#endif /* __linux__ && UDP_SEGMENT */

    res = hev_task_io_socket_sendmmsg (hev_socks5_udp_get_fd (self), mvec, num,
                                       MSG_WAITALL, task_io_yielder, self);
    if (res <= 0)
        hev_socks5_udp_log_io_failure (self, "udp-write", res, errno);
    else
        HEV_SOCKS5 (self)->timed_out = 0;

    return res;
}

int
hev_socks5_udp_sendmmsg (HevSocks5UDP *self, HevSocks5UDPMsg *msgv,
                         unsigned int num)
{
    switch (HEV_SOCKS5 (self)->type) {
    case HEV_SOCKS5_TYPE_UDP_IN_TCP:
        return hev_socks5_udp_sendmmsg_tcp (self, msgv, num);
    case HEV_SOCKS5_TYPE_UDP_IN_UDP:
        return hev_socks5_udp_sendmmsg_udp (self, msgv, num);
    default:
        return -1;
    }
}

static int
hev_socks5_udp_recvmmsg_tcp (HevSocks5UDP *self, HevSocks5UDPMsg *msgv,
                             unsigned int num, int nonblock)
{
    int i, fd, rlen = 0;

    fd = hev_socks5_udp_get_fd (self);

    if (nonblock)
        nonblock = MSG_DONTWAIT;

    for (i = 0; i < num; i++) {
        HevSocks5UDPHdr udp;
        int addrlen;
        int res;
        size_t received;

        res = hev_socks5_udp_read_exact (self, fd, &udp, 5, nonblock,
                                          &received);
        if (res != 1) {
            if (!received && rlen > 0)
                break;
            if (res != -1 || errno != EAGAIN)
                hev_socks5_udp_log_io_failure (self, "udp-read", res, errno);
            return res < 0 ? res : received ? -2 : 0;
        }

        addrlen = hev_socks5_addr_len (&udp.addr);
        if (addrlen <= 0 || udp.hdrlen != 3 + addrlen) {
            hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-read",
                                    "invalid UDP header length", udp.hdrlen);
            errno = EINVAL;
            return -1;
        }

        udp.datlen = ntohs (udp.datlen);
        if (addrlen > msgv[i].len ||
            udp.datlen > (msgv[i].len - addrlen)) {
            hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-read",
                                    "invalid UDP length", udp.datlen);
            errno = EINVAL;
            return -1;
        }

        res = hev_socks5_udp_read_exact (self, fd, (char *)msgv[i].buf + 2,
                                          addrlen - 2 + udp.datlen, 0,
                                          &received);
        if (res != 1) {
            hev_socks5_udp_log_io_failure (self, "udp-read", res, errno);
            return res < 0 ? res : -2;
        }

        msgv[i].addr = msgv[i].buf;
        msgv[i].buf = (char *)msgv[i].buf + addrlen;
        msgv[i].len = udp.datlen;
        msgv[i].addr->atype = udp.addr.atype;
        msgv[i].addr->domain.len = udp.addr.domain.len;

        rlen++;
    }

    if (rlen > 0)
        HEV_SOCKS5 (self)->timed_out = 0;
    return rlen;
}

static int
hev_socks5_udp_recvmmsg_udp (HevSocks5UDP *self, HevSocks5UDPMsg *msgv,
                             unsigned int num, int nonblock)
{
    struct sockaddr_in6 taddr;
    struct mmsghdr mvec[num];
    struct iovec iov[num];
    int i, fd, res;

    fd = hev_socks5_udp_get_fd (self);

    if (nonblock)
        nonblock = MSG_DONTWAIT;

    for (i = 0; i < num; i++) {
        mvec[i].msg_hdr.msg_name = NULL;
        mvec[i].msg_hdr.msg_namelen = 0;
        mvec[i].msg_hdr.msg_control = NULL;
        mvec[i].msg_hdr.msg_controllen = 0;
        mvec[i].msg_hdr.msg_iov = &iov[i];
        mvec[i].msg_hdr.msg_iovlen = 1;

        iov[i].iov_base = msgv[i].buf;
        iov[i].iov_len = msgv[i].len;
    }

    if (!HEV_SOCKS5 (self)->udp_associated) {
        mvec[0].msg_hdr.msg_name = &taddr;
        mvec[0].msg_hdr.msg_namelen = sizeof (taddr);
    }

    res = hev_task_io_socket_recvmmsg (fd, mvec, num, nonblock, task_io_yielder,
                                       self);
    if (res <= 0) {
        if (res != -1 || errno != EAGAIN)
            hev_socks5_udp_log_io_failure (self, "udp-read", res, errno);
        return res;
    }

    HEV_SOCKS5 (self)->timed_out = 0;
    if (!HEV_SOCKS5 (self)->udp_associated) {
        struct sockaddr *saddr = mvec[0].msg_hdr.msg_name;
        socklen_t alen = mvec[0].msg_hdr.msg_namelen;
        if (connect (fd, saddr, alen) < 0) {
            int error_code = errno;
            hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-connect", NULL,
                                    error_code);
            return -1;
        }
        HEV_SOCKS5 (self)->udp_associated = 1;
    }

    for (i = 0; i < res; i++) {
        HevSocks5UDPHdr *udp = msgv[i].buf;
        int addrlen = hev_socks5_addr_len (&udp->addr);
        int doff;

        msgv[i].len = mvec[i].msg_len;
        if ((msgv[i].len < 4) || (mvec[i].msg_hdr.msg_flags & MSG_TRUNC)) {
            msgv[i].addr = NULL;
            msgv[i].len = 0;
            continue;
        }

        if (addrlen <= 0) {
            LOG_D ("%p socks5 udp addr", self);
            msgv[i].addr = NULL;
            msgv[i].len = 0;
            continue;
        }

        doff = 3 + addrlen;
        if (doff > msgv[i].len) {
            LOG_D ("%p socks5 udp data len", self);
            msgv[i].addr = NULL;
            msgv[i].len = 0;
            continue;
        }

        msgv[i].addr = &udp->addr;
        msgv[i].buf += doff;
        msgv[i].len -= doff;
    }

    return res;
}

int
hev_socks5_udp_recvmmsg (HevSocks5UDP *self, HevSocks5UDPMsg *msgv,
                         unsigned int num, int nonblock)
{
    switch (HEV_SOCKS5 (self)->type) {
    case HEV_SOCKS5_TYPE_UDP_IN_TCP:
        return hev_socks5_udp_recvmmsg_tcp (self, msgv, num, nonblock);
    case HEV_SOCKS5_TYPE_UDP_IN_UDP:
        return hev_socks5_udp_recvmmsg_udp (self, msgv, num, nonblock);
    default:
        return -1;
    }
}

static int
hev_socks5_udp_fwd_f (HevSocks5UDP *self, int fd, void *buf, unsigned int num,
                      int *bind)
{
    HevSocks5UDPMsg svec[num];
    int i, res;

    for (i = 0; i < num; i++) {
        svec[i].buf = buf + UDP_BUF_SIZE * i;
        svec[i].len = UDP_BUF_SIZE;
    }

    res = hev_socks5_udp_recvmmsg (self, svec, num, 1);
    if (res > 0) {
        struct sockaddr_in6 addr[res];
        struct mmsghdr dvec[res];
        struct iovec iov[res];
        int n, ret;

        for (i = 0, n = 0; i < res; i++) {
            int family;

            if (!svec[i].addr) {
                LOG_D ("%p socks5 udp invalid", self);
                continue;
            }

            memset (&addr[n], 0, sizeof (struct sockaddr_in6));
            family = hev_socks5_get_addr_family (HEV_SOCKS5 (self));
            ret = hev_socks5_addr_into_sockaddr6 (svec[i].addr, &addr[n],
                                                  &family);
            if (ret < 0) {
                LOG_D ("%p socks5 udp sockaddr", self);
                continue;
            }

            dvec[n].msg_hdr.msg_name = (struct sockaddr *)&addr[n];
            dvec[n].msg_hdr.msg_namelen = sizeof (struct sockaddr_in6);
            dvec[n].msg_hdr.msg_control = NULL;
            dvec[n].msg_hdr.msg_controllen = 0;
            dvec[n].msg_hdr.msg_iov = &iov[n];
            dvec[n].msg_hdr.msg_iovlen = 1;
            iov[n].iov_base = svec[i].buf;
            iov[n].iov_len = svec[i].len;
            n++;
        }

        if (n && !*bind) {
            HevSocks5Class *skptr = HEV_OBJECT_GET_CLASS (self);
            struct sockaddr *addr = dvec[0].msg_hdr.msg_name;
            ret = skptr->binder (HEV_SOCKS5 (self), fd, addr);
            if (ret < 0) {
                LOG_W ("%p socks5 udp bind", self);
                return -1;
            }
            *bind = 1;
        }

        for (i = 0; i < n; i += ret) {
            ret = hev_task_io_socket_sendmmsg (fd, &dvec[i], n - i, MSG_WAITALL,
                                               task_io_yielder, self);
            if (ret <= 0) {
                if (ret == -2)
                    return -1;
                LOG_D ("%p socks5 udp fwd f send", self);
                ret = 1;
            }
        }
    } else {
        if (res == -1 && errno == EAGAIN)
            return 0;
        LOG_D ("%p socks5 udp fwd f recv", self);
        return -1;
    }

    HEV_SOCKS5 (self)->timed_out = 0;
    return 1;
}

static int
hev_socks5_udp_fwd_b (HevSocks5UDP *self, int fd, struct mmsghdr *svec,
                      unsigned int num)
{
    int i, res;

    res = hev_task_io_socket_recvmmsg (fd, svec, num, MSG_DONTWAIT,
                                       task_io_yielder, self);
    if (res > 0) {
        HevSocks5UDPMsg dvec[res];
        char saddr[res][19];

        for (i = 0; i < res; i++) {
            dvec[i].buf = svec[i].msg_hdr.msg_iov->iov_base;
            dvec[i].len = svec[i].msg_len;
            dvec[i].addr = (HevSocks5Addr *)&saddr[i];
            hev_socks5_addr_from_sockaddr6 (dvec[i].addr,
                                            svec[i].msg_hdr.msg_name);
        }
        res = hev_socks5_udp_sendmmsg (self, dvec, res);
    }
    if (res <= 0) {
        if (res == -1 && errno == EAGAIN)
            return 0;
        LOG_D ("%p socks5 udp fwd b recv send", self);
        return -1;
    }

    HEV_SOCKS5 (self)->timed_out = 0;
    return 1;
}

static int
hev_socks5_udp_splicer (HevSocks5UDP *self, int fd_b)
{
    HevTask *task = hev_task_self ();
    int res_f = 1, res_b = 1;
    int bind = 0;
    void *buf;
    int fd_a;
    int num;

    LOG_D ("%p socks5 udp splicer", self);

    num = hev_socks5_get_udp_copy_buffer_nums ();
    buf = hev_malloc (UDP_BUF_SIZE * num * 2);
    if (!buf)
        return -1;

    fd_a = hev_socks5_udp_get_fd (self);
    if (hev_task_mod_fd (task, fd_a, POLLIN | POLLOUT) < 0)
        hev_task_add_fd (task, fd_a, POLLIN | POLLOUT);
    if (hev_task_add_fd (task, fd_b, POLLIN | POLLOUT) < 0)
        hev_task_mod_fd (task, fd_b, POLLIN | POLLOUT);

    {
        struct mmsghdr vec[num];
        struct sockaddr_in6 addr[num];
        struct iovec iov[num];
        int i;

        for (i = 0; i < num; i++) {
            vec[i].msg_hdr.msg_name = (struct sockaddr *)&addr[i];
            vec[i].msg_hdr.msg_namelen = sizeof (struct sockaddr_in6);
            vec[i].msg_hdr.msg_control = NULL;
            vec[i].msg_hdr.msg_controllen = 0;
            vec[i].msg_hdr.msg_iov = &iov[i];
            vec[i].msg_hdr.msg_iovlen = 1;
            iov[i].iov_base = buf + UDP_BUF_SIZE * (num + i);
            iov[i].iov_len = UDP_BUF_SIZE;
        }

        for (;;) {
            HevTaskYieldType type;

            if (res_f >= 0)
                res_f = hev_socks5_udp_fwd_f (self, fd_b, buf, num, &bind);
            if (res_b >= 0)
                res_b = hev_socks5_udp_fwd_b (self, fd_b, vec, num);

            if (res_f > 0 || res_b > 0)
                type = HEV_TASK_YIELD;
            else if ((res_f & res_b) == 0)
                type = HEV_TASK_WAITIO;
            else
                break;

            if (task_io_yielder (type, self))
                break;
        }
    }

    if (HEV_SOCKS5 (self)->timed_out)
        hev_socks5_log_failure (HEV_SOCKS5 (self), "udp-relay", "timeout", 0);
    hev_free (buf);

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
