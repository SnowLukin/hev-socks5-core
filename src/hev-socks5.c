/*
 ============================================================================
 Name        : hev-socks5.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2021 - 2023 hev
 Description : Socks5
 ============================================================================
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <hev-task.h>
#include <hev-task-io.h>
#include <hev-task-io-socket.h>
#include <hev-task-dns.h>
#include <hev-memory-allocator.h>

#include "hev-socks5-logger-priv.h"

#include "hev-socks5.h"

void
hev_socks5_set_diagnostic_target (HevSocks5 *self, const char *target)
{
    snprintf (self->diagnostic_target, sizeof (self->diagnostic_target), "%s",
              target ? target : "");
}

void
hev_socks5_log_failure (HevSocks5 *self, const char *operation,
                         const char *reason, int error_code)
{
    const char *target = self->diagnostic_target;
    int saved_errno = errno;

    if (self->failure_logged || self->timeout == 0)
        return;
    self->failure_logged = 1;

    if (!target[0]) {
        if (self->type == HEV_SOCKS5_TYPE_UDP_IN_TCP ||
            self->type == HEV_SOCKS5_TYPE_UDP_IN_UDP)
            target = "udp-association";
        else
            target = "unknown";
    }
    if (self->timed_out) {
        reason = "timeout";
        error_code = ETIMEDOUT;
    } else if (!reason) {
        reason = strerror (error_code);
    }

    LOG_I ("%p socks5 failure target=%s operation=%s reason=%s code=%d", self,
           target, operation, reason, error_code);
    errno = saved_errno;
}

int
hev_socks5_get_timeout (HevSocks5 *self)
{
    return self->timeout;
}

void
hev_socks5_set_timeout (HevSocks5 *self, int timeout)
{
    self->timeout = timeout;
}

HevSocks5AddrFamily
hev_socks5_get_addr_family (HevSocks5 *self)
{
    return self->addr_family;
}

void
hev_socks5_set_addr_family (HevSocks5 *self, HevSocks5AddrFamily family)
{
    self->addr_family = family;
}

static int
hev_socks5_bind (HevSocks5 *self, int sock, const struct sockaddr *dest)
{
    return 0;
}

int
hev_socks5_construct (HevSocks5 *self, HevSocks5Type type)
{
    int res;

    res = hev_object_construct (&self->base);
    if (res < 0)
        return res;

    LOG_D ("%p socks5 construct", self);

    HEV_OBJECT (self)->klass = HEV_SOCKS5_TYPE;

    self->fd = -1;
    self->timeout = -1;
    self->type = type;
    self->timed_out = 0;
    self->failure_logged = 0;
    self->diagnostic_target[0] = '\0';
    self->addr_family = HEV_SOCKS5_ADDR_FAMILY_UNSPEC;

    return 0;
}

static void
hev_socks5_destruct (HevObject *base)
{
    HevSocks5 *self = HEV_SOCKS5 (base);

    LOG_D ("%p socks5 destruct", self);

    if (self->fd >= 0) {
        hev_task_del_fd (hev_task_self (), self->fd);
        close (self->fd);
    }

    HEV_OBJECT_TYPE->destruct (base);
    hev_free (base);
}

HevObjectClass *
hev_socks5_class (void)
{
    static HevSocks5Class klass;
    HevSocks5Class *kptr = &klass;
    HevObjectClass *okptr = HEV_OBJECT_CLASS (kptr);

    if (!okptr->name) {
        memcpy (kptr, HEV_OBJECT_TYPE, sizeof (HevObjectClass));

        okptr->name = "HevSocks5";
        okptr->destruct = hev_socks5_destruct;

        kptr->binder = hev_socks5_bind;
    }

    return okptr;
}
