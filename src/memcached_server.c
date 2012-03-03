/* libeventmc - Memcached client bindings for libevent.
 * Copyright (C) 2010 Admeld Inc, Milosz Tanski <mtanski@admeld.com>
 *
 * The source code for the libmeldmc library is licensed under the MIT license or
 * at your option under the GPL version 2 license. The contents of the both
 * licenses are contained within the libevemtmc distribution in COPYING.txt file.
 *
 */

/* libc */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
/* net */
#include <arpa/inet.h>
/* libevent */
#include <event-config.h>
#include <event.h>
#include <evutil.h>
/* libeventmc */
#include "memcached_server.h"
#include "util.h"


#define MEMCACHED_MAGIC_REQ 0x80
#define MEMCACHED_MAGIC_RES 0x81


struct header_raw {
  uint8_t     magic;
  uint8_t     opcode;
  uint16_t    key_len;
  uint8_t     extra_len;
  uint8_t     data_type;
  uint16_t    status;         /* in the case of request this is __reserved__ */
  uint32_t    total_len;
  uint32_t    opaque;
  uint64_t    cas;
} __attribute__((packed))__;


struct memcached_server {
  struct event           *event_base;

  int                     fd;
  struct bufferevent     *buffer;

  memcached_cb_result     cb_result;
  memcached_cb_disconn    cb_disconn;

  void                   *baton;

  struct dgram           *current_command;
};


static inline void run_callback(struct memcached_server *server, struct evbuffer *input)
{
  struct header_raw *hdr = (struct header_raw *) EVBUFFER_DATA(input);
  char              *raw_data = (char *) EVBUFFER_DATA(input) + sizeof(struct header_raw); 

  uint16_t key_len   = ntohs(hdr->key_len);
  uint8_t  extra_len = hdr->extra_len;
  uint32_t total_len = ntohl(hdr->total_len);

  struct memcached_msg in_msg = {
    .opcode     = hdr->opcode,
    .status     = ntohs(hdr->status),
    .cas        = hdr->cas,
    .opaque     = hdr->opaque,
    .key        = (char *) raw_data + extra_len,
    .key_len    = key_len,
    .extra      = (void *) raw_data,
    .extra_len  = extra_len,
    .data       = (char *) raw_data + extra_len + key_len,
    .data_len   = total_len - extra_len - key_len,
  };

  if (server->cb_result != NULL)
    server->cb_result(server, &in_msg, server->baton);
}


static void cb_bufferevent_read(struct bufferevent *bufferevent, void *baton)
{
  struct memcached_server *server = (struct memcached_server *) baton;
  struct evbuffer         *input = EVBUFFER_INPUT(bufferevent);
  struct header_raw       *hdr;
  size_t                   response_len;

/* A loop in case we have more data pending */
next_msg:
  hdr = (struct header_raw *) EVBUFFER_DATA(input);
  response_len = sizeof(struct header_raw) + ntohl(hdr->total_len);

  if (EVBUFFER_LENGTH(input) < response_len) {
    /* If this response comes with extra data, set the water mark and wait till we have the header and data. */
    bufferevent_setwatermark(bufferevent, EV_READ, response_len, 0);
    return;
  }

  run_callback(server, input);

  /* Get rid of the last parsed message. */
  evbuffer_drain(bufferevent->input, response_len);

  /* Check if we (possibly) have another whole message in the buffer */
  if (EVBUFFER_LENGTH(input) >= sizeof(struct header_raw))
    goto next_msg;

  /* Wait for the next header to come in over the wire. */
  bufferevent_setwatermark(bufferevent, EV_READ, sizeof(struct header_raw), 0);
}



static void quit_cleanup(struct memcached_server *server)
{
  if (server == NULL)
    return;

  if (server->buffer != NULL) {
    bufferevent_free(server->buffer);
    server->buffer = NULL;
  }

  if (server->fd != -1)
    close(server->fd);

  server->fd = -1;
}

static void cb_bufferevent_error(struct bufferevent *bufev, short what, void *baton)
{
  struct memcached_server *server = (struct memcached_server *) baton;

  /* Deal with command timeout */
  if ((what & EVBUFFER_TIMEOUT)) {
    /* TODO: Do something here? */
    return;
  }

  /* Run the callback (if there is one). */
  if (server->cb_disconn != NULL)
    server->cb_disconn(server, server->baton);

  quit_cleanup(server);
}

static int build_socket(struct sockaddr *addr, enum memcached_conn conn_type)
{
  int          type, fd = -1;
  socklen_t    addr_len;

  if (addr->sa_family == AF_INET) 
    addr_len = sizeof(struct sockaddr_in);
  else if (addr->sa_family == AF_INET6)
    addr_len = sizeof(struct sockaddr_in6);
  else {
    errno = EAFNOSUPPORT;
    goto fail;
  }

  /* Both tcp and text use tcp sockets. One is binary (tcp) the other is the old text protocol (text). */
  type = (conn_type == MEMCACHED_CONN_UDP) ? SOCK_DGRAM : SOCK_STREAM;

  if ((fd = socket(addr->sa_family, type, 0)) == -1)
    return -1;

  /* Mark the file descriptor as non blocking so we can have non-blocking reads/writes and connect() */
  if (evutil_make_socket_nonblocking(fd)== - 1)
    goto fail;

  /* Connect the socket. Do this even in the udp case to so we don't have to use sendto(). Otherwise we have to
   * overwrite libevents write handler to use sendto() */
  if (connect(fd, addr, addr_len) == -1) {
    if (errno != EINPROGRESS)
      goto fail;
  }

  return fd;

fail:
  close(fd);
  return -1;
}

struct memcached_server *memcached_init(struct event_base *event_base, struct sockaddr *addr,
                                        enum memcached_conn conn_type, memcached_cb_result cb_result,
                                        memcached_cb_disconn cb_disconn, void *cb_baton)
{
  struct memcached_server *server;

  /* Right now we're only implementing the tcp protocol. */
  if (conn_type != MEMCACHED_CONN_TCP) {
    errno = EAFNOSUPPORT;
    return NULL;
  }

  if ((server = calloc(1, sizeof(*server))) == NULL)
    return NULL;

  server->cb_result = cb_result;
  server->cb_disconn = cb_disconn;
  server->baton = cb_baton;

  if ((server->fd = build_socket(addr, conn_type)) == -1)
    goto fail;

  if ((server->buffer = bufferevent_new(server->fd, cb_bufferevent_read, NULL, cb_bufferevent_error,
      server))== NULL)
  {
    goto fail;
  }

/* Configure the buffer event */

  if (event_base != NULL) {
    if (bufferevent_base_set(event_base, server->buffer) == -1)
      goto fail;
  }

  /* Stop reading after we get the header */
  bufferevent_setwatermark(server->buffer, EV_READ, sizeof(struct header_raw), 0);

  if (bufferevent_enable(server->buffer, EV_READ|EV_WRITE) == -1)
    goto fail;

  return server;

/* Failed to intilize (the buffer event) */
fail:
  quit_cleanup(server);
  return NULL;
}

void memcached_free(struct memcached_server *server)
{
  /* Free the bufferevent and close the socket, if we didn't previously. */
  quit_cleanup(server);

  free(server);
}

int memcached_send(struct memcached_server *server, struct memcached_msg *msg, enum memcached_data_type data_type)
{
  struct header_raw  hdr;
  uint32_t           total_len = msg->extra_len + msg->key_len + msg->data_len;

  if (server->fd == -1) {
    errno = ENOLINK;
    return -1;
  }

  /* write out  he header */
  hdr.magic = MEMCACHED_MAGIC_REQ;
  hdr.opcode = msg->opcode;
  hdr.key_len = htons(msg->key_len);
  hdr.extra_len = msg->extra_len;
  hdr.data_type = data_type;
  hdr.status = htons(0);
  hdr.total_len = htonl(total_len);
  hdr.opaque = msg->opaque;
  hdr.cas = msg->cas;

  if (bufferevent_write(server->buffer, &hdr, sizeof(hdr)) == -1)
    return -1;

  /* add extra, key & data sections */
  if (bufferevent_write(server->buffer, msg->extra, msg->extra_len) == -1
   || bufferevent_write(server->buffer, msg->key, msg->key_len) == -1
   || bufferevent_write(server->buffer, msg->data, msg->data_len) == -1)
  {
    return -1;
  }

  return 0;
}
