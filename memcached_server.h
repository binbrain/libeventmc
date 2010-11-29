/* libeventmc - Memcached client bindings for libevent.
 * Copyright (C) 2010 Admeld Inc, Milosz Tanski <mtanski@admeld.com>
 *
 * The source code for the libmeldmc library is licensed under the MIT license or
 * at your option under the GPL version 2 license. The contents of the both
 * licenses are contained within the libevemtmc distribution in COPYING.txt file.
 *
 */

#ifndef __EVENT_MEMCACHED_H__
#define __EVENT_MEMCACHED_H__

#include <stdint.h>
#include <sys/socket.h>

/* libevent */
struct event_base;

/* Opaque object for the rest of the api. */
struct memcached_server;

enum memcached_conn {
  MEMCACHED_CONN_TCP,
  MEMCACHED_CONN_UDP,
  MEMCACHED_CONN_TEXT,
};

enum memcached_cmd {
  MEMCACHED_CMD_GET        = 0x00,
  MEMCACHED_CMD_SET        = 0x01,
  MEMCACHED_CMD_ADD        = 0x02,
  MEMCACHED_CMD_REPLACE    = 0x03,
  MEMCACHED_CMD_DEL        = 0x04,
  MEMCACHED_CMD_INC        = 0x05,
  MEMCACHED_CMD_DEC        = 0x06,
  MEMCACHED_CMD_QUIT       = 0x07,
  MEMCACHED_CMD_FLUSH      = 0x08,
  MEMCACHED_CMD_GETK       = 0x0c,
};

enum memcached_result {
  /* non operational errors */
  MEMCACHED_RESULT_CANCELED   = -0x02,
  MEMCACHED_RESULT_CONN       = -0x01,
  /* result values */
  MEMCACHED_RESULT_SUCCESS    = 0x00,
  MEMCACHED_RESULT_NO_KEY     = 0x01,
  MEMCACHED_RESULT_EXISTS     = 0x02,
  MEMCACHED_RESULT_TOOBIG     = 0x03,
  MEMCACHED_RESULT_INVALID    = 0x04,
  MEMCACHED_RESULT_NOT_STORED = 0x05,
  MEMCACHED_RESULT_NOT_NUM    = 0x06,
  MEMCACHED_RESULT_CMD        = 0x81,
  MEMCACHED_RESULT_MEM        = 0x82,
};

enum memcached_data_type {
  MEMCACHED_DT_BYTES,
};

struct memcached_msg {
  enum memcached_cmd    opcode;
  enum memcached_result status;

  uint32_t  opaque;
  uint64_t  cas;

  const char  *key;
  size_t       key_len;

  const void  *extra;
  size_t       extra_len;

  const void  *data;
  size_t       data_len;
};

/* callbacks */
typedef void (*memcached_cb_disconn)(struct memcached_server *server, void *baton);
typedef void (*memcached_cb_result)(struct memcached_server *server, struct memcached_msg *in_msg, void *baton);

/* memached_init
 *
 * Connect to a single memcached instance. 
 *
 * @event - eventlib base event (can be NULL if using the global event)
 * @addr  - pointer to a strcut of type struct in_addr/in6_addr
 * @conn_type - type of protocol to use for this connection
 *
 *
 * @cb_con_disconn - disconnect callback
 * 
 */
struct memcached_server *memcached_init(struct event_base *event_base, struct sockaddr *addr, 
                                        enum memcached_conn conn_type, memcached_cb_result cb_result,
                                        memcached_cb_disconn cb_disconn, void *cb_baton);

void memcached_free(struct memcached_server *server);

int memcached_send(struct memcached_server *server, struct memcached_msg *in_msg, enum memcached_data_type data_type);


#endif /* __EVENT_MEMCACHED__ */
