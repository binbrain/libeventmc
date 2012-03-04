/* libeventmc - Memcached client bindings for libevent.
 * Copyright (C) 2010 Admeld Inc, Milosz Tanski <mtanski@admeld.com>
 *
 * The source code for the libmeldmc library is licensed under the MIT license or
 * at your option under the GPL version 2 license. The contents of the both
 * licenses are contained within the libevemtmc distribution in COPYING file.
 *
 */

/* libc */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
/* networking */
#include <netinet/in.h>
#include <sys/socket.h>
/* BSDisms */
#include "bsd_tree.h"
/* libevent */
#include <event-config.h>
#include <event.h>
/* libeventmc */
#include "memcached_server.h"
#include "memcached_api.h"
#include "util.h"

struct pending_cmd
{
  struct {
    /* We use the opaque fields in memcached to figure out matchup sent commands to responses (and callbacks) */
    uint32_t                  opaque;
    enum memcached_cmd        sent_command;

    const char    *key;
    size_t         key_len;
  } out_data;

  void                     *callback_data;

  union {
    memcached_cb_get        callback_get;
    memcached_cb_add        callback_add;     /* add/set/replace */
    void                   *callback_dummy;
  } callbacks;

  struct memcached_server  *server;

  RB_ENTRY(pending_cmd)     e_tree;
};

struct memcached_api
{
  /* All server have to be the same connection type */
  enum memcached_conn     conn_type;
  /* The libevent event_base object */
  struct event_base      *event_base;

  /* List of callbacks */
  memcached_hash_func     cb_func_hash;
  memcached_keytrans_func cb_func_keytrans;
  memcached_cb_unknown    cb_unknown_id;

  /* To keep track of which response is which. */
  uint32_t                sequence_id;

  int                     num_host;
  struct memcached_host  *host_list;

  void                   *user_data;

  /* Tree of pending commands */
  RB_HEAD(rb_cmds, pending_cmd) pending_cmd_list;
};

/* GCC seams to not have a __unused keyword, but it does have an attribute. */
#define __unused __attribute__((unused))
#define __inline inline

  /* Compare function for the cmd red-black tree entries. */
  static inline int cmp_cmd(struct pending_cmd *c1, struct pending_cmd *c2)
    { return (c1->out_data.opaque - c2->out_data.opaque); }

  /* Generate functions for manipulating the tree. */
  RB_GENERATE_STATIC(rb_cmds, pending_cmd, e_tree, cmp_cmd);

#undef __inline
#undef __unused

static inline struct pending_cmd *find_cmd(struct memcached_api *api, uint32_t opaque)
{
  struct pending_cmd search_cmd = { .out_data.opaque = opaque };

  return RB_FIND(rb_cmds, &api->pending_cmd_list, &search_cmd);
}

static inline void free_pending_cmd(struct memcached_api *api, struct pending_cmd * cmd)
{
  RB_REMOVE(rb_cmds, &api->pending_cmd_list, cmd);
  free((char *) cmd->out_data.key);
  free(cmd);
}

static void do_unknown_id_callback(struct memcached_api *api, const struct memcached_msg * restrict in_msg)
{
  /* If there's is no unknown command id callback defined then perform a fault here. */
  if (api->cb_unknown_id == NULL)
    CORE_ME("Got an unknown a response with an unknown id back.");

  api->cb_unknown_id(api, in_msg, api->user_data);
}

static void do_user_callback(struct memcached_api *api, const struct memcached_msg * restrict in_msg,
                             const struct pending_cmd *out_cmd)
{
  /* Run the callbacks */
  if (out_cmd->callbacks.callback_dummy == NULL)
    ; /* We don't care about the response */
  else if (in_msg->opcode == MEMCACHED_CMD_GET
        || in_msg->opcode == MEMCACHED_CMD_GETK)
  {
    out_cmd->callbacks.callback_get(api, in_msg->status, out_cmd->out_data.key, out_cmd->out_data.key_len, in_msg->data, 
                                    in_msg->data_len, in_msg->cas, api->user_data, out_cmd->callback_data);

  } else if (in_msg->opcode == MEMCACHED_CMD_ADD
          || in_msg->opcode == MEMCACHED_CMD_SET
          || in_msg->opcode == MEMCACHED_CMD_REPLACE)
  {
    /* This callback can handle add/set/replace */
    out_cmd->callbacks.callback_add(api, in_msg->status, in_msg->cas, api->user_data, out_cmd->callback_data);
  } else {
    CORE_ME("Unimplemented result handler (cmd: %i)", in_msg->opcode);
  }
}

static void cb_result(struct memcached_server *server, struct memcached_msg *in_msg, void *baton)
{
  struct memcached_api *api = (struct memcached_api *) baton;
  struct pending_cmd   *out_cmd;

  if ((out_cmd = find_cmd(api, in_msg->opaque)) == NULL) {
    do_unknown_id_callback(api, in_msg);
    return;
  }

  /* Sanity check. */
  if (in_msg->opcode != out_cmd->out_data.sent_command)
    CORE_ME("Got a result with unexpected opcode");

  /* Run user callback */
  do_user_callback(api, in_msg, out_cmd);

  /* Cleanup. */
  free_pending_cmd(api, out_cmd);
}

static void fault_pending_cmd(struct memcached_api *api, enum memcached_result reason, struct pending_cmd * cmd)
{
  struct memcached_msg fake_error_msg = {
    .opcode   = cmd->out_data.sent_command,
    .status   = reason,
    .opaque   = cmd->out_data.opaque,
    .cas      = 0,
    .key      = cmd->out_data.key,   .key_len    = cmd->out_data.key_len,
    .extra    = NULL,                .extra_len  = 0,
    .data     = NULL,                .data_len   = 0,
  };

  /* Process like a regular callback. */
  do_user_callback(api, &fake_error_msg, cmd);

  /* Get rid of the command entry and it's related data. */
  free_pending_cmd(api, cmd);
}

static void fault_server_pending_cmds(struct memcached_api *api, struct memcached_server *server)
{
  struct pending_cmd *cur, *next;

  for (cur = RB_MIN(rb_cmds, &api->pending_cmd_list); cur != NULL; cur = next) {
    next = RB_NEXT(rb_cmds, &api->pennding_cmd_list, cur);

    /* Send connection failed callback to all pending command listeners. */
    if (cur->server == server)
      fault_pending_cmd(api, MEMCACHED_RESULT_CONN, cur);
  }
}

static void cb_server_error(struct memcached_server *server, void *baton)
{
  struct memcached_api *api = (struct memcached_api *) baton;

  for (int i = 0; i < api->num_host; i++) {
    if (api->host_list[i].server_conn == server) {
      /* Error out on any pending commands on that memcached server. */
      fault_server_pending_cmds(api, server);

      memcached_free(api->host_list[i].server_conn);
      api->host_list[i].server_conn = NULL;

      return;
    }
  }

  CORE_ME("cb_server_error() called with an unknown server");
}

static struct pending_cmd *new_cmd(struct memcached_api *api, struct memcached_server *server,
                                   struct memcached_msg *msg, const char *key, size_t key_len, void *callback_func,
                                   void *callback_data)
{
  struct pending_cmd *cmd;

  if ((cmd = calloc(1, sizeof(*cmd))) == NULL)
    return NULL;

  cmd->out_data.opaque = msg->opaque;
  cmd->out_data.sent_command = msg->opcode;
  cmd->out_data.key = key;
  cmd->out_data.key_len = key_len;

  cmd->callbacks.callback_dummy = callback_func;
  cmd->callback_data = callback_data;
  cmd->server = server;

  if (RB_INSERT(rb_cmds, &api->pending_cmd_list, cmd) != NULL)
    CORE_ME("Elment with this opaque id already exists in the tree");

  return cmd;
}

struct memcached_host *get_host(struct memcached_api *api, const char *key, size_t key_len)
{
  int server_num = api->cb_func_hash(key, key_len, api->host_list, api->num_host);

  if (server_num <= -1 || server_num >= api->num_host) {
    errno = EBADSLT;
    return NULL;
  }

  /* Map the hash key to the memcached server number. */
  return &api->host_list[server_num];
}

/* Server command proxy */
static int server_command_poxy(struct memcached_api *api, struct memcached_msg *msg, void *callback_func,
                               void *callback_data)
{
  int                    result;
  struct pending_cmd    *cmd;
  struct memcached_host *host;

  const char            *key_after;
  size_t                 key_len;

  /*  Key transformation functions (if there is one). */
  if (api->cb_func_keytrans(msg->key, msg->key_len, &key_after, &key_len) == -1)
    goto fail;

  if ((host = get_host(api, msg->key, msg->key_len)) == NULL)
    goto fail_free_key;

  /* Use the opaque field to keep track of which message this is. */
  msg->opaque = api->sequence_id;

  if (host->server_conn == NULL) {
    if ((host->server_conn = memcached_init(api->event_base, (struct sockaddr *) &host->sockaddr, api->conn_type, 
                                            cb_result, cb_server_error, api)) == NULL)
    {
      goto fail_free_key;
    }
  }

  /* New server command entry, so we know how to dispatch a callback when it comes back. */
  if ((cmd = new_cmd(api, host->server_conn, msg, key_after, key_len, callback_func, callback_data)) == NULL)
    goto fail_free_key;

  /* NOTE: Set this to null so we don't double free it in case of a error!!! */
  key_after = NULL;

  /* Schedule the command to be sent, and if everything looks okay set the sequence number to the next id. */
  if ((result = memcached_send(host->server_conn, msg, MEMCACHED_DT_BYTES)) == -1)
    goto fail_free_cmd;

  /* Roll over the sequence id to 0 if we're over 31 bits (to allow for negative return values) */
  api->sequence_id = (api->sequence_id + 1 > INT32_MAX) ? 0 : api->sequence_id + 1;

  return api->sequence_id;

fail_free_cmd:
  free_pending_cmd(api, cmd);

fail_free_key:
  free((char *) key_after);

fail:
  return -1;
}

static inline int cmp_inet4(const struct sockaddr_in *addr1, const struct sockaddr_in *addr2)
{
  int cmp_addr;
  if ((cmp_addr = addr1->sin_addr.s_addr - addr1->sin_addr.s_addr))
    return cmp_addr;

  return addr1->sin_port - addr1->sin_port;
}

static inline int cmp_inet6(const struct sockaddr_in6 *addr1, const struct sockaddr_in6 *addr2)
{
  int cmp_result;

  if ((cmp_result = addr1->sin6_addr.__in6_u.__u6_addr32[0] - addr2->sin6_addr.__in6_u.__u6_addr32[0]))
    return cmp_result;
  if ((cmp_result = addr1->sin6_addr.__in6_u.__u6_addr32[1] - addr2->sin6_addr.__in6_u.__u6_addr32[1]))
    return cmp_result;
  if ((cmp_result = addr1->sin6_addr.__in6_u.__u6_addr32[2] - addr2->sin6_addr.__in6_u.__u6_addr32[2]))
    return cmp_result;
  if ((cmp_result = addr1->sin6_addr.__in6_u.__u6_addr32[3] - addr2->sin6_addr.__in6_u.__u6_addr32[3]))
    return cmp_result;

  return addr1->sin6_port - addr2->sin6_port;
}

static int cmp_servers(const void *l, const void *r)
{
  const struct memcached_host *h1 = (const struct memcached_host *) l;
  const struct memcached_host *h2 = (const struct memcached_host *) r;

  const struct sockaddr *a1 = (const struct sockaddr *) &h1->sockaddr;
  const struct sockaddr *a2 = (const struct sockaddr *) &h2->sockaddr;

  /* Make things work (maybe) when there's multiple familizies */
  int protocol_cmp = a1->sa_family - a2->sa_family;
  if (protocol_cmp != 0)
    return protocol_cmp;

  if (a1->sa_family == AF_INET)
    return cmp_inet4(&h1->sockaddr.addr_4, &h2->sockaddr.addr_4);

  return cmp_inet6(&h1->sockaddr.addr_6, &h2->sockaddr.addr_6);
}

static int add_hosts(struct memcached_api *api, int num_hosts, struct sockaddr **hosts)
{
  socklen_t addrlen;

  for (int i = 0; i < num_hosts; i++) {
    if (hosts[i]->sa_family == AF_INET)
      addrlen = sizeof(struct sockaddr_in);
    else if (hosts[i]->sa_family == AF_INET6)
      addrlen = sizeof(struct sockaddr_in6);
    else {
      errno = EAFNOSUPPORT;
      return -1;
    }

    memcpy(&api->host_list[i].sockaddr, hosts[i], addrlen);
  }

  /* Sort the servers by address name. So we pick consistent servers in between startups. */
  if (num_hosts > 1)
    qsort(api->host_list, num_hosts, sizeof(*api->host_list), cmp_servers);

  api->num_host = num_hosts;
  return 0;
}

struct memcached_api *memcached_api_init(struct event_base *event_base, memcached_hash_func hash_func,
                                         memcached_keytrans_func key_fun, memcached_cb_unknown cb_unknown_id,
                                         int num_hosts, struct sockaddr **hosts, enum memcached_conn conn_type,
                                         void *api_baton)
{
  struct memcached_api *api;

  if ((api = calloc(1, sizeof(*api))) == NULL)
    return NULL;

  /* A hash function needs to be specified. */
  if ((api->cb_func_hash = hash_func) == NULL) {
    errno = EINVAL;
    goto fail;
  }

  /* Key transofmration function needs to be specified. */
  if ((api->cb_func_keytrans = key_fun) == NULL) {
    errno = EINVAL;
    goto fail;
  }

  api->cb_unknown_id = cb_unknown_id;

  if ((api->host_list = calloc(num_hosts, sizeof(struct memcached_host))) == NULL)
    goto fail;

  api->event_base = event_base;

  /* TODO: check value */
  api->conn_type = conn_type;

  /* Initlize pending command list (red,black tree) */
  RB_INIT(&api->pending_cmd_list);

  /* Userdata to pass back with callbacks */
  api->user_data = api_baton;

  if (add_hosts(api, num_hosts, hosts) == -1)
    goto fail;

  return api;

fail:
  free(api->host_list);
  free(api);
  return NULL;
}

void memcached_api_free(struct memcached_api *api)
{
  /* TODO: Close all server connections */
  for (int i = 0; i < api->num_host; i++)
    memcached_free(api->host_list[i].server_conn);

  /* Free the data allocated for all the pending commands.*/
  struct pending_cmd *next_cmd, *cur_cmd;
	for (cur_cmd = RB_MIN(rb_cmds, &api->pending_cmd_list); cur_cmd != NULL; cur_cmd = next_cmd) {
	  next_cmd = RB_NEXT(rb_cmds, &api->pending_cmd_list, cur_cmd);

    /* Free the pending commands (and their data) without issuing callbacks. */
		free_pending_cmd(api, cur_cmd);
	}

  free(api->host_list);
  free(api);
}

void memcached_unkown_id_ignore(struct memcached_api *api, const struct memcached_msg *in_msg, void *api_baton)
{
  /* Do nothing, ignore the unknown id error. */
  return;
}

void memcached_api_prune_pending(struct memcached_api *api)
{
  struct pending_cmd *next_cmd, *cur_cmd;

  for (cur_cmd = RB_MIN(rb_cmds, &api->pending_cmd_list); cur_cmd != NULL; cur_cmd = next_cmd) {
	  next_cmd = RB_NEXT(rb_cmds, &api->pending_cmd_list, cur_cmd);

    /* Fault the command (do any callbacks) with a canceled status. */
    fault_pending_cmd(api, MEMCACHED_RESULT_CANCELED, cur_cmd);
	}
}

int memcached_api_get(struct memcached_api *api, const char *key, size_t key_len, memcached_cb_get callback_func,
                      void *callback_data)
{
  struct memcached_msg msg = {
    .opcode     = MEMCACHED_CMD_GET,
    .key        = key,
    .key_len    = key_len,
    .extra      = NULL,
    .extra_len  = 0,
    /* These fields are unused in the GET command. */
    .cas        = 0,
    .data       = NULL,     .data_len   = 0,
  };

  /* Schedule the command to be run. */
  return server_command_poxy(api, &msg, callback_func, callback_data);
}

int memcached_api_add(struct memcached_api *api, const char *const key, size_t key_len, void *data, size_t data_len,
                      memcached_cb_add callback_func, void *callback_data)
{
  struct memcached_msg msg = {
    .opcode   = MEMCACHED_CMD_ADD,
    .key      = key,
    .key_len  = key_len,
    .data     = data,
    .data_len = data_len,
    /* These fields are unused in the ADD command. */
    .cas      = 0,
    .extra    = NULL,     .extra_len  = 0,
  };

  /* Schedule the command to be run. */
  return server_command_poxy(api, &msg, callback_func, callback_data);
}

int memcached_api_set(struct memcached_api *api, const char *const key, size_t key_len, void *data, size_t data_len,
                      uint64_t cas, uint32_t flags, uint32_t expiry, memcached_cb_set callback_func,
                      void *callback_data)
{
  uint32_t extra[2] = {
    htonl(flags),
    htonl(expiry),
  };

  struct memcached_msg msg = {
    .opcode     = MEMCACHED_CMD_SET,
    .key        = key,
    .key_len    = key_len,
    .data       = data,
    .data_len   = data_len,
    .cas        = cas,
    .extra      = extra,
    .extra_len  = sizeof(extra),
  };

  /* Schedule the command to be run. */
  return server_command_poxy(api, &msg, callback_func, callback_data);
}
