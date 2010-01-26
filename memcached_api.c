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
/* libeventmemcache */
#include "memcached_server.h"
#include "memcached_api.h"
#include "util.h"
#include "crc32.h"

struct pending_cmd
{
  /* We use the opaque fields in memcached to */
  uint32_t                opaque;

  enum memcached_cmd      sent_command;

  union {
    memcached_cb_get      callback_get;
    memcached_cb_add      callback_add;     /* add/set/replace */
    void                 *callback_dummy;
  } callbacks;

  void                   *callback_data;

  RB_ENTRY(pending_cmd)   e_tree;
};

struct memcached_api
{
  /* All server have to be the same connection type */
  enum memcached_conn     conn_type;
  /* The libevent event_base object */
  struct event_base      *event_base;

  /* List of callbacks */
  memcached_hash_func     cb_func_hash;

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
  static inline int cmp_cmd(struct pending_cmd *c1, struct pending_cmd *c2) { return (c1->opaque - c2->opaque); }

  /* Generate functions for manipulating the tree. */
  RB_GENERATE_STATIC(rb_cmds, pending_cmd, e_tree, cmp_cmd);

#undef __inline
#undef __unused

static inline struct pending_cmd *find_cmd(struct memcached_api *api, uint32_t opaque)
{
  struct pending_cmd search_cmd = { .opaque = opaque };

  return RB_FIND(rb_cmds, &api->pending_cmd_list, &search_cmd);
}

static void cb_result(struct memcached_server *server, struct memcached_msg *in_msg, void *baton)
{
  struct memcached_api *api = (struct memcached_api *) baton;
  struct pending_cmd   *cmd;

  if ((cmd = find_cmd(api, in_msg->opaque)) == NULL)
    CORE_ME("Unable to find such value");

  /* Sanity check. */
  if (in_msg->opcode != cmd->sent_command)
    CORE_ME("Got a result with unexpected opcode");

  /* Run the callbacks */
  if (cmd->callbacks.callback_dummy == NULL)
    ; /* We don't care about the response */
  else if (in_msg->opcode == MEMCACHED_CMD_GET
        || in_msg->opcode == MEMCACHED_CMD_GETK)
  {
    cmd->callbacks.callback_get(api, in_msg->status, in_msg->key, in_msg->key_len, in_msg->data, in_msg->data_len,
                                in_msg->cas, api->user_data, cmd->callback_data);

  } else if (in_msg->opcode == MEMCACHED_CMD_ADD
          || in_msg->opcode == MEMCACHED_CMD_SET
          || in_msg->opcode == MEMCACHED_CMD_REPLACE)
  {
    /* This callback can handle add/set/replace */
    cmd->callbacks.callback_add(api, in_msg->status, in_msg->cas, api->user_data, cmd->callback_data);
  } else {
    CORE_ME("Unimplemented result handler (cmd: %i)", in_msg->opcode);
  }

  /* Cleanup. */
  RB_REMOVE(rb_cmds, &api->pending_cmd_list, cmd);
  free(cmd);
}


static struct pending_cmd *new_cmd(struct memcached_api *api, struct memcached_msg *msg, void *callback_func,
                                   void *callback_data)
{
  struct pending_cmd *cmd;

  if ((cmd = calloc(1, sizeof(*cmd))) == NULL)
    return NULL;

  cmd->opaque = msg->opaque;
  cmd->sent_command = msg->opcode;
  cmd->callbacks.callback_dummy = callback_func;
  cmd->callback_data = callback_data;

  if (RB_INSERT(rb_cmds, &api->pending_cmd_list, cmd) != NULL)
    CORE_ME("Elment with this opaque id already exists in the tree");

  return cmd;
}


int memcached_hash_none(const char *key, ssize_t key_len, const struct memcached_host *hosts, int num_hosts)
{
  /* The naive case, always pick the first server */
  return 0;
}

int memcached_hash_crc32(const char *key, ssize_t key_len, const struct memcached_host *hosts, int num_hosts)
{
  if (num_hosts == 0)
    return 0;

  crc32t sum = crc32update(crc32init(), (const unsigned char *) key, key_len);
  return sum % num_hosts;
}

int memcached_hash_ketama(const char *key, ssize_t key_len, const struct memcached_host *hosts, int num_hosts)
{
  /* TODO: Implement */
  return -1;
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

  if ((host = get_host(api, msg->key, msg->key_len)) == NULL)
    return -1;

  /* Use the opaque field to keep track of which message this is. */
  msg->opaque = api->sequence_id;

  /* TODO: Do something better here. */
  if ((cmd = new_cmd(api, msg, callback_func, callback_data)) == NULL)
    return -1;

  if (host->server_conn == NULL) {
    if ((host->server_conn = memcached_init(api->event_base, (struct sockaddr *) &host->sockaddr, api->conn_type, 
                                            cb_result, NULL, api)) == NULL)
    { 
      return -1;
    }
  }

  /* Schedule the command to be sent, and if everything looks okay set the sequence number to the next id. */
  if ((result = memcached_send(host->server_conn, msg, MEMCACHED_DT_BYTES)) == -1) {
    RB_REMOVE(rb_cmds, &api->pending_cmd_list, cmd);
    free(cmd);

    return -1;
  } else
    api->sequence_id++;

  return 0;
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

  if ((cmp_result = addr1->sin6_addr.in6_u.u6_addr32[0] - addr2->sin6_addr.in6_u.u6_addr32[0]))
    return cmp_result;
  if ((cmp_result = addr1->sin6_addr.in6_u.u6_addr32[1] - addr2->sin6_addr.in6_u.u6_addr32[1]))
    return cmp_result;
  if ((cmp_result = addr1->sin6_addr.in6_u.u6_addr32[2] - addr2->sin6_addr.in6_u.u6_addr32[2]))
    return cmp_result;
  if ((cmp_result = addr1->sin6_addr.in6_u.u6_addr32[3] - addr2->sin6_addr.in6_u.u6_addr32[3]))
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

static int add_hosts(struct memcached_api *api, int num_hosts, struct sockaddr *hosts)
{
  socklen_t addrlen;

  for (int i = 0; i < num_hosts; i++) {
    if (hosts->sa_family != AF_INET || hosts->sa_family != AF_INET6) {
      errno = EAFNOSUPPORT;
      return -1;
    }

    addrlen = (hosts->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    memcpy(&api->host_list[i].sockaddr, &hosts[i], addrlen);
  }

  /* Sort the servers by address name. So we pick consistent servers in between startups. */
  if (num_hosts > 1)
    qsort(api->host_list, num_hosts, sizeof(*api->host_list), cmp_servers);

  api->num_host = num_hosts;
  return 0;
}

struct memcached_api *memcached_api_init(struct event_base *event_base, memcached_hash_func hash_func, int num_hosts,
                                         struct sockaddr *hosts, enum memcached_conn conn_type, void *user_baton)
{
  struct memcached_api *api;

  if ((api = calloc(1, sizeof(*api))) == NULL)
    return NULL;

  if ((api->cb_func_hash = hash_func) == NULL) {
    errno = EINVAL;
    goto fail;
  }

  if ((api->host_list = calloc(num_hosts, sizeof(struct memcached_host))) == NULL)
    goto fail;

  api->event_base = event_base;

  /* TODO: check value */
  api->conn_type = conn_type;

  /* Initlize pending command list (red,black tree) */
  RB_INIT(&api->pending_cmd_list);

  /* Userdata to pass back with callbacks */
  api->user_data = user_baton;

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
		   RB_REMOVE(rb_cmds, &api->pending_cmd_list, cur_cmd);
		   free(cur_cmd);
	}

  free(api->host_list);
  free(api);
}

int memcached_api_get(struct memcached_api *api, const char *key, size_t key_len, memcached_cb_get callback_func,
                      void *callback_data)
{
  struct memcached_msg msg = {
    .opcode     = MEMCACHED_CMD_GETK,
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
