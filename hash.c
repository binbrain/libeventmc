#include "crc32.h"
#include "memcached_server.h"
#include "memcached_api.h"

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
