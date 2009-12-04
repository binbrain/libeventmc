/* libc */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* libeventmemcached */
#include "common.h"

void *
__DLL_LOCAL
malloc_memcpy(const void *in_data, size_t object_size)
{
  void *ptr;

  if ((ptr = malloc(object_size)) == NULL)
    return NULL;

  return memcpy(ptr, in_data, object_size);
}

void
__DLL_LOCAL
CORE_ME(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);

  vprintf(fmt, ap);  
  abort();
}
