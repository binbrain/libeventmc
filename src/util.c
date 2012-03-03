/* libeventmc - Memcached client bindings for libevent.
 * Copyright (C) 2010 Admeld Inc, Milosz Tanski <mtanski@admeld.com>
 *
 * The source code for the libmeldmc library is licensed under the MIT license or
 * at your option under the GPL version 2 license. The contents of the both
 * licenses are contained within the libevemtmc distribution in COPYING.txt file.
 *
 */

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
