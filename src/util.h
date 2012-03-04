/* libeventmc - Memcached client bindings for libevent.
 * Copyright (C) 2010 Admeld Inc, Milosz Tanski <mtanski@admeld.com>
 *
 * The source code for the libmeldmc library is licensed under the MIT license or
 * at your option under the GPL version 2 license. The contents of the both
 * licenses are contained within the libevemtmc distribution in COPYING file.
 *
 */

#ifndef __UTIL_H__
#define __UTIL_H__

void *malloc_memcpy(const void *ptr, size_t object_size);

void CORE_ME(const char *fmt, ...);

#endif /* __UTIL_H__ */
