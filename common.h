/* libeventmc - Memcached client bindings for libevent.
 * Copyright (C) 2010 Admeld Inc, Milosz Tanski <mtanski@admeld.com>
 *
 * The source code for the libmeldmc library is licensed under the MIT license or
 * at your option under the GPL version 2 license. The contents of the both
 * licenses are contained within the libevemtmc distribution in COPYING.txt file.
 *
 */

#ifndef __COMMON_H__
#define __COMMON_H__

#if __GNUC__ > 4
  #define __DLL_PUBLIC  __attribute__ ((visibility("default")))
  #define __DLL_LOCAL   __attribute__ ((visibility("hidden")))
#else
  #define __DLL_PUBLIC
  #define __DLL_LOCAL
#endif


#endif /* __COMMON_H__ */
