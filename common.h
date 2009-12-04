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
