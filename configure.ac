AC_PREREQ([2.68])
AC_INIT([libeventmc], [1.0], [http://www.admeld.com])
AC_CONFIG_SRCDIR([src/memcached_api.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall])
AC_PROG_LIBTOOL
AC_PROG_CC
AC_PROG_INSTALL
AC_CONFIG_MACRO_DIR([m4])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_C_RESTRICT
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([socket strndup])
AC_CHECK_LIB([crypto], [MD5], [], [
	echo "OpenSSL is required for this program"
	exit 1;])
AC_CHECK_LIB([event], [evutil_make_socket_nonblocking], [], [
	echo "libevent is required for this program"
	exit 1;])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
