EVMC_VERSION = 0.2

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_CFLAGS = -c -D_GNU_SOURCE -O2 -ggdb3 --std=gnu99 -DVERSION=\"$(EVMC_VERSION)\" -fPIC $(CFLAGS)
lib_LTLIBRARIES = libeventmc.la
libeventmc_la_SOURCES = src/bsd_tree.h  src/common.h  src/crc32.c  src/crc32.h\
			src/hash.c  src/key.c  src/memcached_api.c\
			src/memcached_api.h  src/memcached_server.c\
			src/memcached_server.h  src/util.c  src/util.h
libeventmc_la_LDFLAGS= -lcrypto -levent
include_HEADERS = src/memcached_api.h src/memcached_server.h
