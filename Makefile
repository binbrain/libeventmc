EVMC_VERSION:=0.3.1
EVMC_PREFIX=$(PREFIX)

EVMC_CFLAGS:=-c -D_GNU_SOURCE -O2 -ggdb3 -DVERSION=\"$(EVMC_VERSION)\" -Wall --std=gnu99 -fPIC $(CFLAGS)
EVMC_LDFLAGS:=-lcrypto -levent $(LDFLAGS)

EVMC_CFILES:=util.c memcached_server.c memcached_api.c key.c hash.c crc32.c
EVMC_OBJS:=$(patsubst %.c,%.o,$(EVMC_CFILES))

EVMC_INSTALL_HEADERS:=memcached_server.h memcached_api.h

.PHONY: all clean strip install tarball


all: libeventmc.so libeventmc.a

strip: all
	strip libeventmc.so

clean:
	$(RM) libeventmc.so
	$(RM) libeventmc.a
	$(RM) $(EVMC_OBJS)

install: all
	mkdir -p $(EVMC_PREFIX)/include/eventmc
	mkdir -p $(EVMC_PREFIX)/lib
	install -m 644 $(EVMC_INSTALL_HEADERS) $(EVMC_PREFIX)/include/eventmc
	install -m 644 libeventmc.a $(EVMC_PREFIX)/lib
	install -m 755 libeventmc.so $(EVMC_PREFIX)/lib

tarball:
	$(RM) -R /tmp/libeventmc-$(EVMC_VERSION)
	mkdir -p /tmp/libeventmc-$(EVMC_VERSION)
	rsync -az --exclude 'libeventmc-*.tar.gz' --exclude '.git' --exclude '*.o' --exclude '*.a' --exclude '*.so' --exclude '.svn' --exclude '*.v[pt]*' --exclude '.*.swp' . /tmp/libeventmc-$(EVMC_VERSION)
	tar  -c -j -f libeventmc-$(EVMC_VERSION).tar.bz2 -C /tmp libeventmc-$(EVMC_VERSION)
	$(RM) -R /tmp/libeventmc-$(EVMC_VERSION)

libeventmc.so: $(EVMC_OBJS)
	$(CC) $(EVMC_LDFLAGS) -shared -o $@ $^

libeventmc.a: $(EVMC_OBJS)
	$(AR) rcs $@ $&

$(EVMC_OBJS): %.o: %.c
	$(CC) $(EVMC_CFLAGS) -o $@ $<
