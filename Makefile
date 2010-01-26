EVMC_VERSION:=0.1.3
EVMC_PREFIX=$(PREFIX)

EVMC_CFLAGS:=-c -D_GNU_SOURCE -O2 -ggdb3 -DVERSION=\"$(EVMC_VERSION)\" -Wall --std=gnu99 -fPIC $(CFLAGS)
EVMC_LDFLAGS:=-levent $(LDFLAGS)

EVMC_CFILES:=util.c memcached_server.c memcached_api.c crc32.c
EVMC_OBJS:=$(patsubst %.c,%.o,$(EVMC_CFILES))

EVMC_INSTALL_HEADERS:=memcached_server.h memcached_api.h

.PHONY: all clean strip install


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

libeventmc.so: $(EVMC_OBJS)
	$(CC) $(EVMC_LDFLAGS) -shared -o $@ $^

libeventmc.a: $(EVMC_OBJS)
	$(AR) rcs $@ $&

$(EVMC_OBJS): %.o: %.c
	$(CC) $(EVMC_CFLAGS) -o $@ $<
