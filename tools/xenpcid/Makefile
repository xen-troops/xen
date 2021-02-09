XEN_ROOT=$(CURDIR)/../..
include $(XEN_ROOT)/tools/Rules.mk

CFLAGS += -Werror
CFLAGS += $(CFLAGS_libxenstore) $(CFLAGS_libxenvchan) $(CFLAGS_libxenlight)
CFLAGS += -include $(XEN_ROOT)/tools/config.h # libxl_json.h needs it.

LDLIBS += $(LDLIBS_libxenstore) $(LDLIBS_libxenvchan) $(LDLIBS_libxl_json) $(LDLIBS_libxl)

.PHONY: all
all: xenpcid

.PHONY: install
install: all
	$(INSTALL_DIR) $(DESTDIR)$(sbindir)
	$(INSTALL_PROG) xenpcid $(DESTDIR)$(sbindir)

.PHONY: clean
clean:
	$(RM) -f xenpcid xenpcid.o $(DEPS_RM)

.PHONY: distclean
distclean: clean

.PHONY: uninstall
uninstall:
	rm -f $(DESTDIR)$(sbindir)/xenpcid

xenpcid: xenpcid.o Makefile
	$(CC) $(LDFLAGS) $< -o $@ $(LDLIBS) -lyajl $(APPEND_LDFLAGS)

-include $(DEPS_INCLUDE)
