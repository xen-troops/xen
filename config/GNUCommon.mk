# Allow git to be wrappered in the environment
GIT        ?= git

INSTALL      = install
INSTALL_DIR  = $(INSTALL) -d -m0755 -p
INSTALL_DATA = $(INSTALL) -m0644 -p
INSTALL_PROG = $(INSTALL) -m0755 -p

BOOT_DIR ?= /boot
DEBUG_DIR ?= /usr/lib/debug

SOCKET_LIBS =
UTIL_LIBS = -lutil

SONAME_LDFLAG = -soname
SHLIB_LDFLAGS = -shared
