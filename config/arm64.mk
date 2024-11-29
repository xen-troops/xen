CONFIG_ARM := y
CONFIG_ARM_64 := y

CONFIG_XEN_INSTALL_SUFFIX :=

CFLAGS += #-marm -march= -mcpu= etc

ifeq ($(clang),y)
CFLAGS += -target aarch64 -march=armv8-a
endif

# Use only if calling $(LD) directly.
LDFLAGS_DIRECT += -EL

IOEMU_CPU_ARCH ?= aarch64

EFI_DIR ?= /usr/lib64/efi
