AS         = $(CROSS_COMPILE)as
LD         = $(CROSS_COMPILE)ld
ifeq ($(clang),y)
CC         = $(CROSS_COMPILE)clang
CXX        = $(CROSS_COMPILE)clang++
LD_LTO     = $(CROSS_COMPILE)llvm-ld
else
CC         = $(CROSS_COMPILE)gcc
CXX        = $(CROSS_COMPILE)g++
LD_LTO     = $(CROSS_COMPILE)ld
endif
CPP        = $(CC) -E
ADDR2LINE  = $(CROSS_COMPILE)addr2line
AR         = $(CROSS_COMPILE)ar
RANLIB     = $(CROSS_COMPILE)ranlib
NM         = $(CROSS_COMPILE)nm
STRIP      = $(CROSS_COMPILE)strip
OBJCOPY    = $(CROSS_COMPILE)objcopy
OBJDUMP    = $(CROSS_COMPILE)objdump
SIZEUTIL   = $(CROSS_COMPILE)size

include $(XEN_ROOT)/config/GNUCommon.mk
