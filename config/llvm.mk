AS         = llvm-as
LD         = ld.lld
CC         = clang
CXX        = clang++
LD_LTO     = llvm-lto
CPP        = $(CC) -E
ADDR2LINE  = llvm-addr2line
AR         = llvm-ar
RANLIB     = llvm-ranlib
NM         = llvm-nm
STRIP      = llvm-strip
OBJCOPY    = llvm-objcopy
OBJDUMP    = llvm-objdump
SIZEUTIL   = llvm-size

include $(XEN_ROOT)/config/GNUCommon.mk

