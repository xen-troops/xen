ifeq ($(llvm),y)
include $(XEN_ROOT)/config/llvm.mk
else
include $(XEN_ROOT)/config/StdGNU.mk
endif

SYSCONFIG_DIR = $(CONFIG_DIR)/$(CONFIG_LEAF_DIR)
