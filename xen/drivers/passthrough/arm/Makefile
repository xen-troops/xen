obj-y += iommu.o iommu_helpers.o iommu_fwspec.o
obj-$(CONFIG_ARM_SMMU) += smmu.o

ifeq ($(CONFIG_IPMMU_VMSA),y)
obj-y += ipmmu-vmsa.o
obj-y += ipmmu-vmsa-plat.o
else
ifeq ($(CONFIG_IPMMU_VMSA_LEGACY),y)
obj-y += ipmmu-vmsa-legacy.o
obj-y += ipmmu-vmsa-plat.o
obj-y += io-pgtable.o
obj-y += io-pgtable-arm.o
endif
endif