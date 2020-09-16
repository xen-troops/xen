/*
 * Copyright (C) 2020 Arm Ltd.
 *
 * Based on Linux drivers/pci/ecam.c
 * Copyright 2016 Broadcom.
 *
 * Based on Linux drivers/pci/controller/pci-host-common.c
 * Based on Linux drivers/pci/controller/pci-host-generic.c
 * Copyright (C) 2014 ARM Limited Will Deacon <will.deacon@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ARM_PCI_H__
#define __ARM_PCI_H__

#include <xen/pci.h>
#include <xen/device_tree.h>
#include <asm/device.h>
#include <asm/mmio.h>

#ifdef CONFIG_HAS_PCI

/* Arch pci dev struct */
struct arch_pci_dev {
    struct device dev;
};

#define PRI_pci "%04x:%02x:%02x.%u"
#define pci_to_dev(pcidev) (&(pcidev)->arch.dev)
/*
 * FIXME: because of the header cross-dependencies, e.g. we need both
 * struct pci_dev and struct arch_pci_dev at the same time, this cannot be
 * done with an inline here. Macro can be implemented, but looks scary.
 */
struct pci_dev *dev_to_pci(struct device *dev);

/*
 * struct to hold the mappings of a config space window. This
 * is expected to be used as sysdata for PCI controllers that
 * use ECAM.
 */
struct pci_config_window {
    paddr_t     phys_addr;
    paddr_t     size;
    uint8_t     busn_start;
    uint8_t     busn_end;
    const struct pci_ecam_ops     *ops;
    void __iomem        *win;
    /* R-Car */
    /* TODO: is it bridge or config property? */
    uint8_t root_bus_nr;
};

/* Forward declaration as pci_host_bridge and pci_ops depend on each other. */
struct pci_host_bridge;

struct pci_ops {
    void __iomem *(*map_bus)(struct pci_host_bridge *bridge, uint32_t sbdf,
                             uint32_t offset);
    int (*read)(struct pci_host_bridge *bridge, uint32_t sbdf,
                uint32_t reg, uint32_t len, uint32_t *value);
    int (*write)(struct pci_host_bridge *bridge, uint32_t sbdf,
                 uint32_t reg, uint32_t len, uint32_t value);
    int (*register_mmio_handler)(struct domain *d,
                                 struct pci_host_bridge *bridge,
                                 const struct mmio_handler_ops *ops);
    int (*need_mapping)(struct domain *d, struct pci_host_bridge *bridge,
                        u64 addr, u64 len);
};

/*
 * struct to hold pci ops and bus shift of the config window
 * for a PCI controller.
 */
struct pci_ecam_ops {
    unsigned int            bus_shift;
    struct pci_ops          pci_ops;
    int (*init)(struct pci_config_window *);
};

/* default ECAM ops */
extern const struct pci_ecam_ops pci_generic_ecam_ops;

/*
 * struct to hold pci host bridge information
 * for a PCI controller.
 */
struct pci_host_bridge {
    struct dt_device_node *dt_node;  /* Pointer to the associated DT node */
    struct list_head node;           /* Node in list of host bridges */
    uint16_t segment;                /* Segment number */
    u8 bus_start;                    /* Bus start of this bridge. */
    u8 bus_end;                      /* Bus end of this bridge. */
    void *sysdata;                   /* Pointer to the config space window*/
    const struct pci_ops *ops;
};

int pci_generic_config_read(struct pci_host_bridge *bridge, uint32_t sbdf,
                            uint32_t reg, uint32_t len, uint32_t *value);

int pci_generic_config_write(struct pci_host_bridge *bridge, uint32_t sbdf,
                            uint32_t reg, uint32_t len, uint32_t value);

struct pci_host_bridge *pci_find_host_bridge(uint16_t segment, uint8_t bus);
struct dt_device_node *pci_find_host_bridge_node(struct device *dev);
void pci_add_host_bridge(struct pci_host_bridge *bridge);
struct pci_host_bridge * pci_alloc_host_bridge(void);

int pci_host_common_probe(struct dt_device_node *dev,
                          const struct pci_ecam_ops *ops,
                          int ecam_reg_idx);
bool dt_pci_parse_bus_range(struct dt_device_node *dev,
                            struct pci_config_window *cfg);

void __iomem *pci_ecam_map_bus(struct pci_host_bridge *bridge,
                               uint32_t sbdf, uint32_t where);
int pci_host_iterate_bridges(struct domain *d,
                             int (*clb)(struct domain *d,
                                        struct pci_host_bridge *bridge));
bool pci_host_bridge_need_mapping(struct domain *d,
                                  const struct dt_device_node *node,
                                  u64 addr, u64 len);
struct domain *pci_get_owner_domain(u16 seg, u8 bus);
#else   /*!CONFIG_HAS_PCI*/
struct arch_pci_dev { };
static inline void  pci_init(void) { }
static inline bool pci_host_bridge_need_mapping(struct domain *d,
                                                const struct dt_device_node *node,
                                                u64 addr, u64 len)
{
    return true;
}
#endif  /*!CONFIG_HAS_PCI*/
#endif /* __ARM_PCI_H__ */
