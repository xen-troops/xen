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

#ifdef CONFIG_ARM_PCI

/* Arch pci dev struct */
struct arch_pci_dev {
    struct device dev;
};

#define PRI_pci "%04x:%02x:%02x.%u"
#define pci_to_dev(pcidev) (&(pcidev)->arch.dev)

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
    struct pci_ecam_ops     *ops;
    void __iomem        *win;
};

/* Forward declaration as pci_host_bridge and pci_ops depend on each other. */
struct pci_host_bridge;

struct pci_ops {
    int (*read)(struct pci_host_bridge *bridge,
                    uint32_t sbdf, int where, int size, u32 *val);
    int (*write)(struct pci_host_bridge *bridge,
                    uint32_t sbdf, int where, int size, u32 val);
};

/*
 * struct to hold pci ops and bus shift of the config window
 * for a PCI controller.
 */
struct pci_ecam_ops {
    unsigned int            bus_shift;
    struct pci_ops          pci_ops;
    int             (*init)(struct pci_config_window *);
};

/*
 * struct to hold pci host bridge information
 * for a PCI controller.
 */
struct pci_host_bridge {
    struct dt_device_node *dt_node;  /* Pointer to the associated DT node */
    struct list_head node;           /* Node in list of host bridges */
    uint16_t segment;                /* Segment number */
    void *sysdata;                   /* Pointer to the config space window*/
    const struct pci_ops *ops;
};

struct pci_host_bridge *pci_find_host_bridge(uint16_t segment, uint8_t bus);

int pci_host_common_probe(struct dt_device_node *dev,
                struct pci_ecam_ops *ops);

void pci_init(void);

#else   /*!CONFIG_ARM_PCI*/
struct arch_pci_dev { };
static inline void  pci_init(void) { }
#endif  /*!CONFIG_ARM_PCI*/
#endif /* __ARM_PCI_H__ */
