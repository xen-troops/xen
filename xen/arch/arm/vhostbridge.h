/*
 * xen/arch/arm/vhostbridge.h
 * Copyright (c) 2021 EPAM Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __ARCH_ARM_VHOSTBRIDGE_H__
#define __ARCH_ARM_VHOSTBRIDGE_H__

#include <xen/pci.h>

int vhostbridge_init(struct domain *d, const struct pci_dev *pdev);
void vhostbridge_fini(struct domain *d);
uint32_t vhostbridge_read(struct domain *d, pci_sbdf_t sbdf, unsigned int reg,
                          unsigned int size);
void vhostbridge_write(struct domain *d, pci_sbdf_t sbdf, unsigned int reg,
                       unsigned int size, uint32_t data);

#endif /* __ARCH_ARM_VHOSTBRIDGE_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

