/*
 * Copyright (C) 2020 Arm Ltd.
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

#include <asm/device.h>
#include <xen/pci.h>
#include <asm/pci.h>

#include <xen/warning.h>

extern bool pci_under_qemu;

static const struct dt_device_match gen_pci_dt_match[] = {
    { .compatible = "pci-host-ecam-generic",
      .data =       &pci_generic_ecam_ops },

    { },
};

static int gen_pci_dt_init(struct dt_device_node *dev, const void *data)
{
    const struct dt_device_match *of_id;
    const struct pci_ecam_ops *ops;

    /*
     * FIXME: This is a really dirty hack: R-Car doesn't have ECAM
     * host bridge, but QEMU does.
     */
    pci_under_qemu = true;
    warning_add("\n\nWARNING! ASSUMING QEMU\n\n\n");

    of_id = dt_match_node(gen_pci_dt_match, dev->dev.of_node);
    ops = (struct pci_ecam_ops *) of_id->data;

    printk(XENLOG_INFO "Found PCI host bridge %s compatible:%s \n",
            dt_node_full_name(dev), of_id->compatible);

    return pci_host_common_probe(dev, ops, 0);
}

DT_DEVICE_START(pci_gen, "PCI HOST GENERIC", DEVICE_PCI)
.dt_match = gen_pci_dt_match,
.init = gen_pci_dt_init,
DT_DEVICE_END

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
