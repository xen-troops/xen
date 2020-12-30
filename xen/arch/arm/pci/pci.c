/*
 * Copyright (C) 2020 Arm Ltd.
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

#include <xen/acpi.h>
#include <xen/device_tree.h>
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/pci.h>
#include <xen/param.h>

int arch_pci_clean_pirqs(struct domain *d)
{
    return 0;
}

struct pci_dev *dev_to_pci(struct device *dev)
{
    struct arch_pci_dev *arch_dev;

    ASSERT(dev->type == DEV_PCI);

    arch_dev = container_of((dev), struct arch_pci_dev, dev);
    return container_of(arch_dev, struct pci_dev, arch);
}

static int __init dt_pci_init(void)
{
    struct dt_device_node *np;
    int rc;

    dt_for_each_device_node(dt_host, np)
    {
        rc = device_init(np, DEVICE_PCI, NULL);
        if( !rc )
            continue;
        /*
         * Ignore the following error codes:
         *   - EBADF: Indicate the current is not an pci
         *   - ENODEV: The pci device is not present or cannot be used by
         *     Xen.
         */
        else if ( rc != -EBADF && rc != -ENODEV )
        {
            printk(XENLOG_ERR "No driver found in XEN or driver init error.\n");
            return rc;
        }
    }

    return 0;
}

#ifdef CONFIG_ACPI
static void __init acpi_pci_init(void)
{
    printk(XENLOG_ERR "ACPI pci init not supported \n");
    return;
}
#else
static inline void __init acpi_pci_init(void) { }
#endif

static bool __initdata param_pci_enable;
static int __init parse_pci_param(const char *arg)
{
    if ( !arg )
    {
        param_pci_enable = false;
        return 0;
    }

    switch ( parse_bool(arg, NULL) )
    {
        case 0:
            param_pci_enable = false;
            return 0;
        case 1:
            param_pci_enable = true;
            return 0;
    }

    return -EINVAL;
}
custom_param("pci", parse_pci_param);

static int __init pci_init(void)
{
    /*
     * Enable PCI when has been enabled explicitly (pci=on)
     */
    if ( !param_pci_enable)
        return 0;

    if ( acpi_disabled )
        dt_pci_init();
    else
        acpi_pci_init();

    pci_segments_init();

    return 0;
}
__initcall(pci_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
