/*
 * Misc. device initialization
 *
 * Volodymyr Babchuk <volodymyr_babchuk@epam.com>
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

#include <xen/device_tree.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>

#include <asm/device.h>

int __init misc_dev_init(void)
{
    struct dt_device_node *np;
    int rc;

    printk(XENLOG_INFO"Initializing misc. devices\n");
    dt_for_each_device_node(dt_host, np)
    {
        rc = device_init(np, DEVICE_MISC, NULL);
        if (rc && rc != -EBADF && rc != -ENODEV )
            return rc;
    }

    return 0;
}

__initcall(misc_dev_init);
