/*
    Common definitions for Xen PCI client-server protocol.
    Copyright (C) 2021 EPAM Systems Inc.

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef PCID_H
#define PCID_H

#define PCID_XS_DIR             "/local/domain/"
#define PCID_XS_PATH            "/data/pcid-vchan"

#define PCI_RECEIVE_BUFFER_SIZE 4096
#define PCI_MAX_SIZE_RX_BUF     MB(1)

#define PCID_MSG_FIELD_ID        "id"
#define PCID_MSG_FIELD_ARGS      "arguments"

#define PCID_CMD_LIST            "ls"
#define PCID_CMD_DIR_ID          "dir_id"

#define PCID_CMD_WRITE           "write"
#define PCID_CMD_READ_HEX        "read_hex"
#define PCID_CMD_PCI_PATH        "pci_path"
#define PCID_CMD_PCI_INFO        "pci_info"

#define PCID_PCIBACK_DRIVER      "pciback_driver"
#define PCID_PCI_DEV             "pci_dev"

#define SYSFS_DRIVER_PATH        "driver_path"

#if defined(__linux__)
#define SYSFS_PCIBACK_DRIVER   "/sys/bus/pci/drivers/pciback"
#endif

#define PCI_INFO_PATH "/libxl/pci"
#define PCI_BDF_XSPATH         "%04x-%02x-%02x-%01x"
#define PCI_BDF                "%04x:%02x:%02x.%01x"

int libxl_pcid_process(libxl_ctx *ctx);

#endif /* PCID_H */

/*
 * Local variables:
 *  mode: C
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
