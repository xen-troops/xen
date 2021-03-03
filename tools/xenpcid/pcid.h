/*
    Definitions for Xen PCI server protocol.
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
/* TODO: Determine id of control domain and use it all over the code */
#define DOM0_ID 0
#define FOREGROUND_OPT "-f"

#if defined(__linux__)
#define SYSFS_PCIBACK_DRIVER   "/sys/bus/pci/drivers/pciback"
#endif

#define PCI_INFO_PATH "/libxl/pci"
#define PCI_BDF_XSPATH         "%04x-%02x-%02x-%01x"
#define PCI_BDF                "%04x:%02x:%02x.%01x"

/*
 * TODO: Avoid code duplicates
 *
 * The presentation of the structures and some of the functions were taken from
 * Libxl internal files. It will be necessary to made this code common to avoid
 * duplicates.
 */

enum pcid__json_node_type {
    JSON_NULL    = (1 << 0),
    JSON_BOOL    = (1 << 1),
    JSON_INTEGER = (1 << 2),
    JSON_DOUBLE  = (1 << 3),
    JSON_LIST    = (1 << 4),
    JSON_STRING  = (1 << 5),
    JSON_MAP     = (1 << 6),
    JSON_ARRAY   = (1 << 7),
    JSON_ANY     = 255 /* this is a mask of all values above, adjust as needed */
};

struct flexarray {
    int size;
    int autogrow;
    unsigned int count;
    void **data; /* array of pointer */
    libxl_ctx *ctx;
};

struct pcid__json_map_node {
    char *map_key;
    struct pcid__json_object *obj;
};

struct pcid__json_object {
    enum pcid__json_node_type type;
    union {
        bool b;
        long long i;
        double d;
        char *string;
        struct list_head *list;
        /* List of pcid__json_object */
        struct flexarray *array;
        /* List of pcid__json_map_node */
        struct flexarray *map;
    } u;
    struct pcid__json_object *parent;
};

struct pcid__yajl_ctx {
    libxl_ctx *ctx;
    yajl_handle hand;
    struct pcid__json_object *head;
    struct pcid__json_object *current;
};

struct vchan_state {
    /* Server domain ID. */
    libxl_domid domid;
    /* XenStore path of the server with the ring buffer and event channel. */
    char *xs_path;

    struct libxenvchan *ctrl;
    int select_fd;
    /* receive buffer */
    char *rx_buf;
    size_t rx_buf_size; /* current allocated size */
    size_t rx_buf_used; /* actual data in the buffer */
};

#endif /* PCID_H */
