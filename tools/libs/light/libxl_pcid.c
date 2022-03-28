/*
    Utils for xl pcid daemon

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

#define _GNU_SOURCE  // required for strchrnul()

#include "libxl_osdeps.h" /* must come before any other headers */

#include "libxl_internal.h"
#include "libxl_vchan.h"

#include <libxl_utils.h>
#include <libxlutil.h>

#include <pcid.h>
#include <xenstore.h>

#include <libxl.h>
#include <libxl_json.h>
#include <dirent.h>

#define DOM0_ID 0

static struct libxl__json_object *process_ls_cmd(libxl__gc *gc,
                                                 const struct libxl__json_object *resp)
{
    libxl__json_object *result = NULL;
    const libxl__json_object *args, *dir_id;
    struct libxl__json_object *node;
    char *dir_name;
    struct dirent *de;
    DIR *dir = NULL;

    args = libxl__json_map_get(PCID_MSG_FIELD_ARGS, resp, JSON_MAP);
    if (!args)
        goto out;
    dir_id = libxl__json_map_get(PCID_CMD_DIR_ID, args, JSON_ANY);
    if (!dir_id)
        goto out;

    dir_name = dir_id->u.string;

    if (strcmp(PCID_PCIBACK_DRIVER, dir_name) == 0)
        dir = opendir(SYSFS_PCIBACK_DRIVER);
    else {
        LOGE(ERROR, "Unknown directory: %s\n", dir_name);
        goto out;
    }

    if (dir == NULL) {
        if (errno == ENOENT)
            LOGE(ERROR, "Looks like pciback driver not loaded\n");
        else
            LOGE(ERROR, "Couldn't open %s\n", dir_name);
        goto out;
    }

    result = libxl__json_object_alloc(gc, JSON_ARRAY);
    if (!result) {
        LOGE(ERROR, "Memory allocation failed\n");
        goto out;
    }
    while ((de = readdir(dir))) {
        node = libxl__json_object_alloc(gc, JSON_STRING);
        node->u.string = de->d_name;
        flexarray_append(result->u.array, node);
    }

    closedir(dir);

out:
    return result;
}

static int handle_write_cmd(libxl__gc *gc, char *sysfs_path, char *pci_info)
{
    int rc, fd;

    fd = open(sysfs_path, O_WRONLY);
    if (fd < 0) {
        LOGE(ERROR, "Couldn't open %s\n", sysfs_path);
        return ERROR_FAIL;
    }

    rc = write(fd, pci_info, strlen(pci_info));
    close(fd);
    if (rc < 0) {
        LOGE(ERROR, "write to %s returned %d\n", sysfs_path, rc);
        return ERROR_FAIL;
    }

    return 0;
}

static libxl__json_object *process_write_cmd(libxl__gc *gc,
                                             const struct libxl__json_object *resp)
{
    libxl__json_object *result = NULL;
    const struct libxl__json_object *args, *dir_id, *pci_path, *pci_info;
    char *full_path;
    int ret;

    args = libxl__json_map_get(PCID_MSG_FIELD_ARGS, resp, JSON_MAP);
    if (!args)
        goto out;
    dir_id = libxl__json_map_get(PCID_CMD_DIR_ID, args, JSON_ANY);
    if (!dir_id)
        goto out;
    pci_path = libxl__json_map_get(PCID_CMD_PCI_PATH, args, JSON_ANY);
    if (!pci_path)
        goto out;
    pci_info = libxl__json_map_get(PCID_CMD_PCI_INFO, args, JSON_ANY);
    if (!pci_info)
        goto out;

    if (strcmp(dir_id->u.string, PCID_PCI_DEV) == 0)
        full_path = libxl__sprintf(gc, SYSFS_PCI_DEV"%s", pci_path->u.string);
    else if (strcmp(dir_id->u.string, PCID_PCIBACK_DRIVER) == 0)
        full_path = libxl__sprintf(gc, SYSFS_PCIBACK_DRIVER"%s", pci_path->u.string);
    else if (strcmp(dir_id->u.string, SYSFS_DRIVER_PATH) == 0)
        full_path = pci_path->u.string;
    else {
        LOGE(ERROR, "Unknown write directory %s\n", dir_id->u.string);
        goto out;
    }

    ret = handle_write_cmd(gc, full_path, pci_info->u.string);
    if (ret != 0)
        goto out;

    result = libxl__json_object_alloc(gc, JSON_STRING);
    if (!result) {
        LOGE(ERROR, "Memory allocation failed\n");
        goto out;
    }
    result->u.string = pci_path->u.string;

out:
    return result;
}

static libxl__json_object *process_read_hex_cmd(libxl__gc *gc,
                                                const struct libxl__json_object *resp)
{
    libxl__json_object *result = NULL;
    const struct libxl__json_object *args, *dir_id, *pci_info;
    char *full_path;
    uint16_t read_items;
    long long read_number;

    args = libxl__json_map_get(PCID_MSG_FIELD_ARGS, resp, JSON_MAP);
    if (!args)
        goto out;
    dir_id = libxl__json_map_get(PCID_CMD_DIR_ID, args, JSON_ANY);
    if (!dir_id)
        goto out;
    pci_info = libxl__json_map_get(PCID_CMD_PCI_INFO, args, JSON_ANY);
    if (!pci_info)
        goto out;

    if (strcmp(PCID_PCI_DEV, dir_id->u.string) == 0)
        full_path = libxl__sprintf(gc, SYSFS_PCI_DEV"%s", pci_info->u.string);
    else
        full_path = pci_info->u.string;

    FILE *f = fopen(full_path, "r");
    if (!f) {
        LOGE(ERROR, "PCI device %s does not have needed attribute\n",
                full_path);
        goto out;
    }
    read_items = fscanf(f, "0x%llx\n", &read_number);
    fclose(f);
    if (read_items != 1) {
        LOGE(ERROR, "Cannot read attribute of pci device %s\n", full_path);
        goto out;
    }

    result = libxl__json_object_alloc(gc, JSON_INTEGER);
    if (!result) {
        LOGE(ERROR, "Memory allocation failed\n");
        goto out;
    }
    result->u.i = read_number;

out:
    return result;
}

static int pcid_handle_message(libxl__gc *gc, const libxl__json_object *request,
                               libxl__json_object **result)
{
    const libxl__json_object *command_obj;
    char *command_name;

    command_obj = libxl__json_map_get(VCHAN_MSG_EXECUTE, request, JSON_ANY);
    if (!command_obj) {
        LOGE(ERROR, "Execution command not found\n");
        return ERROR_FAIL;
    }
    command_name = command_obj->u.string;

    if (strcmp(command_name, PCID_CMD_LIST) == 0)
       *result = process_ls_cmd(gc, request);
    else if (strcmp(PCID_CMD_WRITE, command_name) == 0)
       *result = process_write_cmd(gc, request);
    else if (strcmp(command_name, PCID_CMD_READ_HEX) == 0)
        *result = process_read_hex_cmd(gc, request);
    else
        return ERROR_NOTFOUND;

    if (!result)
        return ERROR_FAIL;

    return 0;
}

static char *pcid_prepare_reply(libxl__gc *gc, const char *cmd,
                                libxl__json_object *result, int id)
{
    yajl_gen hand = NULL;
    /* memory for 'buf' is owned by 'hand' */
    const unsigned char *buf;
    libxl_yajl_length len;
    yajl_gen_status s;
    char *ret = NULL;
    int rc;

    hand = libxl_yajl_gen_alloc(NULL);
    if (!hand) {
        LOGE(ERROR, "Error with hand allocation\n");
        goto out;
    }

#if HAVE_YAJL_V2
    /* Disable beautify for data */
    yajl_gen_config(hand, yajl_gen_beautify, 0);
#endif

    yajl_gen_map_open(hand);
    if ( !result )
        libxl__yajl_gen_asciiz(hand, VCHAN_MSG_ERROR);
    else {
        libxl__yajl_gen_asciiz(hand, VCHAN_MSG_RETURN);
        rc = libxl__json_object_to_yajl_gen(gc, hand, result);
        if (rc)
            goto get_buf_fail;
    }
    libxl__yajl_gen_asciiz(hand, PCID_MSG_FIELD_ID);
    yajl_gen_integer(hand, id);
    yajl_gen_map_close(hand);

    s = yajl_gen_get_buf(hand, &buf, &len);
    if (s != yajl_gen_status_ok) {
        goto get_buf_fail;
    }

    ret = libxl__sprintf(gc, "%*.*s" END_OF_MESSAGE, (int)len, (int)len, buf);

get_buf_fail:
    yajl_gen_free(hand);
out:

    return ret;
}

int libxl_pcid_process(libxl_ctx *ctx)
{
    GC_INIT(ctx);
    struct vchan_info *vchan;
    char *xs_path;
    char *domid_str;
    int ret = 0;

    domid_str = xs_read(ctx->xsh, 0, "domid", NULL);
    if (!domid_str) {
        LOGE(ERROR, "Can't read own domid\n");
	ret = -ENOENT;
	goto out;
    }

    vchan = libxl__zalloc(gc, sizeof(*vchan));
    xs_path = GCSPRINTF(PCID_XS_DIR"%s"PCID_XS_PATH, domid_str);
    free(domid_str);

    vchan->state = vchan_get_instance(gc, DOM0_ID, xs_path, VCHAN_SERVER);
    if (!(vchan->state)) {
        ret = -1;
        goto out;
    }

    vchan->handle_msg = pcid_handle_message;
    vchan->prepare_cmd = pcid_prepare_reply;
    vchan->receive_buf_size = PCI_RECEIVE_BUFFER_SIZE;
    vchan->max_buf_size = PCI_MAX_SIZE_RX_BUF;

    while (true) {
        ret = vchan_process_command(gc, vchan);
        if (ret < 0)
            break;
    }

out:
    GC_FREE;
    return ret;
}
