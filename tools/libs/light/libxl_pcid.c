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
    int ret = 0;

    vchan = libxl__zalloc(gc, sizeof(*vchan));
    xs_path = GCSPRINTF(PCID_XS_DIR"%d"PCID_XS_PATH, DOM0_ID);

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
