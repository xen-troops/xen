/*
    Xenpcid daemon that acts as a server for the client in the libxl PCI

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <libxenvchan.h>
#include <xenpcid.h>
#include <xenstore.h>

#include <libxl.h>
#include <libxl_json.h>
#include <dirent.h>
#include "pcid.h"

#include <sys/types.h>
#include <sys/stat.h>

/* #define RUN_STANDALONE */
#define BUFSIZE 4096
/*
 * TODO: Running this code in multi-threaded environment
 * Now the code is designed so that only one request to the server
 * from the client is made in one domain. In the future, it is necessary
 * to take into account cases when from different domains there can be
 * several requests from a client at the same time. Therefore, it will be
 * necessary to regulate the multithreading of processes for global variables.
 */
char inbuf[BUFSIZE];
char outbuf[BUFSIZE];
int insiz = 0;
int outsiz = 0;
struct libxenvchan *ctrl;

static void *pcid_zalloc(size_t size)
{
    void *ptr = calloc(size, 1);

    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }

    return ptr;
}

static void free_pcid_obj_map(struct pcid__json_object *obj)
{
    if (obj->u.map)
    {
        unsigned int count;
        struct flexarray *map;

        map = obj->u.map;
        count = map->count;
        while (count--) {
            struct pcid__json_map_node *node;

            node = map->data[count];
            free(node->map_key);
            free(node->obj);
            free(node);
        }
        free(map);
    }
}

static void vchan_wr(char *msg)
{
    int ret, len;

    len = strlen(msg);
    while (len) {
        ret = libxenvchan_write(ctrl, msg, len);
        if (ret < 0) {
            fprintf(stderr, "vchan write failed\n");
            return ;
        }
        msg += ret;
        len -= ret;
    }
}

static int set_nonblocking(int fd, int nonblocking)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1)
        return -1;

    if (nonblocking)
        flags |= O_NONBLOCK;
    else
        flags &= ~O_NONBLOCK;

    if (fcntl(fd, F_SETFL, flags) == -1)
        return -1;

    return 0;
}

static yajl_gen_status pcid__yajl_gen_asciiz(yajl_gen hand, const char *str)
{
    return yajl_gen_string(hand, (const unsigned char *)str, strlen(str));
}

static void free_list(struct list_head *head)
{
    struct list_head* tmp;

    while (head != NULL) {
        tmp = head;
        head = head->next;
        free(tmp);
    }
}

static char *vchan_prepare_cmd(struct pcid__json_object *result,
                               int id)
{
    yajl_gen hand = NULL;
    /* memory for 'buf' is owned by 'hand' */
    const unsigned char *buf;
    libxl_yajl_length len;
    yajl_gen_status s;
    char *ret = NULL;
    struct list_head *resp_list;

    hand = libxl_yajl_gen_alloc(NULL);
    if (!hand) {
        fprintf(stderr, "Error with hand allocation\n");
        return NULL;
    }

#if HAVE_YAJL_V2
    /* Disable beautify for data */
    yajl_gen_config(hand, yajl_gen_beautify, 0);
#endif

    yajl_gen_map_open(hand);

    if ( !result ) {
        pcid__yajl_gen_asciiz(hand, XENPCID_MSG_ERROR);
    } else {
        pcid__yajl_gen_asciiz(hand, XENPCID_MSG_RETURN);
        if (result->type == JSON_LIST) {
            yajl_gen_array_open(hand);
            if (result->u.list) {
                resp_list = result->u.list;
                while (resp_list) {
                    pcid__yajl_gen_asciiz(hand, resp_list->val);
                    free(resp_list->val);
                    resp_list = resp_list->next;
                }
                free_list(result->u.list);
            }
            yajl_gen_array_close(hand);
        } else if (result->type == JSON_STRING) {
            if (result->u.string) {
                pcid__yajl_gen_asciiz(hand, result->u.string);
                free(result->u.string);
            } else
                pcid__yajl_gen_asciiz(hand, "success");
        } else {
            fprintf(stderr, "Unknown result type\n");
        }
        free(result);
    }
    pcid__yajl_gen_asciiz(hand, XENPCID_MSG_FIELD_ID);
    yajl_gen_integer(hand, id);
    yajl_gen_map_close(hand);

    s = yajl_gen_get_buf(hand, &buf, &len);
    if (s != yajl_gen_status_ok) {
        goto out;
    }

    ret = pcid_zalloc((int)len + strlen(XENPCID_END_OF_MESSAGE));
    sprintf(ret, "%*.*s" XENPCID_END_OF_MESSAGE,
            (int)len, (int)len, buf);

    yajl_gen_free(hand);
out:
    return ret;
}

static int handle_ls_command(char *dir_name, struct list_head **result)
{
    struct list_head *dirs = NULL, *head = NULL, *prev =NULL;
    struct dirent *de;
    DIR *dir = NULL;

    head = (struct list_head*)pcid_zalloc(sizeof(struct list_head));
    dirs = head;

    if (strcmp(XENPCID_PCIBACK_DRIVER, dir_name) == 0) {
        dir = opendir(SYSFS_PCIBACK_DRIVER);
    } else {
        fprintf(stderr, "Unknown directory: %s\n", dir_name);
        goto out;
    }

    if (dir == NULL) {
        if (errno == ENOENT) {
            fprintf(stderr,  "Looks like pciback driver not loaded\n");
        } else {
            fprintf(stderr, "Couldn't open\n");
        }
        goto out;
    }

    while((de = readdir(dir))) {
        if (!dirs)
        {
            dirs = (struct list_head*)pcid_zalloc(sizeof(struct list_head));
            prev->next = dirs;
        }
        dirs->val = strdup(de->d_name);
        prev = dirs;
        dirs = dirs->next;
    }

    closedir(dir);

    *result = head;

    return 0;

out:
    fprintf(stderr, "LS command failed\n");
    return 1;
}

static int flexarray_grow(struct flexarray *array, int extents)
{
    int newsize;
    void *newptr;

    newsize = array->size + extents;
    newptr = realloc(array->data, newsize);
    if (newptr)
       array->data = newptr;
    else {
        fprintf(stderr, "Memory reallocation for data in array failed\n");
        return 1;
    }
    array->size += extents;

    return 0;
}

static int flexarray_set(struct flexarray *array, unsigned int idx, void *ptr)
{
    if (idx >= array->size) {
        int newsize;

        if (!array->autogrow)
            return 1;
        newsize = (array->size * 2 < idx) ? idx + 1 : array->size * 2;
        if (flexarray_grow(array, newsize - array->size))
            return 1;
    }
    if (idx + 1 > array->count)
        array->count = idx + 1;
    array->data[idx] = ptr;

    return 0;
}

static int flexarray_append(struct flexarray *array, void *ptr)
{
    return flexarray_set(array, array->count, ptr);
}

static struct flexarray *flexarray_make(int size, int autogrow)
{
    struct flexarray *array;

    array = pcid_zalloc(sizeof(*array));
    array->size = size;
    array->autogrow = autogrow;
    array->count = 0;
    array->data = calloc(size, sizeof(*(array->data)));

    return array;
}

static int flexarray_get(struct flexarray *array, int idx, void **ptr)
{
    if (idx >= array->size)
        return 1;
    *ptr = array->data[idx];
    return 0;
}

static inline bool pcid__json_object_is_map(const struct pcid__json_object *o)
{
    return o != NULL && o->type == JSON_MAP;
}

static struct pcid__json_object *pcid__json_map_get(const char *key,
                                                    const struct pcid__json_object *o,
                                                    enum pcid__json_node_type expected_type)
{
    struct flexarray *maps = NULL;
    int idx = 0;
    struct pcid__json_map_node *node = NULL;

    if (pcid__json_object_is_map(o)) {
        maps = o->u.map;
        for (idx = 0; idx < maps->count; idx++) {
            if (flexarray_get(maps, idx, (void**)&node) != 0) {
                return NULL;
            }

            if (strcmp(key, node->map_key) == 0) {
                if (expected_type == JSON_ANY
                    || (node->obj && (node->obj->type & expected_type))) {
                    return node->obj;
                } else
                    return NULL;
            }
        }
    }
    return NULL;
}

static int handle_write_cmd(char *sysfs_path, char *pci_info)
{
    int rc, fd;

    fd = open(sysfs_path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "Couldn't open %s\n", sysfs_path);
        return ERROR_FAIL;
    }

    rc = write(fd, pci_info, strlen(pci_info));
    close(fd);
    if (rc < 0) {
        fprintf(stderr, "write to %s returned %d\n", sysfs_path, rc);
        return ERROR_FAIL;
    }

    return 0;
}

static inline bool pcid__json_object_is_array(const struct pcid__json_object *o)
{
    return o != NULL && o->type == JSON_ARRAY;
}

static int pcid__json_object_append_to(struct pcid__json_object *obj,
                                       struct pcid__yajl_ctx *ctx_yajl)
{
    struct pcid__json_object *dst = ctx_yajl->current;

    if (dst) {
        switch (dst->type) {
        case JSON_MAP: {
            struct pcid__json_map_node *last = NULL;

            if (dst->u.map->count == 0) {
                fprintf(stderr,
                        "Try to add a value to an empty map (with no key)\n");
                return ERROR_FAIL;
            }
            flexarray_get(dst->u.map, dst->u.map->count - 1, (void**)&last);
            last->obj = obj;
            break;
        }
        case JSON_ARRAY:
            flexarray_append(dst->u.array, obj);
            break;
        default:
            fprintf(stderr,
                    "Try append an object is not a map/array (%i)\n",
                    dst->type);
            return ERROR_FAIL;
        }
    }

    obj->parent = dst;

    if (pcid__json_object_is_map(obj) || pcid__json_object_is_array(obj))
        ctx_yajl->current = obj;
    if (ctx_yajl->head == NULL)
        ctx_yajl->head = obj;

    return 0;
}

static int json_callback_string(void *opaque, const unsigned char *str,
                                long unsigned int len)
{
    struct pcid__yajl_ctx *ctx = opaque;
    char *t = NULL;
    struct pcid__json_object *obj = NULL;

    t = pcid_zalloc(len + 1);
    strncpy(t, (const char *) str, len);
    t[len] = 0;

    obj = pcid_zalloc(sizeof(*obj));
    obj->u.string = t;

    if (pcid__json_object_append_to(obj, ctx))
        return 0;

    return 1;
}

static struct pcid__json_object *pcid__json_object_alloc(enum pcid__json_node_type type)
{
    struct pcid__json_object *obj;

    obj = pcid_zalloc(sizeof(*obj));
    obj->type = type;
    obj->u.map = NULL;
    obj->u.array = NULL;
    obj->u.string = NULL;

    if (type == JSON_MAP || type == JSON_ARRAY) {
        struct flexarray *array = flexarray_make(1, 1);

        if (type == JSON_MAP)
            obj->u.map = array;
        else
            obj->u.array = array;
    }

    return obj;
}

static int json_callback_map_key(void *opaque, const unsigned char *str,
                                 libxl_yajl_length len)
{
    struct pcid__yajl_ctx *ctx_yajl = opaque;
    char *t = NULL;
    struct pcid__json_object *obj = ctx_yajl->current;

    t = pcid_zalloc(len + 1);

    strncpy(t, (const char *) str, len);
    t[len] = 0;

    if (pcid__json_object_is_map(obj)) {
        struct pcid__json_map_node *node;

        node = pcid_zalloc(sizeof(*node));
        node->map_key = t;
        node->obj = NULL;

        flexarray_append(obj->u.map, node);
    } else {
        fprintf(stderr, "Current json object is not a map\n");
        return 0;
    }

    return 1;
}

static int json_callback_start_map(void *opaque)
{
    struct pcid__yajl_ctx *ctx = opaque;
    struct pcid__json_object *obj = NULL;

    obj = pcid__json_object_alloc(JSON_MAP);

    if (pcid__json_object_append_to(obj, ctx))
        return 0;

    return 1;
}

static int json_callback_end_map(void *opaque)
{
    struct pcid__yajl_ctx *ctx = opaque;

    if (ctx->current) {
        ctx->current = ctx->current->parent;
    } else {
        fprintf(stderr,
                "No current pcid__json_object, cannot use his parent\n");
        return 0;
    }

    return 1;
}

static yajl_callbacks callbacks = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    json_callback_string,
    json_callback_start_map,
    json_callback_map_key,
    json_callback_end_map,
    NULL,
    NULL,
};

static void yajl_ctx_free(struct pcid__yajl_ctx *yajl_ctx)
{
    if (yajl_ctx->hand) {
        yajl_free(yajl_ctx->hand);
        yajl_ctx->hand = NULL;
    }
}

static struct pcid__json_object *pcid__json_parse(const char *s)
{
    yajl_status status;
    struct pcid__yajl_ctx yajl_ctx;
    struct pcid__json_object *o = NULL;
    unsigned char *str = NULL;

    memset(&yajl_ctx, 0, sizeof (yajl_ctx));
    yajl_ctx.hand = libxl__yajl_alloc(&callbacks, NULL, &yajl_ctx);

    status = yajl_parse(yajl_ctx.hand, (const unsigned char *)s, strlen(s));
    if (status != yajl_status_ok) {
        str = yajl_get_error(yajl_ctx.hand, 1, (const unsigned char*)s, strlen(s));
        fprintf(stderr, "yajl_parse error: %s\n", str);
        yajl_free_error(yajl_ctx.hand, str);
        goto out;
    }

    status = yajl_complete_parse(yajl_ctx.hand);
    if (status != yajl_status_ok) {
        str = yajl_get_error(yajl_ctx.hand, 1, (const unsigned char*)s, strlen(s));
        fprintf(stderr, "yajl_complete_parse error: %s\n", str);
        yajl_free_error(yajl_ctx.hand, str);
        goto out;
    }

    o = yajl_ctx.head;

    yajl_ctx.head = NULL;

    yajl_ctx_free(&yajl_ctx);
    return o;

out:
    str = yajl_get_error(yajl_ctx.hand, 1, (const unsigned char*)s, strlen(s));
    fprintf(stderr, "yajl error: %s\n", str);
    yajl_free_error(yajl_ctx.hand, str);
    yajl_ctx_free(&yajl_ctx);
    return NULL;
}

/*
 * Find a JSON object and store it in o_r.
 * return ERROR_NOTFOUND if no object is found.
 */
static int vchan_get_next_msg(struct vchan_state *state,
                              struct pcid__json_object **o_r)
{
    size_t len;
    char *end = NULL;
    const char eom[] = XENPCID_END_OF_MESSAGE;
    const size_t eoml = sizeof(eom) - 1;
    struct pcid__json_object *o = NULL;

    if (!state->rx_buf_used) {
        fprintf(stderr, "Buffer is empty\n");
        return ERROR_NOTFOUND;
    }

    /* Search for the end of a message: "\r\n" */
    end = memmem(state->rx_buf, state->rx_buf_size, eom, eoml);
    if (!end) {
        fprintf(stderr, "End of the message not found\n");
        return ERROR_NOTFOUND;
    }
    len = (end - state->rx_buf) + eoml;

    fprintf(stderr, "parsing %luB: '%.*s'\n", len, (int)len,
         state->rx_buf);

    /* Replace \r by \0 so that pcid__json_parse can use strlen */
    state->rx_buf[len - eoml] = '\0';
    o = pcid__json_parse(state->rx_buf);

    if (!o) {
        fprintf(stderr, "Parse error\n");
        return ERROR_PROTOCOL_ERROR_PCID;
    }

    *o_r = o;

    outsiz -= len;
    if (outsiz) {
        memmove(outbuf, outbuf + len, outsiz);
        insiz += len;
    } else
        memset(outbuf, 0, BUFSIZE);

    return 0;
}

static struct pcid__json_object *process_ls_cmd(struct pcid__json_object *resp)
{
    struct pcid__json_object *result = NULL, *args, *dir_id;
    char *dir_name;
    struct list_head *dir_list = NULL;
    int ret;

    args = pcid__json_map_get(XENPCID_MSG_FIELD_ARGS, resp, JSON_MAP);
    if (!args)
        goto out;
    dir_id = pcid__json_map_get(XENPCID_CMD_DIR_ID, args, JSON_ANY);
    if (!dir_id)
        goto free_args;
    dir_name = dir_id->u.string;

    ret = handle_ls_command(dir_name, &dir_list);
    free(dir_name);
    if (ret)
        goto free_args;

    result = pcid__json_object_alloc(JSON_LIST);
    result->u.list = dir_list;

free_args:
    free_pcid_obj_map(args);
out:
    return result;
}

static struct pcid__json_object *process_write_cmd(struct pcid__json_object *resp)
{
    struct pcid__json_object *result = NULL, *args, *dir_id, *pci_path, *pci_info;
    char *full_path;
    int ret;

    args = pcid__json_map_get(XENPCID_MSG_FIELD_ARGS, resp, JSON_MAP);
    if (!args)
        goto out;
    dir_id = pcid__json_map_get(XENPCID_CMD_DIR_ID, args, JSON_ANY);
    if (!dir_id)
        goto free_args;
    pci_path = pcid__json_map_get(XENPCID_CMD_PCI_PATH, args, JSON_ANY);
    if (!pci_path)
        goto free_dir_id;
    pci_info = pcid__json_map_get(XENPCID_CMD_PCI_INFO, args, JSON_ANY);
    if (!pci_info)
        goto free_pci_path;

    if (strcmp(dir_id->u.string, XENPCID_PCI_DEV) == 0) {
        full_path = (char *)pcid_zalloc(strlen(SYSFS_PCI_DEV) +
                                        strlen(pci_path->u.string) + 1);
        sprintf(full_path, SYSFS_PCI_DEV"%s", pci_path->u.string);
    } else if (strcmp(dir_id->u.string, XENPCID_PCIBACK_DRIVER) == 0){
        full_path = (char *)pcid_zalloc(strlen(SYSFS_PCIBACK_DRIVER) +
                                        strlen(pci_path->u.string) + 1);
        sprintf(full_path, SYSFS_PCIBACK_DRIVER"%s", pci_path->u.string);
    } else if (strcmp(dir_id->u.string, SYSFS_DRIVER_PATH) == 0){
        full_path = pci_path->u.string;
    } else {
        fprintf(stderr, "Unknown write directory %s\n", dir_id->u.string);
        goto free_pci_info;
    }
    ret = handle_write_cmd(full_path, pci_info->u.string);
    if (strcmp(dir_id->u.string, SYSFS_DRIVER_PATH) != 0)
        free(full_path);
    if (ret != 0)
        goto free_pci_info;

    result = pcid__json_object_alloc(JSON_STRING);

free_pci_info:
    free(pci_info->u.string);
free_pci_path:
    free(pci_path->u.string);
free_dir_id:
    free(dir_id->u.string);
free_args:
    free_pcid_obj_map(args);
out:
    return result;
}

static int vchan_handle_message(struct vchan_state *state,
                                struct pcid__json_object *resp,
                                struct pcid__json_object **result)
{
    struct pcid__json_object *command_obj;
    char *command_name;

    command_obj = pcid__json_map_get(XENPCID_MSG_EXECUTE, resp, JSON_ANY);
    command_name = command_obj->u.string;

    if (strcmp(command_name, XENPCID_CMD_LIST) == 0)
        (*result) = process_ls_cmd(resp);
    else if (strcmp(XENPCID_CMD_WRITE, command_name) == 0)
        (*result) = process_write_cmd(resp);
    else
        fprintf(stderr, "Unknown command\n");
    free(command_name);

    if (!(*result)) {
        fprintf(stderr, "Message handling failed\n");
        return 1;
    }

    return 0;
}

static int vchan_process_message(struct vchan_state *state,
                                 struct pcid__json_object **result)
{
    int rc;
    struct pcid__json_object *o = NULL, *reply = NULL;

    /* parse rx buffer to find one json object */
    rc = vchan_get_next_msg(state, &o);
    if (rc == ERROR_NOTFOUND) {
        perror("Message not found\n");
        return rc;
    }

    rc = vchan_handle_message(state, o, &reply);
    free_pcid_obj_map(o);
    free(o);

    if (rc == 0)
        *result = reply;

    return 0;
}

static struct vchan_state *vchan_get_instance(void)
{
    static struct vchan_state *state = NULL;

    if (state)
        return state;

    state = pcid_zalloc(sizeof(*state));

    return state;
}

static void vchan_receive_command(struct vchan_state *state)
{
    struct pcid__json_object *result = NULL;
    char *reply;
    int ret;

    state->rx_buf = outbuf;
    state->rx_buf_size = outsiz;
    state->rx_buf_used = outsiz;
    ret = vchan_process_message(state, &result);

    reply = vchan_prepare_cmd(result, 0);
    if (!reply) {
        fprintf(stderr, "Reply preparing failed\n");
        return;
    }

    vchan_wr(reply);
    free(reply);
}

/* Borrowed daemonize from xenstored - Initially written by Stevens. */
static void daemonize(void)
{
    pid_t pid;

    if ( (pid = fork()) < 0 )
        exit(1);

    if ( pid != 0 )
        exit(0);

    setsid();

    if ( (pid = fork()) < 0 )
        exit(1);

    if ( pid != 0 )
        exit(0);

    if ( chdir("/") == -1 )
        exit(1);

    umask(0);
}

int main(int argc, char *argv[])
{
    int ret, rsiz, wsiz;
    int libxenvchan_fd;
    uint32_t domid;
    char *domid_str, vchan_path[100];
    struct xs_handle *xs;
    struct vchan_state *vchan;

    if (argc == 2 && strcmp(argv[1], FOREGROUND_OPT) == 0)
        daemonize();

    xs = xs_open(0);
    if (!xs)
        perror("XS opening ERROR");;

    domid_str = xs_read(xs, XBT_NULL, "domid", NULL);
    domid = atoi(domid_str);
    free(domid_str);
    free(xs);

    rsiz = 0;
    wsiz = 0;
    sprintf(vchan_path, XENPCID_XS_PATH, domid);
    ctrl = libxenvchan_server_init(NULL, DOM0_ID, vchan_path, rsiz, wsiz);
    if (!ctrl) {
        perror("Libxenvchan server init failed\n");
        exit(1);
    }

    vchan = vchan_get_instance();
    if (!vchan)
        perror("Vchan creation failed\n");

    vchan->domid = DOM0_ID;
    vchan->xs_path = vchan_path;
    vchan->ctrl = ctrl;

    libxenvchan_fd = libxenvchan_fd_for_select(ctrl);
    vchan->select_fd = libxenvchan_fd;

    for (;;) {
        fd_set rfds;
        fd_set wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        if (insiz != BUFSIZE)
            FD_SET(0, &rfds);
        if (outsiz)
            FD_SET(1, &wfds);
        FD_SET(libxenvchan_fd, &rfds);
        ret = select(libxenvchan_fd + 1, &rfds, &wfds, NULL, NULL);
        if (ret < 0) {
            fprintf(stderr, "Error occured during the libxenvchan fd monitoring\n");
            goto exit;
        }
        if (FD_ISSET(0, &rfds)) {
            ret = read(0, inbuf + insiz, BUFSIZE - insiz);
            if (ret < 0 && errno != EAGAIN)
                goto exit;
            if (ret == 0) {
                while (insiz) {
                    libxenvchan_wait(ctrl);
                }
                goto out;
            }
            if (ret)
                insiz += ret;
        }
        if (FD_ISSET(libxenvchan_fd, &rfds))
            libxenvchan_wait(ctrl);
        if (FD_ISSET(1, &wfds))
            vchan_receive_command(vchan);
        while (libxenvchan_data_ready(ctrl) && outsiz < BUFSIZE) {
            ret = libxenvchan_read(ctrl, outbuf + outsiz, BUFSIZE - outsiz);
            if (ret < 0)
                goto exit;
            outsiz += ret;
            vchan_receive_command(vchan);
            while (!libxenvchan_data_ready(ctrl))
                libxenvchan_wait(ctrl);
        }
        if (!libxenvchan_is_open(ctrl)) {
            if (set_nonblocking(1, 0))
                goto exit;
            while (outsiz)
                vchan_receive_command(vchan);
            goto out;
        }
    }

out:
    free(vchan);
    return 0;

exit:
    free(vchan);
    exit(1);
}
