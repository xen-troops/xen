/*
 * Vchan support for JSON messages processing
 *
 * Copyright (C) 2021 EPAM Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_osdeps.h" /* must come before any other headers */

#include "libxl_internal.h"
#include "libxl_vchan.h"

#define VCHAN_EOM       "\r\n"
/*
 * http://xenbits.xen.org/docs/unstable/misc/xenstore-paths.html
 * 1.4.4 Domain Controlled Paths
 * 1.4.4.1 ~/data [w]
 * A domain writable path. Available for arbitrary domain use.
 */
#define VCHAN_SRV_DIR   "/local/domain"

struct vchan_state {
    struct libxenvchan *ctrl;

    /* Server domain ID. */
    libxl_domid domid;

    /* XenStore path of the server with the ring buffer and event channel. */
    char *xs_path;

    int select_fd;

    /* GC used for state's lifetime allocations, such as rx_buf. */
    libxl__gc *gc;
    /* Receive buffer. */
    char *rx_buf;
    /* Current allocated size. */
    size_t rx_buf_size;
    /* Actual data in the buffer. */
    size_t rx_buf_used;

    /* YAJL generator used to parse and create requests/replies. */
    yajl_gen gen;
};

int libxl__vchan_field_add_string(libxl__gc *gc, yajl_gen gen,
                                  const char *field, char *val)
{
    libxl__json_object *result;

    libxl__yajl_gen_asciiz(gen, field);
    result = libxl__json_object_alloc(gc, JSON_STRING);
    result->u.string = val;
    return libxl__json_object_to_yajl_gen(gc, gen, result);
}

static libxl__json_object *libxl__vchan_arg_new(libxl__gc *gc,
                                                libxl__json_node_type type,
                                                libxl__json_object *args,
                                                char *key)
{
    libxl__json_map_node *arg;
    libxl__json_object *obj;

    obj = libxl__json_object_alloc(gc, type);

    GCNEW(arg);

    arg->map_key = key;
    arg->obj = obj;

    flexarray_append(args->u.map, arg);

    return obj;
}

void libxl__vchan_arg_add_string(libxl__gc *gc, libxl__json_object *args,
                                 char *key, char *val)
{
    libxl__json_object *obj = libxl__vchan_arg_new(gc, JSON_STRING, args, key);

    obj->u.string = val;
}

void libxl__vchan_arg_add_bool(libxl__gc *gc, libxl__json_object *args,
                               char *key, bool val)
{
    libxl__json_object *obj = libxl__vchan_arg_new(gc, JSON_BOOL, args, key);

    obj->u.b = val;
}

void libxl__vchan_arg_add_integer(libxl__gc *gc, libxl__json_object *args,
                                 char *key,  int val)
{
    libxl__json_object *obj = libxl__vchan_arg_new(gc, JSON_INTEGER, args, key);

    obj->u.i = val;
}

static void reset_yajl_generator(struct vchan_state *state)
{
    yajl_gen_clear(state->gen);
    yajl_gen_reset(state->gen, NULL);
}

void vchan_dump_gen(libxl__gc *gc, yajl_gen gen)
{
    const unsigned char *buf = NULL;
    size_t len = 0;

    yajl_gen_get_buf(gen, &buf, &len);
    LOG(DEBUG, "%s\n", buf);
}

void vchan_dump_state(libxl__gc *gc, struct vchan_state *state)
{
    vchan_dump_gen(gc, state->gen);
}

/*
 * Find a JSON object and store it in o_r.
 * return ERROR_NOTFOUND if no object is found.
 */
static int vchan_get_next_msg(libxl__gc *gc, struct vchan_state *state,
                              libxl__json_object **o_r)
{
    size_t len;
    char *end = NULL;
    const size_t eoml = sizeof(VCHAN_EOM) - 1;
    libxl__json_object *o = NULL;

    if (!state->rx_buf_used)
        return ERROR_NOTFOUND;

    /* Search for the end of a message which is CRLF. */
    end = memmem(state->rx_buf, state->rx_buf_used, VCHAN_EOM, eoml);
    if (!end)
        return ERROR_NOTFOUND;

    len = (end - state->rx_buf) + eoml;

    LOGD(DEBUG, state->domid, "parsing %zuB: '%.*s'", len, (int)len,
         state->rx_buf);

    /* Replace \r by \0 so that libxl__json_parse can use strlen */
    state->rx_buf[len - eoml] = '\0';

    o = libxl__json_parse(gc, state->rx_buf);
    state->rx_buf_used -= len;
    if (!o) {
        LOGD(ERROR, state->domid, "Parse error");
        /*
         * In case of parsing error get back to a known state:
         * reset the buffer and continue reading.
         */
        return ERROR_INVAL;
    }

    memmove(state->rx_buf, state->rx_buf + len, state->rx_buf_used);

    LOGD(DEBUG, state->domid, "JSON object received: %s", JSON(o));

    *o_r = o;

    return 0;
}

static int vchan_process_packet(libxl__gc *gc, struct vchan_info *vchan,
                                libxl__json_object **resp_result)
{
    while (true) {
        struct vchan_state *state = vchan->state;
        int rc;
        ssize_t r;

        if (!libxenvchan_is_open(state->ctrl))
            return ERROR_FAIL;

        /* Check if the buffer still has space or increase its size. */
        if (state->rx_buf_size - state->rx_buf_used < vchan->receive_buf_size) {
            size_t newsize = state->rx_buf_size * 2 + vchan->receive_buf_size;

            if (newsize > vchan->max_buf_size) {
                LOGD(ERROR, state->domid,
                     "receive buffer is too big (%zu > %zu)",
                     newsize, vchan->max_buf_size);
                return ERROR_NOMEM;
            }

            state->rx_buf_size = newsize;
            state->rx_buf = libxl__realloc(state->gc, state->rx_buf,
                                           state->rx_buf_size);
        }

        do {
            libxl__json_object *msg;

            r = libxenvchan_read(state->ctrl,
                                 state->rx_buf + state->rx_buf_used,
                                 state->rx_buf_size - state->rx_buf_used);

            if (r < 0) {
                LOGED(ERROR, state->domid, "error reading");
                return ERROR_FAIL;
            } else if (r == 0)
                continue;

            LOG(DEBUG, "received %zdB: '%.*s'", r,
                (int)r, state->rx_buf + state->rx_buf_used);

            state->rx_buf_used += r;
            assert(state->rx_buf_used <= state->rx_buf_size);

            /* parse rx buffer to find one json object */
            rc = vchan_get_next_msg(gc, state, &msg);
            if ((rc == ERROR_INVAL) || (rc == ERROR_NOTFOUND))
                continue;
            if (rc)
                return rc;

            if (resp_result)
                return vchan->handle_response(gc, msg, resp_result);
            else {
                reset_yajl_generator(state);
                return vchan->handle_request(gc, state->gen, msg);
            }
        } while (libxenvchan_data_ready(state->ctrl));
    }

    return 0;
}

static int vchan_write(libxl__gc *gc, struct vchan_state *state, char *cmd)
{
    size_t len;
    int ret;

    len = strlen(cmd);
    while (len) {
        ret = libxenvchan_write(state->ctrl, cmd, len);
        if (ret < 0) {
            LOGE(ERROR, "vchan write failed");
            return ERROR_FAIL;
        }
        cmd += ret;
        len -= ret;
    }
    return 0;
}

libxl__json_object *vchan_send_command(libxl__gc *gc, struct vchan_info *vchan,
                                       char *cmd, libxl__json_object *args)
{
    libxl__json_object *result;
    char *request;
    int ret;

    reset_yajl_generator(vchan->state);
    request = vchan->prepare_request(gc, vchan->state->gen, cmd, args);
    if (!request)
        return NULL;

    ret = vchan_write(gc, vchan->state, request);
    if (ret < 0)
        return NULL;

    ret = vchan_write(gc, vchan->state, VCHAN_EOM);
    if (ret < 0)
        return NULL;

    ret = vchan_process_packet(gc, vchan, &result);
    if (ret < 0)
        return NULL;

    return result;
}

int vchan_process_command(libxl__gc *gc, struct vchan_info *vchan)
{
    char *json_str;
    int ret;

    ret = vchan_process_packet(gc, vchan, NULL);
    if (ret)
        return ret;

    json_str = vchan->prepare_response(gc, vchan->state->gen);
    if (!json_str)
        return ERROR_INVAL;

    ret = vchan_write(gc, vchan->state, json_str);
    if (ret)
        return ret;

    return vchan_write(gc, vchan->state, VCHAN_EOM);
}

static libxl_domid vchan_find_server(libxl__gc *gc, char *xs_dir, char *xs_file)
{
    char **domains;
    unsigned int i, n;
    libxl_domid domid = DOMID_INVALID;

    domains = libxl__xs_directory(gc, XBT_NULL, xs_dir, &n);
    if (!n)
        goto out;

    for (i = 0; i < n; i++) {
        const char *tmp;
        int d;

        if (sscanf(domains[i], "%d", &d) != 1)
            continue;

        tmp = libxl__xs_read(gc, XBT_NULL,
                             GCSPRINTF("%s/%d/data/%s", xs_dir, d, xs_file));
        /* Found the domain where the server lives. */
        if (tmp) {
            domid = d;
            break;
        }
    }

out:
    return domid;
}

static int vchan_init_client(libxl__gc *gc, struct vchan_state *state,
                             bool is_server)
{
    if (is_server) {
        state->ctrl = libxenvchan_server_init(NULL, state->domid,
                                              state->xs_path, 0, 0);
        if (!state->ctrl) {
            perror("Couldn't initialize vchan server");
            exit(1);
        }

    } else {
        state->ctrl = libxenvchan_client_init(CTX->lg, state->domid,
                                              state->xs_path);
        if (!state->ctrl) {
            LOGE(ERROR, "Couldn't initialize vchan client");
            return ERROR_FAIL;
        }
    }

    state->ctrl->blocking = 1;
    state->select_fd = libxenvchan_fd_for_select(state->ctrl);
    if (state->select_fd < 0) {
        LOGE(ERROR, "Couldn't read file descriptor for vchan client");
        return ERROR_FAIL;
    }

    LOG(DEBUG, "Initialized vchan %s, XenSore at %s",
        is_server ? "server" : "client", state->xs_path);

    return 0;
}

struct vchan_state *vchan_init_new_state(libxl__gc *gc, libxl_domid domid,
                                         char *vchan_xs_path, bool is_server)
{
    struct vchan_state *state;
    yajl_gen gen;
    int ret;

    gen = libxl_yajl_gen_alloc(NULL);
    if (!gen) {
        LOGE(ERROR, "Failed to allocate yajl generator");
        return NULL;
    }

#if HAVE_YAJL_V2
    /* Disable beautify for data */
    yajl_gen_config(gen, yajl_gen_beautify, 0);
#endif

    state = libxl__zalloc(gc, sizeof(*state));
    state->domid = domid;
    state->xs_path = vchan_xs_path;
    state->gc = gc;
    ret = vchan_init_client(gc, state, is_server);
    if (ret) {
        state = NULL;
        yajl_gen_free(gen);
    }

    state->gen = gen;

    return state;
}

char *vchan_get_server_xs_path(libxl__gc *gc, libxl_domid domid, char *srv_name)
{
    return GCSPRINTF(VCHAN_SRV_DIR "/%d/data/%s", domid, srv_name);
}

/*
 * Wait for the server to create the ring and event channel:
 * since the moment we create a XS folder to the moment we start
 * watching it the server may have already created the ring and
 * event channel entries. Thus, we cannot watch reliably here without
 * races, so poll for both entries to be created.
 */
static int vchan_wait_server_available(libxl__gc *gc, const char *xs_path)
{
    char *xs_ring, *xs_evt;
    int timeout_ms = 5000;

    xs_ring = GCSPRINTF("%s/ring-ref", xs_path);
    xs_evt = GCSPRINTF("%s/event-channel", xs_path);

    while (timeout_ms) {
        unsigned int len;
        void *file;
        int entries = 0;

        file = xs_read(CTX->xsh, XBT_NULL, xs_ring, &len);
        if (file) {
            entries++;
            free(file);
        }

        file = xs_read(CTX->xsh, XBT_NULL, xs_evt, &len);
        if (file) {
            entries++;
            free(file);
        }

        if (entries == 2)
            return 0;

        timeout_ms -= 10;
        usleep(10000);
    }

    return ERROR_TIMEDOUT;
}

struct vchan_state *vchan_new_client(libxl__gc *gc, char *srv_name)
{
    libxl_domid domid;
    char *xs_path, *vchan_xs_path;
    libxl_uuid uuid;
    libxl_ctx *ctx = libxl__gc_owner(gc);

    domid = vchan_find_server(gc, VCHAN_SRV_DIR, srv_name);
    if (domid == DOMID_INVALID) {
        LOGE(ERROR, "Can't find vchan server");
        return NULL;
    }

    xs_path = vchan_get_server_xs_path(gc, domid, srv_name);
    LOG(DEBUG, "vchan server at %s\n", xs_path);

    /* Generate unique client id. */
    libxl_uuid_generate(&uuid);

    vchan_xs_path = GCSPRINTF("%s/" LIBXL_UUID_FMT, xs_path,
                              LIBXL_UUID_BYTES((uuid)));

    if (!xs_mkdir(ctx->xsh, XBT_NULL, vchan_xs_path)) {
        LOG(ERROR, "Can't create xs_dir at %s", vchan_xs_path);
        return NULL;
    }

    if (vchan_wait_server_available(gc, vchan_xs_path)) {
        LOG(ERROR, "Failed to wait for the server to come up at %s",
            vchan_xs_path);
        return NULL;
    }

    return vchan_init_new_state(gc, domid, vchan_xs_path, false);
}

void vchan_fini_one(libxl__gc *gc, struct vchan_state *state)
{
    if (!state)
        return;

    LOG(DEBUG, "Closing vchan");
    libxenvchan_close(state->ctrl);

    yajl_gen_free(state->gen);
}
