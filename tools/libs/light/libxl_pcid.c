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

#include <xenstore.h>

#include <libxl.h>
#include <libxl_json.h>
#include <dirent.h>

#include <pthread.h>
#include <pcid.h>

#define DOM0_ID 0

struct vchan_client {
    XEN_LIST_ENTRY(struct vchan_client) list;

    /* This is the watch entry fired for this client. */
    char **watch_ret;
    /* Length of the watch_ret[XS_WATCH_PATH]. */
    size_t watch_len;

    struct vchan_info info;

    /*
     * This context is used by the processing loop to create its own gc
     * and use it while processing commands, so we do not get OOM.
     */
    libxl_ctx *ctx;
    /* This gc holds all allocations made for the client needs itself. */
    libxl__gc gc[1];
    pthread_t run_thread;
};

static XEN_LIST_HEAD(clients_list, struct vchan_client) vchan_clients;

static pthread_mutex_t vchan_client_mutex;

static int make_error_reply(libxl__gc *gc, yajl_gen gen, char *desc,
                            char *command_name)
{
    int rc;

    rc = libxl__vchan_field_add_string(gc, gen, PCID_MSG_FIELD_RESP,
                                       command_name);
    if (rc)
        return rc;

    rc = libxl__vchan_field_add_string(gc, gen, PCID_MSG_FIELD_ERR,
                                       PCID_MSG_ERR_FAILED);
    if (rc)
        return rc;

    rc = libxl__vchan_field_add_string(gc, gen, PCID_MSG_FIELD_ERR_DESC, desc);
    if (rc)
        return rc;

    return 0;
}

static int process_list_assignable(libxl__gc *gc, yajl_gen gen,
                                   char *command_name,
                                   const struct libxl__json_object *request,
                                   struct libxl__json_object **response)
{
    struct dirent *de;
    DIR *dir = NULL;

    dir = opendir(SYSFS_PCIBACK_DRIVER);
    if (dir == NULL) {
        make_error_reply(gc, gen, strerror(errno), command_name);
        return ERROR_FAIL;
    }

    libxl__yajl_gen_asciiz(gen, PCID_MSG_FIELD_DEVICES);

    *response = libxl__json_object_alloc(gc, JSON_ARRAY);

    while ((de = readdir(dir))) {
        unsigned int dom, bus, dev, func;

        if (sscanf(de->d_name, PCID_SBDF_FMT, &dom, &bus, &dev, &func) != 4)
            continue;

        struct libxl__json_object *node =
            libxl__json_object_alloc(gc, JSON_STRING);
        node->u.string = de->d_name;
        flexarray_append((*response)->u.array, node);
    }

    closedir(dir);

    return 0;
}

static int pcid_handle_request(libxl__gc *gc, yajl_gen gen,
                               const libxl__json_object *request)
{
    const libxl__json_object *command_obj;
    libxl__json_object *command_response;
    char *command_name;
    int ret = 0;

    yajl_gen_map_open(gen);

    command_obj = libxl__json_map_get(PCID_MSG_FIELD_CMD, request, JSON_ANY);
    if (!command_obj) {
        /* This is an unsupported or bad request. */
        ret = make_error_reply(gc, gen, "Unsupported request or bad packet",
                               PCID_MSG_ERR_NA);
        goto out;
    }

    command_name = command_obj->u.string;

    if (strcmp(command_name, PCID_CMD_LIST_ASSIGNABLE) == 0)
       ret = process_list_assignable(gc, gen, command_name,
                                     request, &command_response);
    else {
        /*
         * This is an unsupported command: make a reply and proceed over
         * the error path.
         */
        ret = make_error_reply(gc, gen, "Unsupported command",
                               command_name);
        if (!ret)
            ret = ERROR_NOTFOUND;
    }

    if (ret) {
        /*
         * The command handler on error must provide a valid response,
         * so we don't need to add any other field below.
         */
        ret = 0;
        goto out;
    }

    ret = libxl__json_object_to_yajl_gen(gc, gen, command_response);
    if (ret)
        goto out;

    ret = libxl__vchan_field_add_string(gc, gen, PCID_MSG_FIELD_RESP,
                                        command_name);
    if (ret)
        goto out;

    ret = libxl__vchan_field_add_string(gc, gen, PCID_MSG_FIELD_ERR,
                                        PCID_MSG_ERR_OK);
out:
    yajl_gen_map_close(gen);

    vchan_dump_gen(gc, gen);

    return ret;
}

static char *pcid_prepare_response(libxl__gc *gc, yajl_gen gen)
{
    const unsigned char *buf;
    libxl_yajl_length len;
    yajl_gen_status sts;
    char *reply = NULL;

    sts = yajl_gen_get_buf(gen, &buf, &len);
    if (sts != yajl_gen_status_ok)
        goto out;

    reply = libxl__sprintf(gc, "%s", buf);

    vchan_dump_gen(gc, gen);

out:
    return reply;
}

static void server_fini_one(libxl__gc *gc, struct vchan_client *client)
{
    pthread_mutex_lock(&vchan_client_mutex);
    XEN_LIST_REMOVE(client, list);
    pthread_mutex_unlock(&vchan_client_mutex);

    GC_FREE;
    free(client);
}

static void *client_thread(void *arg)
{
    struct vchan_client *client = arg;

    while (true) {
        int ret;
        /*
         * libvchan uses garbage collector for processing requests,
         * so we create a new one each time we process a packet and
         * dispose it right away to prevent OOM.
         */
        GC_INIT(client->ctx);
        ret = vchan_process_command(gc, &client->info);
        GC_FREE;

        if ((ret == ERROR_NOTFOUND) || (ret == ERROR_INVAL))
            continue;
        if (ret < 0)
            break;
    }
    vchan_fini_one(client->gc, client->info.state);
    server_fini_one(client->gc, client);
    return NULL;
}

#define DEFAULT_THREAD_STACKSIZE (16 * 1024)
/* NetBSD doesn't have PTHREAD_STACK_MIN. */
#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 0
#endif

#define READ_THREAD_STACKSIZE                           \
    ((DEFAULT_THREAD_STACKSIZE < PTHREAD_STACK_MIN) ?   \
    PTHREAD_STACK_MIN : DEFAULT_THREAD_STACKSIZE)

static bool init_client_thread(libxl__gc *gc, struct vchan_client *new_client)
{

    sigset_t set, old_set;
    pthread_attr_t attr;
    static size_t stack_size;
#ifdef USE_DLSYM
    size_t (*getsz)(pthread_attr_t *attr);
#endif

    if (pthread_attr_init(&attr) != 0)
        return false;
    if (!stack_size) {
#ifdef USE_DLSYM
        getsz = dlsym(RTLD_DEFAULT, "__pthread_get_minstack");
        if (getsz)
            stack_size = getsz(&attr);
#endif
        if (stack_size < READ_THREAD_STACKSIZE)
            stack_size = READ_THREAD_STACKSIZE;
    }
    if (pthread_attr_setstacksize(&attr, stack_size) != 0) {
        pthread_attr_destroy(&attr);
        return false;
    }

    sigfillset(&set);
    pthread_sigmask(SIG_SETMASK, &set, &old_set);

    if (pthread_create(&new_client->run_thread, &attr, client_thread,
                       new_client) != 0) {
        pthread_sigmask(SIG_SETMASK, &old_set, NULL);
        pthread_attr_destroy(&attr);
        return false;
    }
    pthread_sigmask(SIG_SETMASK, &old_set, NULL);
    pthread_attr_destroy(&attr);

    return true;
}

static void init_new_client(libxl_ctx *ctx, libxl__gc *gc,
                            struct clients_list *list, char **watch_ret)
{
    struct vchan_client *new_client;
    char *xs_path = watch_ret[XS_WATCH_PATH];

    LOG(DEBUG, "New client at \"%s\"", xs_path);

    new_client = malloc(sizeof(*new_client));
    if (!new_client) {
        LOGE(ERROR, "Failed to allocate new client at \"%s\"", xs_path);
        return;
    }

    memset(new_client, 0, sizeof(*new_client));

    new_client->watch_ret = watch_ret;
    new_client->watch_len = strlen(xs_path);
    new_client->ctx = ctx;
    /*
     * Remember the GC of this client, so we can dispose its memory.
     * Use it from now on.
     */
    LIBXL_INIT_GC(new_client->gc[0], ctx);

    new_client->info.state = vchan_init_new_state(new_client->gc, DOM0_ID,
                                                  xs_path, true);
    if (!(new_client->info.state)) {
        LOGE(ERROR, "Failed to add new client at \"%s\"", xs_path);
        server_fini_one(new_client->gc, new_client);
        return;
    }

    new_client->info.handle_request = pcid_handle_request;
    new_client->info.prepare_response = pcid_prepare_response;
    new_client->info.receive_buf_size = PCI_RECEIVE_BUFFER_SIZE;
    new_client->info.max_buf_size = PCI_MAX_SIZE_RX_BUF;

    if (!init_client_thread(new_client->gc, new_client)) {
        LOGE(ERROR, "Failed to create client's thread for \"%s\"", xs_path);
        server_fini_one(new_client->gc, new_client);
        return;
    }

    pthread_mutex_lock(&vchan_client_mutex);
    XEN_LIST_INSERT_HEAD(&vchan_clients, new_client, list);
    pthread_mutex_unlock(&vchan_client_mutex);
}

static void terminate_clients(void)
{
    struct vchan_client *client;

    pthread_mutex_lock(&vchan_client_mutex);
    XEN_LIST_FOREACH(client, &vchan_clients, list) {
        pthread_join(client->run_thread, NULL);
    }
    pthread_mutex_unlock(&vchan_client_mutex);
}

int libxl_pcid_process(libxl_ctx *ctx)
{
    GC_INIT(ctx);
    char *xs_path, *str;
    char **watch_ret;
    unsigned int watch_num;
    libxl_domid domid;
    int ret;

    pthread_mutex_init(&vchan_client_mutex, NULL);

    str = xs_read(ctx->xsh, 0, "domid", NULL);
    if (!str) {
        LOGE(ERROR, "Can't read own domid\n");
        ret = -ENOENT;
        goto out;
    }

    ret = sscanf(str, "%d", &domid);
    free(str);
    if (ret != 1)
    {
        LOGE(ERROR, "Own domid is not an integer\n");
        ret = -EINVAL;
        goto out;
    }

    xs_path = vchan_get_server_xs_path(gc, domid, PCID_SRV_NAME);

    /* Recreate the base folder: remove all leftovers. */
    ret = libxl__xs_rm_checked(gc, XBT_NULL, xs_path);
    if (ret)
        goto out;

    if (!xs_mkdir(CTX->xsh, XBT_NULL, xs_path))
    {
        LOGE(ERROR, "xenstore mkdir failed: `%s'", xs_path);
        ret = ERROR_FAIL;
        goto out;
    }

    /* Wait for vchan client to create a new UUID under the server's folder. */
    if (!xs_watch(CTX->xsh, xs_path, PCID_XS_TOKEN)) {
        LOGE(ERROR, "xs_watch (%s) failed", xs_path);
        ret = ERROR_FAIL;
        goto out;
    }

    while ((watch_ret = xs_read_watch(CTX->xsh, &watch_num))) {
        struct vchan_client *client;
        size_t len;
        bool found;

        /*
         * Any change under the base directory will fire an event, so we need
         * to filter if this is indeed a new client or it is because vchan
         * server creates nodes under its UUID.
         *
         * Never try to instantiate a vchan server right under xs_path.
         */
        if (!strcmp(watch_ret[XS_WATCH_PATH], xs_path))
            continue;

        found = false;
        len = strlen(watch_ret[XS_WATCH_PATH]);

        pthread_mutex_lock(&vchan_client_mutex);
        XEN_LIST_FOREACH(client, &vchan_clients, list) {
            str = client->watch_ret[XS_WATCH_PATH];

            if (strstr(watch_ret[XS_WATCH_PATH], str)) {
                /*
                 * Base path is a substring of the current path, so it can be:
                 *  - a new node with different name, but starting with str
                 *  - a subnode under str, so it will have '/' after str
                 *  - same string
                 */
                if (len == client->watch_len) {
                    found = true;
                    break;
                }
                if (len > client->watch_len) {
                    if (watch_ret[XS_WATCH_PATH][client->watch_len] == '/') {
                        found = true;
                        break;
                    }
                }
            }
        }
        pthread_mutex_unlock(&vchan_client_mutex);

        if (!found)
            init_new_client(ctx, gc, &vchan_clients, watch_ret);
    }

    xs_unwatch(CTX->xsh, xs_path, PCID_XS_TOKEN);

out:
    terminate_clients();
    GC_FREE;
    pthread_mutex_destroy(&vchan_client_mutex);
    return ret;
}
