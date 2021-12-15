/*
    Common definitions for JSON messages processing by vchan
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

#ifndef LIBXL_VCHAN_H
#define LIBXL_VCHAN_H

#include <libxenvchan.h>

struct vchan_state;

struct vchan_info {
    struct vchan_state *state;

    /* Process request and produce the result by adding json-objects to gen .*/
    int (*handle_request)(libxl__gc *gc, yajl_gen gen,
                      const libxl__json_object *request);
    /* Convert the prepared response into JSON string. */
    char *(*prepare_response)(libxl__gc *gc, yajl_gen gen);

    /* Prepare request as JSON string which will be sent. */
    char *(*prepare_request)(libxl__gc *gc, yajl_gen gen, char *request,
                             libxl__json_object *args);
    /* Handle response and produce the output suitable for the requester. */
    int (*handle_response)(libxl__gc *gc, const libxl__json_object *response,
                           libxl__json_object **result);

    /* Handle new client connection on the server side. */
    int (*handle_new_client)(libxl__gc *gc);

    /* Buffer info. */
    size_t receive_buf_size;
    size_t max_buf_size;
};

int libxl__vchan_field_add_string(libxl__gc *gc, yajl_gen hand,
                                  const char *field, char *val);

libxl__json_object *vchan_send_command(libxl__gc *gc, struct vchan_info *vchan,
                                       char *cmd, libxl__json_object *args);

void vchan_reset_generator(struct vchan_state *state);

int vchan_process_command(libxl__gc *gc, struct vchan_info *vchan);

char *vchan_get_server_xs_path(libxl__gc *gc, libxl_domid domid, char *srv_name);

struct vchan_state *vchan_init_new_state(libxl__gc *gc, libxl_domid domid,
                                         char *vchan_xs_path, bool is_server);

struct vchan_state *vchan_new_client(libxl__gc *gc, char *srv_name);

void vchan_fini_one(libxl__gc *gc, struct vchan_state *state);

void vchan_dump_state(libxl__gc *gc, struct vchan_state *state);
void vchan_dump_gen(libxl__gc *gc, yajl_gen gen);

#endif /* LIBXL_VCHAN_H */

/*
 * Local variables:
 *  mode: C
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
