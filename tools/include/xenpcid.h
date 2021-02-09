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

#ifndef XENPCID_H
#define XENPCID_H

#define XENPCID_SERVER              1

#define XENPCID_XS_PATH             "/local/domain/%d/data/pcid-vchan"

#define XENPCID_END_OF_MESSAGE      "\r\n"

#define XENPCID_MSG_EXECUTE         "execute"
#define XENPCID_MSG_RETURN          "return"
#define XENPCID_MSG_ERROR           "error"

#define XENPCID_MSG_FIELD_ID        "id"
#define XENPCID_MSG_FIELD_ARGS      "arguments"

#define XENPCID_CMD_LIST            "ls"
#define XENPCID_CMD_DIR_ID          "dir_id"

#define XENPCID_PCIBACK_DRIVER      "pciback_driver"

#endif /* XENPCID_H */

/*
 * Local variables:
 *  mode: C
 *  c-file-style: "linux"
 *  indent-tabs-mode: t
 *  c-basic-offset: 8
 *  tab-width: 8
 * End:
 */
