/*
    Pcid daemon that acts as a server for the client in the libxl PCI

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

#include <libxl_utils.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <pcid.h>
#include <xenstore.h>

/*
 * TODO: Running this code in multi-threaded environment
 * Now the code is designed so that only one request to the server
 * from the client is made in one domain. In the future, it is necessary
 * to take into account cases when from different domains there can be
 * several requests from a client at the same time. Therefore, it will be
 * necessary to regulate the multithreading of processes for global variables.
 */

int main_pcid(int argc, char *argv[])
{
    int opt = 0, daemonize = 1, ret;
    const char *pidfile = NULL;
    static const struct option opts[] = {
        {"pidfile", 1, 0, 'p'},
        COMMON_LONG_OPTS,
        {0, 0, 0, 0}
    };

    SWITCH_FOREACH_OPT(opt, "fp:", opts, "pcid", 0) {
    case 'f':
        daemonize = 0;
        break;
    case 'p':
        pidfile = optarg;
        break;
    }

    if (daemonize) {
        ret = do_daemonize("xlpcid", pidfile);
        if (ret) {
            ret = (ret == 1) ? 0 : ret;
            goto out_daemon;
        }
    }

    libxl_pcid_process(ctx);

    ret = 0;

out_daemon:
    exit(ret);
}
