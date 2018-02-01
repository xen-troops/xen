/*
 * Copyright (C) 2016 EPAM Systems Inc.
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

#include <stdlib.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

int main_vkbattach(int argc, char **argv)
{
    int opt;
    int rc;
    uint32_t domid;
    libxl_device_vkb vkb;

    SWITCH_FOREACH_OPT(opt, "", NULL, "vkb-attach", 2) {
        /* No options */
    }

    libxl_device_vkb_init(&vkb);
    domid = find_domain(argv[optind++]);

    for (argv += optind, argc -= optind; argc > 0; ++argv, --argc) {
        rc = parse_vkb_config(&vkb, *argv);
        if (rc) goto out;
    }

    if (vkb.backend_type == LIBXL_VKB_BACKEND_UNKNOWN) {
        fprintf(stderr, "backend-type should be set\n");
        rc = ERROR_FAIL; goto out;
    }

    if (vkb.multi_touch_height || vkb.multi_touch_width ||
        vkb.multi_touch_num_contacts) {
        vkb.feature_multi_touch = true;
    }

    if (vkb.feature_multi_touch && !(vkb.multi_touch_height ||
        vkb.multi_touch_width || vkb.multi_touch_num_contacts)) {
        fprintf(stderr, "multi-touch-width, multi-touch-height, "
                        "multi-touch-num-contacts should be set\n");
        rc = ERROR_FAIL; goto out;
    }

    if (dryrun_only) {
        char *json = libxl_device_vkb_to_json(ctx, &vkb);
        printf("vkb: %s\n", json);
        free(json);
        goto out;
    }

    if (libxl_device_vkb_add(ctx, domid, &vkb, 0)) {
        fprintf(stderr, "libxl_device_vkb_add failed.\n");
        rc = ERROR_FAIL; goto out;
    }

    rc = 0;

out:
    libxl_device_vkb_dispose(&vkb);
    return rc;
}

int main_vkblist(int argc, char **argv)
{
    int opt;
    libxl_device_vkb *vkbs;
    libxl_vkbinfo vkbinfo;
    int nb, i;

    SWITCH_FOREACH_OPT(opt, "", NULL, "vkb-list", 1) {
        /* No options */
    }

    /*      Idx id     BE   Hdl  Sta  evch ref BE-path */
    printf("%-3s %-10s %-2s %-6s %-5s %-6s %6s %-30s\n",
           "Idx", "ID", "BE", "handle", "state", "evt-ch", "ref", "BE-path");
    for (argv += optind, argc -= optind; argc > 0; --argc, ++argv) {
        uint32_t domid = find_domain(*argv);
        vkbs = libxl_device_vkb_list(ctx, domid, &nb);
        if (!vkbs) {
            continue;
        }
        for (i = 0; i < nb; ++i) {
            if (!libxl_device_vkb_getinfo(ctx, domid, &vkbs[i], &vkbinfo)) {
                /* Idx BE */
                printf("%-3d %-10s %-2d ", vkbinfo.devid,
                                           vkbinfo.id ? vkbinfo.id : "",
                                           vkbinfo.backend_id);
                /* Hdl  Sta  evch ref  BE-path */
                printf("%6d %5d %6d %6d %-30s\n",
                        vkbinfo.devid, vkbinfo.state, vkbinfo.evtch,
                        vkbinfo.rref, vkbinfo.backend);
                libxl_vkbinfo_dispose(&vkbinfo);
            }
        }
        libxl_device_vkb_list_free(vkbs, nb);
    }
    return 0;
}

int main_vkbdetach(int argc, char **argv)
{
    uint32_t domid, devid;
    int opt, rc;
    libxl_device_vkb vkb;

    SWITCH_FOREACH_OPT(opt, "", NULL, "vkb-detach", 2) {
        /* No options */
    }

    domid = find_domain(argv[optind++]);
    devid = atoi(argv[optind++]);

    libxl_device_vkb_init(&vkb);

    if (libxl_devid_to_device_vkb(ctx, domid, devid, &vkb)) {
        fprintf(stderr, "Error: Device %d not connected.\n", devid);
        rc = ERROR_FAIL;
        goto out;
    }

    rc = libxl_device_vkb_remove(ctx, domid, &vkb, 0);
    if (rc) {
        fprintf(stderr, "libxl_device_vkb_remove failed.\n");
        rc = ERROR_FAIL;
        goto out;
    }

    rc = 0;

out:
    libxl_device_vkb_dispose(&vkb);
    return rc;
}


/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
