/*
 * Copyright (C) 2019 EPAM Systems Inc.
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

#include <xen/io/sndif.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

int main_guest_pm_set(int argc, char **argv)
{
    int opt;
    int rc;
    uint32_t domid;
    bool enable = false;
    bool disable = false;
    bool enabled;
    uint8_t opp_min, opp_max;
    char *endptr;

    SWITCH_FOREACH_OPT(opt, "ed", NULL, "guest-pm-set", 1) {
        case 'e':
            enable = true;
            break;
        case 'd':
            disable = true;
            break;
    }

    if (!enable && !disable) {
        fprintf(stderr, "Please specify either -e or -d\n");
        return EXIT_FAILURE;
    }

    if (enable && disable) {
        fprintf(stderr, "You can't specify both -e and -d at the same time\n");
        return EXIT_FAILURE;
    }

    domid = find_domain(argv[optind++]);

    rc = libxl_guest_pm_get(ctx, domid, &enabled, &opp_min, &opp_max);
    if (rc)
        return rc;

    if (disable && !enabled)
    {
        fprintf(stderr, "Nothing to do - already disabled\n");
        return EXIT_SUCCESS;
    }

    if (argc > optind) {
        opp_min = strtol(argv[optind++], &endptr, 10);
        if (*endptr) {
            fprintf(stderr, "Can't parse '%s' as an integer number\n", argv[optind-1]);
            return EXIT_FAILURE;
        }
    }

    if (argc > optind) {
        opp_max = strtol(argv[optind++], &endptr, 10);
        if (*endptr) {
            fprintf(stderr, "Can't parse '%s' as an integer number\n", argv[optind-1]);
            return EXIT_FAILURE;
        }
    }

    if (enable) {
        /* Default value if user didn't supplied anything */
        if (opp_min == 255 && !enabled) {
            opp_min = 0;
            opp_max = 15;
        }

        if (opp_min > opp_max) {
            fprintf(stderr, "Error: MinOPP is greater than MaxOPP\n");
            return EXIT_FAILURE;
        }

        rc = libxl_guest_pm_set(ctx, domid, true, opp_min, opp_max);

        if (!rc)
            printf("Enabled PM for guest %d with OPP ranges %d - %d\n",
                   domid, opp_min, opp_max);

    } else {
        rc = libxl_guest_pm_set(ctx, domid, false, opp_min, opp_max);

        if (!rc)
            printf("Disabled PM for guest %d\n", domid);
    }

    if (rc)
        fprintf(stderr, "Operation failed with rc = %d\n", rc);

    return rc;
}

int main_guest_pm_show(int argc, char **argv)
{
    int opt;
    int rc;
    uint32_t domid;
    bool enabled;
    uint8_t opp_min, opp_max;

    SWITCH_FOREACH_OPT(opt, "", NULL, "guest-pm-show", 1) {
        /* No options */
    }

    domid = find_domain(argv[optind++]);

    rc = libxl_guest_pm_get(ctx, domid, &enabled, &opp_min, &opp_max);
    if (rc)
        return rc;

    printf("DomId %d\n", domid);
    printf("Domain Power Management enabled: %s\n", enabled?"true":"false");
    if (enabled)
        printf("OPP ranges allowed: %d - %d\n", opp_min, opp_max);

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */


