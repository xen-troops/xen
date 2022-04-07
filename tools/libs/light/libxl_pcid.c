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

#define PCI_BDF                "%04x:%02x:%02x.%01x"

static int sysfs_write_bdf(libxl__gc *gc, const char * sysfs_path,
        unsigned int domain, unsigned int bus,
        unsigned int dev, unsigned int func);

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

    dir = opendir(SYSFS_PCI_DEV);
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

static bool pci_supp_legacy_irq(void)
{
#ifdef CONFIG_PCI_SUPP_LEGACY_IRQ
    return true;
#else
    return false;
#endif
}

static int process_list_resources(libxl__gc *gc, yajl_gen gen,
                                   char *command_name,
                                   const struct libxl__json_object *request,
                                   struct libxl__json_object **response)
{
    struct libxl__json_object *iomem =
                 libxl__json_object_alloc(gc, JSON_ARRAY);
    struct libxl__json_object *irqs =
                 libxl__json_object_alloc(gc, JSON_ARRAY);
    const struct libxl__json_object *json_sdbf;
    const struct libxl__json_object *json_domid;
    unsigned int dom, bus, dev, func;
    libxl_domid domainid;
    char *sysfs_path;
    FILE *f;
    unsigned long long start, end, flags;
    int irq, i;
    int rc = 0;
    libxl__json_map_node *map_node = NULL;

    json_sdbf = libxl__json_map_get(PCID_MSG_FIELD_SBDF, request, JSON_STRING);
    if (!json_sdbf) {
        make_error_reply(gc, gen, "No mandatory parameter 'sbdf'", command_name);
        return ERROR_FAIL;
    }
    if (sscanf(libxl__json_object_get_string(json_sdbf), PCID_SBDF_FMT,
               &dom, &bus, &dev, &func) != 4) {
        make_error_reply(gc, gen, "Can't parse SBDF", command_name);
        return ERROR_FAIL;
    }

    json_domid = libxl__json_map_get(PCID_MSG_FIELD_DOMID, request, JSON_INTEGER);
    if (!json_domid) {
        make_error_reply(gc, gen, "No mandatory parameter 'domid'", command_name);
        return ERROR_FAIL;
    }
    domainid = libxl__json_object_get_integer(json_domid);

    libxl__yajl_gen_asciiz(gen, PCID_MSG_FIELD_RESOURCES);
    *response = libxl__json_object_alloc(gc, JSON_MAP);

    sysfs_path = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/resource", dom, bus, dev, func);
    f = fopen(sysfs_path, "r");
    start = 0;
    irq = 0;

    if (f == NULL) {
        LOGED(ERROR, domainid, "Couldn't open %s", sysfs_path);
        rc = ERROR_FAIL;
        goto out;
    }
    for (i = 0; i < PROC_PCI_NUM_RESOURCES; i++) {
        if (fscanf(f, "0x%llx 0x%llx 0x%llx\n", &start, &end, &flags) != 3)
            continue;
        if (start) {
            struct libxl__json_object *node =
                libxl__json_object_alloc(gc, JSON_STRING);

            node->u.string = GCSPRINTF("0x%llx 0x%llx 0x%llx", start, end, flags);
            flexarray_append(iomem->u.array, node);
        }
    }
    fclose(f);
    if (!pci_supp_legacy_irq())
        goto out_no_irq;
    sysfs_path = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/irq", dom, bus, dev, func);
    f = fopen(sysfs_path, "r");
    if (f == NULL) {
        LOGED(ERROR, domainid, "Couldn't open %s", sysfs_path);
        goto out_no_irq;
    }
    if ((fscanf(f, "%u", &irq) == 1) && irq) {
            struct libxl__json_object *node =
                libxl__json_object_alloc(gc, JSON_INTEGER);

            node->u.i = irq;
            flexarray_append(irqs->u.array, node);
    }
    fclose(f);

    GCNEW(map_node);
    map_node->map_key = libxl__strdup(gc, PCID_RESULT_KEY_IRQS);
    map_node->obj = irqs;
    flexarray_append((*response)->u.map, map_node);
out_no_irq:
    GCNEW(map_node);
    map_node->map_key = libxl__strdup(gc, PCID_RESULT_KEY_IOMEM);
    map_node->obj = iomem;
    flexarray_append((*response)->u.map, map_node);
    rc = 0;
out:
    return rc;
}

static int pciback_dev_is_assigned(libxl__gc *gc, unsigned int domain,
				   unsigned int bus, unsigned int dev,
				   unsigned int func)
{
    char * spath;
    int rc;
    struct stat st;

    if (access(SYSFS_PCIBACK_DRIVER, F_OK) < 0) {
        if (errno == ENOENT) {
            LOG(ERROR, "Looks like pciback driver is not loaded");
        } else {
            LOGE(ERROR, "Can't access "SYSFS_PCIBACK_DRIVER);
        }
        return -1;
    }

    spath = GCSPRINTF(SYSFS_PCIBACK_DRIVER"/"PCI_BDF,
		      domain, bus, dev, func);
    rc = lstat(spath, &st);

    if (rc == 0)
        return 1;
    if (rc < 0 && errno == ENOENT)
        return 0;
    LOGE(ERROR, "Accessing %s", spath);
    return 0;
}

#define PCID_INFO_PATH		"pcid"
#define PCID_BDF_XSPATH         "%04x-%02x-%02x-%01x"

static char *pcid_info_xs_path(libxl__gc *gc, unsigned int domain,
			       unsigned int bus, unsigned int dev,
			       unsigned int func, const char *node)
{
    return node ?
        GCSPRINTF(PCID_INFO_PATH"/"PCID_BDF_XSPATH"/%s",
                  domain, bus, dev, func, node) :
        GCSPRINTF(PCID_INFO_PATH"/"PCID_BDF_XSPATH,
                  domain, bus, dev, func);
}


static int pcid_info_xs_write(libxl__gc *gc, unsigned int domain,
			       unsigned int bus, unsigned int dev,
			       unsigned int func, const char *node,
			      const char *val)
{
    char *path = pcid_info_xs_path(gc, domain, bus, dev, func, node);
    int rc = libxl__xs_printf(gc, XBT_NULL, path, "%s", val);

    if (rc) LOGE(WARN, "Write of %s to node %s failed.", val, path);

    return rc;
}

static char *pcid_info_xs_read(libxl__gc *gc, unsigned int domain,
			       unsigned int bus, unsigned int dev,
			       unsigned int func, const char *node)
{
    char *path = pcid_info_xs_path(gc, domain, bus, dev, func, node);

    return libxl__xs_read(gc, XBT_NULL, path);
}

static void pcid_info_xs_remove(libxl__gc *gc, unsigned int domain,
			       unsigned int bus, unsigned int dev,
			       unsigned int func, const char *node)
{
    char *path = pcid_info_xs_path(gc, domain, bus, dev, func, node);
    libxl_ctx *ctx = libxl__gc_owner(gc);

    /* Remove the xenstore entry */
    xs_rm(ctx->xsh, XBT_NULL, path);
}


/* Write the standard BDF into the sysfs path given by sysfs_path. */
static int sysfs_write_bdf(libxl__gc *gc, const char * sysfs_path,
			   unsigned int domain, unsigned int bus,
			   unsigned int dev, unsigned int func)
{
    int rc, fd;
    char *buf;

    fd = open(sysfs_path, O_WRONLY);
    if (fd < 0) {
        LOGE(ERROR, "Couldn't open %s", sysfs_path);
        return ERROR_FAIL;
    }

    buf = GCSPRINTF(PCI_BDF, domain, bus, dev, func);
    rc = write(fd, buf, strlen(buf));
    /* Annoying to have two if's, but we need the errno */
    if (rc < 0)
        LOGE(ERROR, "write to %s returned %d", sysfs_path, rc);
    close(fd);

    if (rc < 0)
        return ERROR_FAIL;

    return 0;
}


/* Unbind device from its current driver, if any.  If driver_path is non-NULL,
 * store the path to the original driver in it. */
static int sysfs_dev_unbind(libxl__gc *gc, unsigned int domain,
			    unsigned int bus, unsigned int dev,
			    unsigned int func,
                            char **driver_path)
{
    char * spath, *dp = NULL;
    struct stat st;

    spath = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF"/driver",
                           domain, bus, dev, func);
    if (!lstat(spath, &st)) {
        /* Find the canonical path to the driver. */
        dp = libxl__zalloc(gc, PATH_MAX);
        dp = realpath(spath, dp);
        if ( !dp ) {
            LOGE(ERROR, "realpath() failed");
            return -1;
        }

        LOG(DEBUG, "Driver re-plug path: %s", dp);

        /* Unbind from the old driver */
        spath = GCSPRINTF("%s/unbind", dp);
        if (sysfs_write_bdf(gc, spath, domain, bus, dev, func) < 0) {
            LOGE(ERROR, "Couldn't unbind device");
            return -1;
        }
    }

    if (driver_path)
        *driver_path = dp;

    return 0;
}

/*
 * A brief comment about slots.  I don't know what slots are for; however,
 * I have by experimentation determined:
 * - Before a device can be bound to pciback, its BDF must first be listed
 *   in pciback/slots
 * - The way to get the BDF listed there is to write BDF to
 *   pciback/new_slot
 * - Writing the same BDF to pciback/new_slot is not idempotent; it results
 *   in two entries of the BDF in pciback/slots
 * It's not clear whether having two entries in pciback/slots is a problem
 * or not.  Just to be safe, this code does the conservative thing, and
 * first checks to see if there is a slot, adding one only if one does not
 * already exist.
 */

/* Scan through /sys/.../pciback/slots looking for pci's BDF */
static int pciback_dev_has_slot(libxl__gc *gc, unsigned int domain,
			      unsigned int bus, unsigned int dev,
			      unsigned int func)
{
    FILE *f;
    int rc = 0;
    unsigned s_domain, s_bus, s_dev, s_func;

    f = fopen(SYSFS_PCIBACK_DRIVER"/slots", "r");

    if (f == NULL) {
        LOGE(ERROR, "Couldn't open %s", SYSFS_PCIBACK_DRIVER"/slots");
        return ERROR_FAIL;
    }

    while (fscanf(f, "%x:%x:%x.%d\n",
		  &s_domain, &s_bus, &s_dev, &s_func) == 4) {
        if (s_domain == domain &&
            s_bus == bus &&
            s_dev == dev &&
            s_func == func) {
            rc = 1;
            goto out;
        }
    }
out:
    fclose(f);
    return rc;
}

static int pciback_dev_assign(libxl__gc *gc, unsigned int domain,
			      unsigned int bus, unsigned int dev,
			      unsigned int func)
{
    int rc;

    if ( (rc = pciback_dev_has_slot(gc, domain, bus, dev, func)) < 0 ) {
        LOGE(ERROR, "Error checking for pciback slot");
        return ERROR_FAIL;
    } else if (rc == 0) {
        if ( sysfs_write_bdf(gc, SYSFS_PCIBACK_DRIVER"/new_slot",
                             domain, bus, dev, func) < 0 ) {
            LOGE(ERROR, "Couldn't bind device to pciback!");
            return ERROR_FAIL;
        }
    }

    if ( sysfs_write_bdf(gc, SYSFS_PCIBACK_DRIVER"/bind",
			 domain, bus, dev, func) < 0 ) {
        LOGE(ERROR, "Couldn't bind device to pciback!");
        return ERROR_FAIL;
    }
    return 0;
}

static int process_pciback_dev_is_assigned(libxl__gc *gc, yajl_gen gen,
                                   char *command_name,
                                   const struct libxl__json_object *request,
                                   struct libxl__json_object **response)
{
    const struct libxl__json_object *json_o;
    unsigned int dom, bus, dev, func;
    int rc;

    libxl__yajl_gen_asciiz(gen, PCID_MSG_FIELD_RESULT);
    *response = libxl__json_object_alloc(gc, JSON_BOOL);
    json_o = libxl__json_map_get(PCID_MSG_FIELD_SBDF, request, JSON_STRING);
    if (!json_o) {
        make_error_reply(gc, gen, "No mandatory parameter 'sbdf'", command_name);
        return ERROR_FAIL;
    }

    if (sscanf(libxl__json_object_get_string(json_o), PCID_SBDF_FMT,
               &dom, &bus, &dev, &func) != 4) {
        make_error_reply(gc, gen, "Can't parse SBDF", command_name);
        return ERROR_FAIL;
    }
    rc = pciback_dev_is_assigned(gc, dom, bus, dev, func);
    if (rc < 0)
        return ERROR_FAIL;
    (*response)->u.b = rc;
    return 0;
}

static int device_pci_reset(libxl__gc *gc, unsigned int domain, unsigned int bus,
                                   unsigned int dev, unsigned int func)
{
    char *reset;
    int fd, rc;

    reset = GCSPRINTF("%s/do_flr", SYSFS_PCIBACK_DRIVER);
    fd = open(reset, O_WRONLY);
    if (fd >= 0) {
        char *buf = GCSPRINTF(PCI_BDF, domain, bus, dev, func);
        rc = write(fd, buf, strlen(buf));
        if (rc < 0)
            LOGD(ERROR, domain, "write to %s returned %d", reset, rc);
        close(fd);
        return rc < 0 ? rc : 0;
    }
    if (errno != ENOENT)
        LOGED(ERROR, domain, "Failed to access pciback path %s", reset);
    reset = GCSPRINTF("%s/"PCI_BDF"/reset", SYSFS_PCI_DEV, domain, bus, dev, func);
    fd = open(reset, O_WRONLY);
    if (fd >= 0) {
        rc = write(fd, "1", 1);
        if (rc < 0)
            LOGED(ERROR, domain, "write to %s returned %d", reset, rc);
        close(fd);
        return rc < 0 ? rc : 0;
    }
    if (errno == ENOENT) {
        LOGD(ERROR, domain,
             "The kernel doesn't support reset from sysfs for PCI device "PCI_BDF,
             domain, bus, dev, func);
    } else {
        LOGED(ERROR, domain, "Failed to access reset path %s", reset);
    }
    return -1;
}

static int process_device_pci_reset(libxl__gc *gc, yajl_gen gen,
                                   char *command_name,
                                   const struct libxl__json_object *request,
                                   struct libxl__json_object **response)
{
    const struct libxl__json_object *json_o;
    unsigned int dom, bus, dev, func;
    int rc;

    json_o = libxl__json_map_get(PCID_MSG_FIELD_SBDF, request, JSON_STRING);
    if (!json_o) {
        make_error_reply(gc, gen, "No mandatory parameter 'sbdf'", command_name);
        return ERROR_FAIL;
    }

    if (sscanf(libxl__json_object_get_string(json_o), PCID_SBDF_FMT,
               &dom, &bus, &dev, &func) != 4) {
        make_error_reply(gc, gen, "Can't parse SBDF", command_name);
        return ERROR_FAIL;
    }
    rc = device_pci_reset(gc, dom, bus, dev, func);
    if (rc < 0)
        return ERROR_FAIL;
    return rc;
}

static int process_make_assignable(libxl__gc *gc, yajl_gen gen,
                                   char *command_name,
                                   const struct libxl__json_object *request,
                                   struct libxl__json_object **response)
{
    struct stat st;
    const struct libxl__json_object *json_o;
    unsigned int dom, bus, dev, func;
    int rc;
    bool rebind;
    char *spath, *driver_path = NULL;

    json_o = libxl__json_map_get(PCID_MSG_FIELD_SBDF, request, JSON_STRING);
    if (!json_o) {
        make_error_reply(gc, gen, "No mandatory parameter 'sbdf'", command_name);
        return ERROR_FAIL;
    }

    if (sscanf(libxl__json_object_get_string(json_o), PCID_SBDF_FMT,
	       &dom, &bus, &dev, &func) != 4) {
        make_error_reply(gc, gen, "Can't parse SBDF", command_name);
        return ERROR_FAIL;
    }

    json_o = libxl__json_map_get(PCID_MSG_FIELD_REBIND, request, JSON_BOOL);
    if (!json_o) {
        make_error_reply(gc, gen, "No mandatory parameter 'rebind'", command_name);
        return ERROR_FAIL;
    }

    rebind = libxl__json_object_get_bool(json_o);

    /* See if the device exists */
    spath = GCSPRINTF(SYSFS_PCI_DEV"/"PCI_BDF, dom, bus, dev, func);
    if ( lstat(spath, &st) ) {
        make_error_reply(gc, gen, strerror(errno), command_name);
        LOGE(ERROR, "Couldn't lstat %s", spath);
        return ERROR_FAIL;
    }

    /* Check to see if it's already assigned to pciback */
    rc = pciback_dev_is_assigned(gc, dom, bus, dev, func);
    if (rc < 0) {
        make_error_reply(gc, gen, "Can't check if device is assigned",
			 command_name);
        return ERROR_FAIL;
    }
    if (rc) {
        LOG(WARN, PCI_BDF" already assigned to pciback", dom, bus, dev, func);
        goto done;
    }

    /* Check to see if there's already a driver that we need to unbind from */
    if (sysfs_dev_unbind(gc, dom, bus, dev, func, &driver_path)) {
        LOG(ERROR, "Couldn't unbind "PCI_BDF" from driver",
            dom, bus, dev, func);
        return ERROR_FAIL;
    }

    /* Store driver_path for rebinding back */
    if (rebind) {
        if (driver_path) {
            pcid_info_xs_write(gc, dom, bus, dev, func, "driver_path",
			       driver_path);
        } else if ( (driver_path =
                     pcid_info_xs_read(gc, dom, bus, dev, func,
				       "driver_path")) != NULL ) {
            LOG(INFO, PCI_BDF" not bound to a driver, will be rebound to %s",
                dom, bus, dev, func, driver_path);
        } else {
            LOG(WARN, PCI_BDF" not bound to a driver, will not be rebound.",
                dom, bus, dev, func);
        }
    } else {
        pcid_info_xs_remove(gc, dom, bus, dev, func, "driver_path");
    }

    if (pciback_dev_assign(gc, dom, bus, dev, func)) {
        LOG(ERROR, "Couldn't bind device to pciback!");
        return ERROR_FAIL;
    }

done:
    return 0;
}

static int pciback_dev_unassign(libxl__gc *gc, unsigned int domain,
			      unsigned int bus, unsigned int dev,
			      unsigned int func)
{
    /* Remove from pciback */
    if ( sysfs_dev_unbind(gc, domain, bus, dev, func, NULL) < 0 ) {
        LOG(ERROR, "Couldn't unbind device!");
        return ERROR_FAIL;
    }

    /* Remove slot if necessary */
    if ( pciback_dev_has_slot(gc, domain, bus, dev, func) > 0 ) {
        if ( sysfs_write_bdf(gc, SYSFS_PCIBACK_DRIVER"/remove_slot",
                             domain, bus, dev, func) < 0 ) {
            LOGE(ERROR, "Couldn't remove pciback slot");
            return ERROR_FAIL;
        }
    }
    return 0;
}

static int process_revert_assignable(libxl__gc *gc, yajl_gen gen,
                                   char *command_name,
                                   const struct libxl__json_object *request,
                                   struct libxl__json_object **response)
{
    const struct libxl__json_object *json_o;
    unsigned int dom, bus, dev, func;
    int rc;
    bool rebind;
    char *driver_path = NULL;

    json_o = libxl__json_map_get(PCID_MSG_FIELD_SBDF, request, JSON_STRING);
    if (!json_o) {
        make_error_reply(gc, gen, "No mandatory parameter 'sbdf'", command_name);
        return ERROR_FAIL;
    }

    if (sscanf(libxl__json_object_get_string(json_o), PCID_SBDF_FMT,
	       &dom, &bus, &dev, &func) != 4) {
        make_error_reply(gc, gen, "Can't parse SBDF", command_name);
        return ERROR_FAIL;
    }

    json_o = libxl__json_map_get(PCID_MSG_FIELD_REBIND, request, JSON_BOOL);
    if (!json_o) {
        make_error_reply(gc, gen, "No mandatory parameter 'rebind'", command_name);
        return ERROR_FAIL;
    }

    rebind = libxl__json_object_get_bool(json_o);

    /* Unbind from pciback */
    if ( (rc = pciback_dev_is_assigned(gc, dom, bus, dev, func)) < 0 ) {
        make_error_reply(gc, gen, "Can't unbind from pciback", command_name);
        return ERROR_FAIL;
    } else if ( rc ) {
        pciback_dev_unassign(gc, dom, bus, dev, func);
    } else {
        LOG(WARN, "Not bound to pciback");
    }

    /* Rebind if necessary */
    driver_path = pcid_info_xs_read(gc, dom, bus, dev, func, "driver_path");

    if ( driver_path ) {
        if ( rebind ) {
            LOG(INFO, "Rebinding to driver at %s", driver_path);

            if ( sysfs_write_bdf(gc,
                                 GCSPRINTF("%s/bind", driver_path),
                                 dom, bus, dev, func) < 0 ) {
                LOGE(ERROR, "Couldn't bind device to %s", driver_path);
                return -1;
            }

            pcid_info_xs_remove(gc, dom, bus, dev, func, "driver_path");
        }
    } else {
        if ( rebind ) {
            LOG(WARN,
                "Couldn't find path for original driver; not rebinding");
        }
    }

    return 0;
}

static int pcid_handle_request(libxl__gc *gc, yajl_gen gen,
                               const libxl__json_object *request)
{
    const libxl__json_object *command_obj;
    libxl__json_object *command_response = NULL;
    char *command_name;
    int ret = 0;

    yajl_gen_map_open(gen);

    command_obj = libxl__json_map_get(PCID_MSG_FIELD_CMD, request, JSON_STRING);
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
    else if (strcmp(command_name, PCID_CMD_MAKE_ASSIGNABLE) == 0)
       ret = process_make_assignable(gc, gen, command_name,
                                     request, &command_response);
    else if (strcmp(command_name, PCID_CMD_REVERT_ASSIGNABLE) == 0)
       ret = process_revert_assignable(gc, gen, command_name,
                                     request, &command_response);
    else if (strcmp(command_name, PCID_CMD_IS_ASSIGNED) == 0)
       ret = process_pciback_dev_is_assigned(gc, gen, command_name,
                                     request, &command_response);
    else if (strcmp(command_name, PCID_CMD_RESET_DEVICE) == 0)
       ret = process_device_pci_reset(gc, gen, command_name,
                                     request, &command_response);
    else if (strcmp(command_name, PCID_CMD_RESOURCE_LIST) == 0)
       ret = process_list_resources(gc, gen, command_name,
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

    if (command_response) {
	ret = libxl__json_object_to_yajl_gen(gc, gen, command_response);
	if (ret)
	    goto out;
    }

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
