/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Generic part of the SCI (System Control Interface) subsystem.
 *
 * Oleksii Moisieiev <oleksii_moisieiev@epam.com>
 * Copyright (c) 2024 EPAM Systems
 */

#ifndef __ASM_ARM_SCI_H
#define __ASM_ARM_SCI_H

#include <xen/lib.h>
#include <xen/types.h>
#include <xen/device_tree.h>
#include <public/domctl.h>
#include <xen/errno.h>

#ifdef CONFIG_ARM_SCI

struct sci_channel
{
    uint32_t guest_func_id;
    uint64_t paddr;
};

struct sci_mediator_ops {

    /*
     * Probe for SCI. Should return true if SCI found and
     * mediator is initialized.
     */
    bool (*probe)(struct dt_device_node *scmi_node);

    /*
     * Called during domain construction if toolstack requests to enable
     * SCI support so mediator can inform SCP-firmware about new
     * guest and create own structures for the new domain.
     */
    int (*domain_init)(struct domain *d, struct xen_arch_domainconfig *config);

    /*
     * Called during domain destruction, releases all resources, that
     * were allocated by the mediator.
     */
    void (*domain_destroy)(struct domain *d);

    /*
     * Called during parsing partial device-sci for the domain.
     * Passing device_node so mediator could process the device and
     * mark the device as related to the domain if needed.
     */
    int (*add_dt_device)(struct domain *d, struct dt_device_node *dev);

    /*
     * Called during domain destruction to relinquish resources used
     * by mediator itself. This function can return -ERESTART to indicate
     * that it does not finished work and should be called again.
     */
    int (*relinquish_resources)(struct domain *d);

    /* Handle call for current domain */
    bool (*handle_call)(struct domain *d, void *regs);
};

struct sci_mediator_desc {
    /* Printable name of the SCI. */
    const char *name;

    /* Mediator callbacks as described above. */
    const struct sci_mediator_ops *ops;

    /*
     * ID of SCI. Corresponds to xen_arch_domainconfig.sci_type.
     * Should be one of XEN_DOMCTL_CONFIG_ARM_SCI_xxx
     */
    uint16_t sci_type;

    /* Match structure to init mediator */
    const struct dt_device_match *dt_match;

};

/*
 * Initialize sci domain.
 *
 * Initialization routine to prepare SCI mediator for the domain.
 */
int sci_domain_init(struct domain *d, uint16_t sci_type,
                    struct xen_arch_domainconfig *config);
/*
 * Destroy sci_domain instance.
 */
void sci_domain_destroy(struct domain *d);

/*
 * Add device-tree node to the domain.
 *
 * SCI driver will do the register routine and set the device
 * permissions for the given domain.
 */
int sci_add_dt_device(struct domain *d, struct dt_device_node *dev);

/*
 * Free resources assigned to the certain domain.
 */
int sci_relinquish_resources(struct domain *d);

/*
 * Handle sci call from the domain.
 *
 * SCI-Mediator acts as SMC server for the registered domains and
 * does redirection of the domain calls to the SPI server,
 * such as ARM-TF or similar.
 */
bool sci_handle_call(struct domain *d, void *args);

/*
 * Get current sci type.
 */
uint16_t sci_get_type(void);
int sci_do_domctl(
    struct xen_domctl *domctl, struct domain *d,
    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl);

#define REGISTER_SCI_MEDIATOR(_name, _namestr, _type, _match, _ops) \
static const struct sci_mediator_desc __sci_desc_##_name __used     \
__section(".scimediator.info") = {                                  \
    .name = _namestr,                                               \
    .ops = _ops,                                                    \
    .sci_type = _type,                                              \
    .dt_match = _match                                              \
}

#else

static inline int sci_domain_init(struct domain *d, uint16_t sci_type,
                    struct xen_arch_domainconfig *config)
{
    if ( likely(sci_type == XEN_DOMCTL_CONFIG_ARM_SCI_NONE) )
        return 0;

    return -ENODEV;
}

static inline void sci_domain_destroy(struct domain *d)
{
}

static inline int sci_add_dt_device(struct domain *d,
                                    struct dt_device_node *dev)
{
    return 0;
}

static inline int sci_relinquish_resources(struct domain *d)
{
    return 0;
}

static inline bool sci_handle_call(struct domain *d, void *args)
{
    return false;
}

static inline uint16_t sci_get_type(void)
{
    return XEN_DOMCTL_CONFIG_ARM_SCI_NONE;
}

#endif  /* CONFIG_ARM_SCI */

#endif /* __ASM_ARM_SCI_H */
