/*
 * xen/include/asm-arm/sci/sci.h
 *
 * Generic part of the SCI (System Control Interface) subsystem.
 *
 * Oleksii Moisieiev <oleksii_moisieiev@epam.com>
 * Copyright (C) 2021, EPAM Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef __ASM_ARM_SCI_H
#define __ASM_ARM_SCI_H

#include <xen/lib.h>
#include <xen/types.h>
#include <xen/device_tree.h>
#include <public/domctl.h>
#include <xen/errno.h>

#ifdef CONFIG_ARM_SCI

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

int sci_domain_init(struct domain *d, uint16_t sci_type,
                    struct xen_arch_domainconfig *config);
void sci_domain_destroy(struct domain *d);
int sci_add_dt_device(struct domain *d, struct dt_device_node *dev);
int sci_relinquish_resources(struct domain *d);
bool sci_handle_call(struct domain *d, void *args);
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

static inline int sci_do_domctl(
    struct xen_domctl *domctl, struct domain *d,
    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    return -ENOSYS;
}


#endif  /* CONFIG_ARM_SCI */

#endif /* __ASM_ARM_SCI_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
