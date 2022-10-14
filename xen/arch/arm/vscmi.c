/*
 * xen/arch/vscmi.c
 *
 * Virtual SCMI handler
 *
 * Volodymyr Babchuk <volodymyr_babchuk@epam.com>
 * Copyright (c) 2019 EPAM Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/mm.h>
#include <xen/guest_pm.h>
#include <xen/sched.h>
#include <xen/spinlock.h>
#include <xen/vmap.h>
#include <asm/io.h>
#include <asm/vscmi.h>
#include <asm/guest_access.h>
#include "asm-arm/mm.h"
#include "scmi_protocol.h"

#define SCMI_VERSION 0x10000
/* One agent, one protocol */
#define SCMI_PROTO_ATTRS (BIT(0, UL) | BIT(8, UL))
#define SCMI_VENDOR "XenTroops"
#ifdef CONFIG_VSCMI_SUBVENDOR
#define SCMI_SUBVENDOR CONFIG_VSCMI_SUBVENDOR
#else
#define SCMI_SUBVENDOR "Renesas"
#endif
#define SCMI_AGENT "XEN"

#define PERF_SUSTAINED_FREQ_KHZ 1000000
#define PERF_OPPS_PER_CALL 5

static DEFINE_SPINLOCK(add_remove_lock);
static NOTIFIER_HEAD(vscmi_chain);

void register_vscmi_notifier(struct notifier_block *nb)
{
    spin_lock(&add_remove_lock);
    notifier_chain_register(&vscmi_chain, nb);
    spin_unlock(&add_remove_lock);
}

void unregister_vscmi_notifier(struct notifier_block *nb)
{
    spin_lock(&add_remove_lock);
    notifier_chain_unregister(&vscmi_chain, nb);
    spin_unlock(&add_remove_lock);
}

int vcpu_vscmi_init(struct vcpu *vcpu)
{
    vcpu->arch.opp = 0;

    return 0;
}

static int mark_shmem_free(mfn_t scmi_mfn)
{
    struct scmi_shared_mem *data;
    data = (struct scmi_shared_mem*)vmap(&scmi_mfn, 1);
    if ( !data )
    {
        gprintk(XENLOG_ERR, "Could not allocate buffer for SCMI SHM\n");
        return -ENOMEM;
    }

    data->channel_status = SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE;
    vunmap(data);
    return 0;
}

int domain_vscmi_init(struct domain *d, gfn_t shmem_gfn)
{
    int rc;

    if ( gfn_eq(shmem_gfn, INVALID_GFN) )
        return -EINVAL;

    d->arch.scmi_base_pg = alloc_domheap_page(d, 0);
    if ( !d->arch.scmi_base_pg )
        return -ENOMEM;

    d->arch.scmi_base_ipa = gfn_to_gaddr(shmem_gfn);

    printk(XENLOG_INFO "SCMI shmem at: %#"PRIpaddr" -> %#"PRIpaddr"\n",
           d->arch.scmi_base_ipa,
           page_to_maddr(d->arch.scmi_base_pg));

    rc = map_regions_p2mt(d, shmem_gfn, 1,
                          page_to_mfn(d->arch.scmi_base_pg), p2m_ram_rw);

    if ( rc )
        goto err;

    if ( !rc )
        guest_pm_force_enable(d);

    rc = mark_shmem_free(page_to_mfn(d->arch.scmi_base_pg));

    if ( rc )
        goto err;

    return 0;
err:
    free_domheap_page(d->arch.scmi_base_pg);
    return rc;
}

void domain_vscmi_free(struct domain *d)
{
    if ( !d->arch.scmi_base_pg )
        return;

    unmap_regions_p2mt(d, gaddr_to_gfn(d->arch.scmi_base_ipa), 1,
                       page_to_mfn(d->arch.scmi_base_pg));

    free_domheap_page(d->arch.scmi_base_pg);
}

static void handle_base_req(struct scmi_shared_mem *data)
{
    switch ( SCMI_HDR_MSG_ID(data->msg_header) )
    {
    case PROTOCOL_VERSION:
        writel_relaxed(SCMI_SUCCESS, data->msg_payload);
        writel_relaxed(SCMI_VERSION, data->msg_payload + 4);
        data->length = sizeof(uint32_t) * 3;
        break;
    case PROTOCOL_ATTRIBUTES:
        writel_relaxed(SCMI_SUCCESS, data->msg_payload);
        writel_relaxed(SCMI_PROTO_ATTRS, data->msg_payload + 4);
        data->length = sizeof(uint32_t) * 3;
        break;
    case BASE_DISCOVER_VENDOR:
        writel_relaxed(SCMI_SUCCESS, data->msg_payload);
        strlcpy((char*)data->msg_payload + 4, SCMI_VENDOR, SCMI_MAX_STR_SIZE);
        data->length = sizeof(uint32_t) * 2 + sizeof(SCMI_VENDOR);
        break;
    case BASE_DISCOVER_SUB_VENDOR:
        writel_relaxed(SCMI_SUCCESS, data->msg_payload);
        strlcpy((char*)data->msg_payload + 4, SCMI_SUBVENDOR, SCMI_MAX_STR_SIZE);
        data->length = sizeof(uint32_t) * 2 + sizeof(SCMI_SUBVENDOR);
        break;
    case BASE_DISCOVER_LIST_PROTOCOLS:
    {
        uint32_t skip = *(uint32_t*)data->msg_payload;
        if ( skip == 0 )
        {
            writel_relaxed(SCMI_SUCCESS, data->msg_payload);
            writel_relaxed(1, data->msg_payload + 4);
            writel_relaxed(SCMI_PROTOCOL_PERF, data->msg_payload + 8);
            data->length = sizeof(uint32_t) * 4;
        }
        else
        {
            writel_relaxed(SCMI_ERR_RANGE, data->msg_payload);
            data->length = sizeof(uint32_t) * 2;
        }

        break;
    }
    case BASE_DISCOVER_AGENT:
        writel_relaxed(SCMI_SUCCESS, data->msg_payload);
        strlcpy((char*)data->msg_payload + 4, SCMI_AGENT, SCMI_MAX_STR_SIZE);
        data->length = sizeof(uint32_t) * 2 + sizeof(SCMI_AGENT);
        break;
    default:
        writel_relaxed(SCMI_ERR_SUPPORT, data->msg_payload);
        data->length = sizeof(uint32_t) * 2;
        break;
    }
}

static void handle_perf_req(struct scmi_shared_mem *data)
{
    switch ( SCMI_HDR_MSG_ID(data->msg_header) )
    {
    case PROTOCOL_VERSION:
        writel_relaxed(SCMI_SUCCESS, data->msg_payload);
        writel_relaxed(SCMI_VERSION, data->msg_payload + 4);
        data->length = sizeof(uint32_t) * 3;
        break;
    case PROTOCOL_ATTRIBUTES:
    {
        struct scmi_msg_resp_perf_attributes* attrs =
            (struct scmi_msg_resp_perf_attributes*)(data->msg_payload + 4);
        writel_relaxed(SCMI_SUCCESS, data->msg_payload);

        attrs->num_domains = cpu_to_le16(current->domain->max_vcpus);
        attrs->flags = cpu_to_le16(0);
        attrs->stats_addr_low = cpu_to_le32(0);
        attrs->stats_addr_high = cpu_to_le32(0);
        attrs->stats_size = cpu_to_le32(0);
        data->length = sizeof(*attrs) + sizeof(uint32_t) * 2;
        break;
    }
    case PERF_DOMAIN_ATTRIBUTES:
    {
        uint32_t domain_id = le32_to_cpu(*(__le32*)data->msg_payload);
        struct scmi_msg_resp_perf_domain_attributes* attrs =
            (struct scmi_msg_resp_perf_domain_attributes*)(data->msg_payload + 4);

        if ( domain_id >= current->domain->max_vcpus )
        {
            writel_relaxed(SCMI_ERR_RANGE, data->msg_payload);
            data->length = sizeof(uint32_t) * 2;
            break;
        }
        writel_relaxed(SCMI_SUCCESS, data->msg_payload);

        attrs->flags = cpu_to_le32(SUPPORTS_SET_LIMITS(~0) |
                                   SUPPORTS_SET_PERF_LVL(~0));
        attrs->rate_limit_us = le32_to_cpu(0);
        attrs->sustained_freq_khz = le32_to_cpu(PERF_SUSTAINED_FREQ_KHZ);
        attrs->sustained_perf_level = le32_to_cpu(VSCMI_OPP_COUNT / 2);
        snprintf((char*)attrs->name, sizeof(attrs->name), "vcpu%d", domain_id);
        data->length = sizeof(*attrs) + sizeof(uint32_t) * 2;

        break;
    }
    case PERF_DESCRIBE_LEVELS:
    {
        struct scmi_msg_perf_describe_levels *req = (void*)data->msg_payload;
        struct scmi_msg_resp_perf_describe_levels *resp =
            (void*)(data->msg_payload + 4);
        int idx = le32_to_cpu(req->level_index);
        int i;

        if ( le32_to_cpu(req->domain) >= current->domain->max_vcpus )
        {
            writel_relaxed(SCMI_ERR_RANGE, data->msg_payload);
            data->length = sizeof(uint32_t) * 2;
            break;
        }

        if ( idx > VSCMI_MAX_OPP )
        {
            writel_relaxed(SCMI_ERR_RANGE, data->msg_payload);
            data->length = sizeof(uint32_t) * 2;
            break;
        }

        resp->num_remaining = MAX(0, VSCMI_OPP_COUNT - idx - PERF_OPPS_PER_CALL);
        resp->num_returned = MIN(PERF_OPPS_PER_CALL, VSCMI_OPP_COUNT - idx);

        for ( i = 0; i < resp->num_returned; i++ )
        {
            resp->opp[i].perf_val = idx + i + 1;
            resp->opp[i].power = resp->opp[i].perf_val * resp->opp[i].perf_val;
            resp->opp[i].transition_latency_us = cpu_to_le16(1);
        }

        data->length = sizeof(*resp) + sizeof(uint32_t) * 2 +
            sizeof(resp->opp[0]) * le16_to_cpu(resp->num_returned);

        writel_relaxed(SCMI_SUCCESS, data->msg_payload);

        break;
    }
    case PERF_LEVEL_SET:
    {
        struct scmi_perf_set_level *req = (void*)data->msg_payload;
        uint32_t perf_domain = le32_to_cpu(req->domain);
        int level = le32_to_cpu(req->level) - 1;
        int ret = 0;

        if ( perf_domain >= current->domain->max_vcpus )
        {
            writel_relaxed(SCMI_ERR_RANGE, data->msg_payload);
            data->length = sizeof(uint32_t) * 2;
            break;
        }

        if ( level < 0 || level > VSCMI_MAX_OPP)
        {
            gprintk(XENLOG_WARNING, "vscmi: requested opp is out of bounds: %d\n", level);
            writel_relaxed(SCMI_ERR_PARAMS, data->msg_payload);
            data->length = sizeof(uint32_t) * 2;
            break;
        }

        if ( current->domain->vcpu[perf_domain]->arch.opp != level )
        {
            current->domain->vcpu[perf_domain]->arch.opp = level;
            ret = notifier_call_chain(&vscmi_chain, 0,
                                      current->domain->vcpu[perf_domain], NULL);
        }

        if ( !ret )
            writel_relaxed(SCMI_SUCCESS, data->msg_payload);
        else
            writel_relaxed(SCMI_ERR_HARDWARE, data->msg_payload);
        data->length = sizeof(uint32_t) * 2;

        break;
    }
    case PERF_LEVEL_GET:
    {
        uint32_t perf_domain = le32_to_cpu(*(__le32*)data->msg_payload);

        if ( perf_domain >= current->domain->max_vcpus )
        {
            writel_relaxed(SCMI_ERR_RANGE, data->msg_payload);
            data->length = sizeof(uint32_t) * 2;
            break;
        }

        writel_relaxed(SCMI_SUCCESS, data->msg_payload);
        writel_relaxed(current->domain->vcpu[perf_domain]->arch.opp + 1,
                       data->msg_payload + 4);
        data->length = sizeof(uint32_t) * 3;

        break;
    }
    default:
        writel_relaxed(SCMI_ERR_SUPPORT, data->msg_payload);
        data->length = sizeof(uint32_t) * 2;
        break;
    }
}

bool vscmi_handle_call(struct cpu_user_regs *regs)
{
    struct scmi_shared_mem *data;
    uint32_t hdr;
    int res;
    mfn_t scmi_mfn;
    paddr_t scmi_ipa;

    if ( !current->domain->arch.scmi_base_pg )
    {
        printk(XENLOG_ERR "No SCMI shared memory for domain\n");
        return false;
    }

    scmi_mfn = page_to_mfn(current->domain->arch.scmi_base_pg);
    scmi_ipa = current->domain->arch.scmi_base_ipa;

    data = (struct scmi_shared_mem*)xzalloc_array(char, VSCMI_SHM_SIZE);
    if ( !data )
    {
        gprintk(XENLOG_ERR, "Could not allocate buffer for SCMI SHM\n");
        return false;
    }

    flush_page_to_ram(mfn_x(scmi_mfn), false);
    res = access_guest_memory_by_ipa(current->domain, scmi_ipa, data,
                                     VSCMI_SHM_SIZE, false);
    if ( res )
    {
        gprintk(XENLOG_ERR, "Error reading guest memory %d\n", res);
        goto err;
    }

    hdr = data->msg_header;

    switch ( SCMI_HDR_PROTO_ID(data->msg_header) )
    {
    case SCMI_PROTOCOL_BASE:
        handle_base_req(data);
        break;
    case SCMI_PROTOCOL_PERF:
        handle_perf_req(data);
        break;
    default:
        writel_relaxed(SCMI_ERR_SUPPORT, data->msg_payload);
        data->length = sizeof(uint32_t) * 2;
        break;
    }

    data->channel_status = SCMI_SHMEM_CHAN_STAT_CHANNEL_FREE;

    res = access_guest_memory_by_ipa(current->domain, scmi_ipa, data,
                                     VSCMI_SHM_SIZE, true);

    flush_page_to_ram(mfn_x(scmi_mfn), false);
    if ( res )
    {
        gprintk(XENLOG_ERR, "Error writing guest memory %d\n", res);
        goto err;
    }

err:
    xfree(data);
    return !res;
}

unsigned int vscmi_scale_opp(int requested, unsigned int freq_min,
                             unsigned int freq_max)
{
    unsigned int ret;

    if ( requested < 0)
        ret = freq_min;
    else if ( requested > VSCMI_MAX_OPP )
        ret = freq_max;
    else
        ret = freq_min +
            (unsigned long long)(freq_max - freq_min) * requested / VSCMI_MAX_OPP;

    return  ret;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
