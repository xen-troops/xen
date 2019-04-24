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

#include <xen/sched.h>
#include <asm/io.h>
#include <asm/vscmi.h>
#include <asm/guest_access.h>
#include "scmi_protocol.h"

#define SCMI_VERSION 0x10000
/* One agent, one protocol */
#define SCMI_PROTO_ATTRS (BIT(0) | BIT(8))
#define SCMI_VENDOR "XenTroops"
#define SCMI_SUBVENDOR "Renesas"
#define SCMI_AGENT "XEN"

#define PERF_SUSTAINED_FREQ_KHZ 1500000

static uint32_t opp_table[] = {
    500,     // VSCPI_OPP_MIN
    1000,    // VSCPI_OPP_LOW
    1500,    // VSCPI_OPP_NOM
    2000,    // VSCPI_OPP_HIGH
    2500,    // VSCPI_OPP_TURBO
};

int vcpu_vscmi_init(struct vcpu *vcpu)
{
    vcpu->arch.opp = VSCMI_OPP_NOM;

    return 0;
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
        attrs->sustained_perf_level = le32_to_cpu(opp_table[VSCMI_OPP_NOM]);
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

        if ( idx >= VSCMI_OPP_TURBO )
        {
            writel_relaxed(SCMI_ERR_RANGE, data->msg_payload);
            data->length = sizeof(uint32_t) * 2;
            break;
        }

        resp->num_remaining = 0;
        resp->num_returned = cpu_to_le16(VSCMI_OPP_TURBO - idx + 1);

        for ( i = idx; i <= VSCMI_OPP_TURBO; i++ )
        {
            resp->opp[i - idx].perf_val = cpu_to_le32(opp_table[i]);
            resp->opp[i - idx].power = cpu_to_le32(opp_table[i]);
            resp->opp[i - idx].transition_latency_us = cpu_to_le16(1);
        }

        data->length = sizeof(*resp) + sizeof(uint32_t) * 2 +
            sizeof(resp->opp[0]) * le16_to_cpu(resp->num_returned);

        writel_relaxed(SCMI_SUCCESS, data->msg_payload);

        break;
    }
    case PERF_LEVEL_SET:
    {
        struct scmi_perf_set_level *req = (void*)data->msg_payload;
        enum vscmi_opp opp;
        uint32_t perf_domain = le32_to_cpu(req->domain);
        int level = le32_to_cpu(req->level);

        if ( perf_domain >= current->domain->max_vcpus )
        {
            writel_relaxed(SCMI_ERR_RANGE, data->msg_payload);
            data->length = sizeof(uint32_t) * 2;
            break;
        }

        for ( opp = VSCMI_OPP_MIN; opp <= VSCMI_OPP_TURBO; opp++ )
            if ( opp_table[opp] == level )
                break;

        if ( opp > VSCMI_OPP_TURBO )
        {
            gprintk(XENLOG_WARNING, "vscmi: can't find OPP for perf level %d\n", level);
            writel_relaxed(SCMI_ERR_PARAMS, data->msg_payload);
            data->length = sizeof(uint32_t) * 2;
            break;
        }

        current->domain->vcpu[perf_domain]->arch.opp = opp;

        writel_relaxed(SCMI_SUCCESS, data->msg_payload);
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
        writel_relaxed(opp_table[current->domain->vcpu[perf_domain]->arch.opp],
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

    data = (struct scmi_shared_mem*)xzalloc_array(char, 256);
    if ( !data )
    {
        gprintk(XENLOG_ERR, "Could not allocate buffer for SCMI SHM\n");
        return false;
    }

    flush_page_to_ram(scmi_mfn, false);
    res = access_guest_memory_by_ipa(current->domain, scmi_ipa, data, 256,
                                     false);
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

    res = access_guest_memory_by_ipa(current->domain, scmi_ipa, data, 256,
                                     true);

    flush_page_to_ram(scmi_mfn, false);
    if ( res )
    {
        gprintk(XENLOG_ERR, "Error writing guest memory %d\n", res);
        goto err;
    }

err:
    xfree(data);
    return !res;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
