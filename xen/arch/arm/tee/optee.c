/*
 * xen/arch/arm/tee/optee.c
 *
 * OP-TEE mediator
 *
 * Volodymyr Babchuk <volodymyr_babchuk@epam.com>
 * Copyright (c) 2018 EPAM Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <xen/device_tree.h>
#include <xen/domain_page.h>
#include <xen/err.h>
#include <xen/guest_access.h>
#include <xen/mm.h>
#include <xen/sched.h>

#include <asm/event.h>
#include <asm/smccc.h>
#include <asm/tee/tee.h>
#include <asm/tee/optee_msg.h>
#include <asm/tee/optee_smc.h>

/*
 * "The return code is an error that originated within the underlying
 * communications stack linking the rich OS with the TEE" as described
 * in GP TEE Client API Specification.
 */
#define TEEC_ORIGIN_COMMS 0x00000002

/* "Non-specific cause" */
#define TEEC_ERROR_GENERIC 0xFFFF0000

/*
 * "Input parameters were invalid" as described
 * in GP TEE Client API Specification.
 */
#define TEEC_ERROR_BAD_PARAMETERS 0xFFFF0006

/* "System ran out of resources" */
#define TEEC_ERROR_OUT_OF_MEMORY 0xFFFF000C

/* Client ID 0 is reserved for hypervisor itself */
#define OPTEE_CLIENT_ID(domain) ((domain)->domain_id + 1)

/*
 * Default maximal number concurrent threads that OP-TEE supports.
 * This limits number of standard calls that guest can have.
 */
#define DEF_MAX_OPTEE_THREADS 16

/*
 * Maximum total number of pages that guest can share with
 * OP-TEE. Currently value is selected arbitrary. Actual number of
 * pages depends on free heap in OP-TEE. As we can't do any
 * assumptions about OP-TEE heap usage, we limit number of pages
 * arbitrary.
 */
#define MAX_TOTAL_SMH_BUF_PG    16384

#define OPTEE_KNOWN_NSEC_CAPS OPTEE_SMC_NSEC_CAP_UNIPROCESSOR
#define OPTEE_KNOWN_SEC_CAPS (OPTEE_SMC_SEC_CAP_HAVE_RESERVED_SHM | \
                              OPTEE_SMC_SEC_CAP_UNREGISTERED_SHM | \
                              OPTEE_SMC_SEC_CAP_DYNAMIC_SHM)

static unsigned int max_optee_threads = DEF_MAX_OPTEE_THREADS;

/*
 * Call context. OP-TEE can issue multiple RPC returns during one call.
 * We need to preserve context during them.
 */
struct optee_std_call {
    struct list_head list;
    /* Page where shadowed copy of call arguments is stored */
    struct page_info *xen_arg_pg;
    /* Above page mapped into XEN */
    struct optee_msg_arg *xen_arg;
    /* Address of original call arguments */
    paddr_t guest_arg_ipa;
    int optee_thread_id;
    int rpc_op;
    uint64_t rpc_data_cookie;
    bool in_flight;
    register_t rpc_params[2];
};

/* Pre-allocated SHM buffer for RPC commands */
struct shm_rpc {
    struct list_head list;
    struct page_info *guest_page;
    struct page_info *xen_arg_pg;
    struct optee_msg_arg *xen_arg;
    gfn_t gfn;
    uint64_t cookie;
};

/* Shared memory buffer for arbitrary data */
struct optee_shm_buf {
    struct list_head list;
    uint64_t cookie;
    unsigned int page_cnt;
    /*
     * Shadowed container for list of pages that guest tries to share
     * with OP-TEE. This is not the list of pages that guest shared
     * with OP-TEE, but container for list of those pages. Check
     * OPTEE_MSG_ATTR_NONCONTIG definition in optee_msg.h for more
     * information.
     */
    struct page_info *pg_list;
    unsigned int pg_list_order;
    /* Pinned guest pages that are shared with OP-TEE */
    struct page_info *pages[];
};

/* Domain context */
struct optee_domain {
    struct list_head call_list;
    struct list_head shm_rpc_list;
    struct list_head optee_shm_buf_list;
    atomic_t call_count;
    atomic_t optee_shm_buf_pages;
    spinlock_t lock;
};

static bool optee_probe(void)
{
    struct dt_device_node *node;
    struct arm_smccc_res resp;

    /* Check for entry in dtb */
    node = dt_find_compatible_node(NULL, NULL, "linaro,optee-tz");
    if ( !node )
        return false;

    /* Check UID */
    arm_smccc_smc(ARM_SMCCC_CALL_UID_FID(TRUSTED_OS_END), &resp);

    if ( (uint32_t)resp.a0 != OPTEE_MSG_UID_0 ||
         (uint32_t)resp.a1 != OPTEE_MSG_UID_1 ||
         (uint32_t)resp.a2 != OPTEE_MSG_UID_2 ||
         (uint32_t)resp.a3 != OPTEE_MSG_UID_3 )
        return false;

    /* Read number of threads */
    arm_smccc_smc(OPTEE_SMC_GET_CONFIG, OPTEE_SMC_CONFIG_NUM_THREADS, &resp);
    if ( resp.a0 == OPTEE_SMC_RETURN_OK )
    {
        max_optee_threads = resp.a1;
        printk(XENLOG_DEBUG "OP-TEE supports %u threads.\n", max_optee_threads);
    }

    return true;
}

static int optee_domain_init(struct domain *d)
{
    struct arm_smccc_res resp;
    struct optee_domain *ctx;

    ctx = xzalloc(struct optee_domain);
    if ( !ctx )
        return -ENOMEM;

    /*
     * Inform OP-TEE about a new guest.
     * This is a "Fast" call in terms of OP-TEE. This basically
     * means that it can't be preempted, because there is no
     * thread allocated for it in OP-TEE. It is close to atomic
     * context in linux kernel: E.g. no blocking calls can be issued.
     * Also, interrupts are disabled.
     *
     * a7 should be 0, so we can't skip last 6 parameters of arm_smccc_smc()
     */
    arm_smccc_smc(OPTEE_SMC_VM_CREATED, OPTEE_CLIENT_ID(d), 0, 0, 0, 0, 0, 0,
                  &resp);
    if ( resp.a0 != OPTEE_SMC_RETURN_OK )
    {
        gprintk(XENLOG_WARNING, "Unable to create OPTEE client: rc = 0x%X\n",
                (uint32_t)resp.a0);

        xfree(ctx);

        return -ENODEV;
    }

    INIT_LIST_HEAD(&ctx->call_list);
    INIT_LIST_HEAD(&ctx->shm_rpc_list);
    INIT_LIST_HEAD(&ctx->optee_shm_buf_list);
    atomic_set(&ctx->call_count, 0);
    atomic_set(&ctx->optee_shm_buf_pages, 0);
    spin_lock_init(&ctx->lock);

    d->arch.tee = ctx;

    return 0;
}

static void forward_call(struct cpu_user_regs *regs)
{
    struct arm_smccc_res resp;

    arm_smccc_smc(get_user_reg(regs, 0),
                  get_user_reg(regs, 1),
                  get_user_reg(regs, 2),
                  get_user_reg(regs, 3),
                  get_user_reg(regs, 4),
                  get_user_reg(regs, 5),
                  get_user_reg(regs, 6),
                  OPTEE_CLIENT_ID(current->domain),
                  &resp);

    set_user_reg(regs, 0, resp.a0);
    set_user_reg(regs, 1, resp.a1);
    set_user_reg(regs, 2, resp.a2);
    set_user_reg(regs, 3, resp.a3);
    set_user_reg(regs, 4, 0);
    set_user_reg(regs, 5, 0);
    set_user_reg(regs, 6, 0);
    set_user_reg(regs, 7, 0);
}

static void set_return(struct cpu_user_regs *regs, uint32_t ret)
{
    set_user_reg(regs, 0, ret);
    set_user_reg(regs, 1, 0);
    set_user_reg(regs, 2, 0);
    set_user_reg(regs, 3, 0);
    set_user_reg(regs, 4, 0);
    set_user_reg(regs, 5, 0);
    set_user_reg(regs, 6, 0);
    set_user_reg(regs, 7, 0);
}

static uint64_t regpair_to_uint64(struct cpu_user_regs *regs, unsigned int idx)
{
    return (uint64_t)get_user_reg(regs, idx) << 32 |
           (uint32_t)get_user_reg(regs, idx + 1);
}

static void uint64_to_regpair(struct cpu_user_regs *regs, unsigned int idx,
                              uint64_t val)
{
    set_user_reg(regs, idx, val >> 32);
    set_user_reg(regs, idx + 1, (uint32_t)val);
}

static struct optee_std_call *allocate_std_call(struct optee_domain *ctx)
{
    struct optee_std_call *call;
    int count;

    /* Make sure that guest does not execute more than max_optee_threads */
    count = atomic_add_unless(&ctx->call_count, 1, max_optee_threads);
    if ( count == max_optee_threads )
        return ERR_PTR(-ENOSPC);

    call = xzalloc(struct optee_std_call);
    if ( !call )
    {
        atomic_dec(&ctx->call_count);
        return ERR_PTR(-ENOMEM);
    }

    call->optee_thread_id = -1;
    call->in_flight = true;

    spin_lock(&ctx->lock);
    list_add_tail(&call->list, &ctx->call_list);
    spin_unlock(&ctx->lock);

    return call;
}

static void free_std_call(struct optee_domain *ctx,
                          struct optee_std_call *call)
{
    atomic_dec(&ctx->call_count);

    spin_lock(&ctx->lock);
    list_del(&call->list);
    spin_unlock(&ctx->lock);

    ASSERT(!call->in_flight);
    ASSERT(!call->xen_arg);

    if ( call->xen_arg_pg )
        free_domheap_page(call->xen_arg_pg);

    xfree(call);
}

static void map_xen_arg(struct optee_std_call *call)
{
    ASSERT(!call->xen_arg);

    call->xen_arg = __map_domain_page(call->xen_arg_pg);
}

static void unmap_xen_arg(struct optee_std_call *call)
{
    if ( !call->xen_arg )
        return;

    unmap_domain_page(call->xen_arg);
    call->xen_arg = NULL;
}

static struct optee_std_call *get_std_call(struct optee_domain *ctx,
                                           int thread_id)
{
    struct optee_std_call *call;

    spin_lock(&ctx->lock);
    list_for_each_entry( call, &ctx->call_list, list )
    {
        if ( call->optee_thread_id == thread_id )
        {
            if ( call->in_flight )
            {
                gdprintk(XENLOG_WARNING, "Guest tries to execute call which is already in flight\n");
                goto out;
            }
            call->in_flight = true;
            map_xen_arg(call);
            spin_unlock(&ctx->lock);

            return call;
        }
    }

out:
    spin_unlock(&ctx->lock);

    return NULL;
}

static void put_std_call(struct optee_domain *ctx, struct optee_std_call *call)
{
    spin_lock(&ctx->lock);
    ASSERT(call->in_flight);
    unmap_xen_arg(call);
    call->in_flight = false;
    spin_unlock(&ctx->lock);
}

static struct shm_rpc *allocate_and_pin_shm_rpc(struct optee_domain *ctx,
                                                gfn_t gfn, uint64_t cookie)
{
    struct shm_rpc *shm_rpc, *shm_rpc_tmp;
    p2m_type_t t;

    shm_rpc = xzalloc(struct shm_rpc);
    if ( !shm_rpc )
        return ERR_PTR(-ENOMEM);

    shm_rpc->xen_arg_pg = alloc_domheap_page(current->domain, 0);
    if ( !shm_rpc->xen_arg_pg )
    {
        xfree(shm_rpc);
        return ERR_PTR(-ENOMEM);
    }

    /* This page will be shared with OP-TEE, so we need to pin it. */
    shm_rpc->guest_page = get_page_from_gfn(current->domain, gfn_x(gfn), &t,
                                            P2M_ALLOC);
    if ( !shm_rpc->guest_page || t != p2m_ram_rw )
        goto err;
    shm_rpc->gfn = gfn;

    shm_rpc->cookie = cookie;

    spin_lock(&ctx->lock);
    /* Check if there is existing SHM with the same cookie. */
    list_for_each_entry( shm_rpc_tmp, &ctx->shm_rpc_list, list )
    {
        if ( shm_rpc_tmp->cookie == cookie )
        {
            spin_unlock(&ctx->lock);
            gdprintk(XENLOG_WARNING, "Guest tries to use the same RPC SHM cookie %lx\n",
                     cookie);
            goto err;
        }
    }

    list_add_tail(&shm_rpc->list, &ctx->shm_rpc_list);
    spin_unlock(&ctx->lock);

    return shm_rpc;

err:
    free_domheap_page(shm_rpc->xen_arg_pg);

    if ( shm_rpc->guest_page )
        put_page(shm_rpc->guest_page);

    xfree(shm_rpc);

    return ERR_PTR(-EINVAL);
}

static void free_shm_rpc(struct optee_domain *ctx, uint64_t cookie)
{
    struct shm_rpc *shm_rpc;
    bool found = false;

    spin_lock(&ctx->lock);

    list_for_each_entry( shm_rpc, &ctx->shm_rpc_list, list )
    {
        if ( shm_rpc->cookie == cookie )
        {
            found = true;
            list_del(&shm_rpc->list);
            break;
        }
    }
    spin_unlock(&ctx->lock);

    if ( !found )
        return;

    free_domheap_page(shm_rpc->xen_arg_pg);

    ASSERT(shm_rpc->guest_page);
    put_page(shm_rpc->guest_page);

    xfree(shm_rpc);
}

static struct shm_rpc *find_shm_rpc(struct optee_domain *ctx, uint64_t cookie)
{
    struct shm_rpc *shm_rpc;

    spin_lock(&ctx->lock);
    list_for_each_entry( shm_rpc, &ctx->shm_rpc_list, list )
    {
        if ( shm_rpc->cookie == cookie )
        {
                spin_unlock(&ctx->lock);
                return shm_rpc;
        }
    }
    spin_unlock(&ctx->lock);

    return NULL;
}

static struct optee_shm_buf *allocate_optee_shm_buf(struct optee_domain *ctx,
                                                    uint64_t cookie,
                                                    unsigned int pages_cnt,
                                                    struct page_info *pg_list,
                                                    unsigned int pg_list_order)
{
    struct optee_shm_buf *optee_shm_buf, *optee_shm_buf_tmp;
    int old, new;
    int err_code;

    do
    {
        old = atomic_read(&ctx->optee_shm_buf_pages);
        new = old + pages_cnt;
        if ( new >= MAX_TOTAL_SMH_BUF_PG )
            return ERR_PTR(-ENOMEM);
    }
    while ( unlikely(old != atomic_cmpxchg(&ctx->optee_shm_buf_pages,
                                           old, new)) );

    optee_shm_buf = xzalloc_bytes(sizeof(struct optee_shm_buf) +
                                  pages_cnt * sizeof(struct page *));
    if ( !optee_shm_buf )
    {
        err_code = -ENOMEM;
        goto err;
    }

    optee_shm_buf->cookie = cookie;
    optee_shm_buf->pg_list = pg_list;
    optee_shm_buf->pg_list_order = pg_list_order;

    spin_lock(&ctx->lock);
    /* Check if there is already SHM with the same cookie */
    list_for_each_entry( optee_shm_buf_tmp, &ctx->optee_shm_buf_list, list )
    {
        if ( optee_shm_buf_tmp->cookie == cookie )
        {
            spin_unlock(&ctx->lock);
            gdprintk(XENLOG_WARNING, "Guest tries to use the same SHM buffer cookie %lx\n",
                     cookie);
            err_code = -EINVAL;
            goto err;
        }
    }

    list_add_tail(&optee_shm_buf->list, &ctx->optee_shm_buf_list);
    spin_unlock(&ctx->lock);

    return optee_shm_buf;

err:
    xfree(optee_shm_buf);
    atomic_sub(pages_cnt, &ctx->optee_shm_buf_pages);

    return ERR_PTR(err_code);
}

static void free_pg_list(struct optee_shm_buf *optee_shm_buf)
{
    if ( optee_shm_buf->pg_list )
    {
        free_domheap_pages(optee_shm_buf->pg_list,
                           optee_shm_buf->pg_list_order);
        optee_shm_buf->pg_list = NULL;
    }
}

static void free_optee_shm_buf(struct optee_domain *ctx, uint64_t cookie)
{
    struct optee_shm_buf *optee_shm_buf;
    bool found = false;

    spin_lock(&ctx->lock);
    list_for_each_entry( optee_shm_buf, &ctx->optee_shm_buf_list, list )
    {
        if ( optee_shm_buf->cookie == cookie )
        {
            found = true;
            list_del(&optee_shm_buf->list);
            break;
        }
    }
    spin_unlock(&ctx->lock);

    if ( !found )
        return;

    for ( int i = 0; i < optee_shm_buf->page_cnt; i++ )
        if ( optee_shm_buf->pages[i] )
            put_page(optee_shm_buf->pages[i]);

    free_pg_list(optee_shm_buf);

    atomic_sub(optee_shm_buf->page_cnt, &ctx->optee_shm_buf_pages);

    xfree(optee_shm_buf);
}

static void free_optee_shm_buf_pg_list(struct optee_domain *ctx,
                                       uint64_t cookie)
{
    struct optee_shm_buf *optee_shm_buf;
    bool found = false;

    spin_lock(&ctx->lock);
    list_for_each_entry( optee_shm_buf, &ctx->optee_shm_buf_list, list )
    {
        if ( optee_shm_buf->cookie == cookie )
        {
            found = true;
            break;
        }
    }
    spin_unlock(&ctx->lock);

    if ( found )
        free_pg_list(optee_shm_buf);
    else
        gdprintk(XENLOG_ERR, "Can't find pagelist for SHM buffer with cookie %lx to free it\n",
                 cookie);
}

static int optee_relinquish_resources(struct domain *d)
{
    struct optee_std_call *call, *call_tmp;
    struct shm_rpc *shm_rpc, *shm_rpc_tmp;
    struct optee_shm_buf *optee_shm_buf, *optee_shm_buf_tmp;
    struct optee_domain *ctx = d->arch.tee;

    if ( !ctx )
        return 0;

    list_for_each_entry_safe( call, call_tmp, &ctx->call_list, list )
        free_std_call(ctx, call);

    if ( hypercall_preempt_check() )
        return -ERESTART;

    list_for_each_entry_safe( shm_rpc, shm_rpc_tmp, &ctx->shm_rpc_list, list )
        free_shm_rpc(ctx, shm_rpc->cookie);

    if ( hypercall_preempt_check() )
        return -ERESTART;

    list_for_each_entry_safe( optee_shm_buf, optee_shm_buf_tmp,
                              &ctx->optee_shm_buf_list, list )
        free_optee_shm_buf(ctx, optee_shm_buf->cookie);

    return 0;
}

static void optee_domain_destroy(struct domain *d)
{
    struct arm_smccc_res resp;
    struct optee_domain *ctx = d->arch.tee;

    if ( !ctx )
        return;

    /*
     * Inform OP-TEE that domain is shutting down. This is
     * also a fast SMC call, like OPTEE_SMC_VM_CREATED, so
     * it is also non-preemptible.
     * At this time all domain VCPUs should be stopped. OP-TEE
     * relies on this.
     *
     * a7 should be 0, so we can't skip last 6 parameters od arm_smccc_smc()
     */
    arm_smccc_smc(OPTEE_SMC_VM_DESTROYED, OPTEE_CLIENT_ID(d), 0, 0, 0, 0, 0, 0,
                  &resp);

    ASSERT(!spin_is_locked(&ctx->lock));
    ASSERT(!atomic_read(&ctx->call_count));
    ASSERT(!atomic_read(&ctx->optee_shm_buf_pages));
    ASSERT(list_empty(&ctx->shm_rpc_list));

    XFREE(d->arch.tee);
}

#define PAGELIST_ENTRIES_PER_PAGE                       \
    ((OPTEE_MSG_NONCONTIG_PAGE_SIZE / sizeof(u64)) - 1)

static size_t get_pages_list_size(size_t num_entries)
{
    int pages = DIV_ROUND_UP(num_entries, PAGELIST_ENTRIES_PER_PAGE);

    return pages * OPTEE_MSG_NONCONTIG_PAGE_SIZE;
}

static int translate_noncontig(struct optee_domain *ctx,
                               struct optee_std_call *call,
                               struct optee_msg_param *param)
{
    uint64_t size;
    unsigned int page_offset;
    unsigned int num_pages;
    unsigned int order;
    unsigned int entries_on_page = 0;
    gfn_t gfn;
    p2m_type_t p2m;
    struct page_info *guest_page, *xen_pages;
    struct optee_shm_buf *optee_shm_buf;
    /*
     * This is memory layout for page list. Basically list consists of 4k pages,
     * every page store 511 page addresses of user buffer and page address of
     * the next page of list.
     *
     * Refer to OPTEE_MSG_ATTR_NONCONTIG description in optee_msg.h for details.
     */
    struct {
        uint64_t pages_list[PAGELIST_ENTRIES_PER_PAGE];
        uint64_t next_page_data;
    } *pages_data_guest, *pages_data_xen;

    /* Offset of user buffer withing page */
    page_offset = param->u.tmem.buf_ptr & (OPTEE_MSG_NONCONTIG_PAGE_SIZE - 1);

    /* Size of the user buffer in bytes */
    size = ROUNDUP(param->u.tmem.size + page_offset,
                   OPTEE_MSG_NONCONTIG_PAGE_SIZE);

    num_pages = DIV_ROUND_UP(size, OPTEE_MSG_NONCONTIG_PAGE_SIZE);

    order = get_order_from_bytes(get_pages_list_size(num_pages));

    xen_pages = alloc_domheap_pages(current->domain, order, 0);
    if ( !xen_pages )
        return -ENOMEM;

    optee_shm_buf = allocate_optee_shm_buf(ctx, param->u.tmem.shm_ref,
                                           num_pages, xen_pages, order);
    if ( IS_ERR(optee_shm_buf) )
        return PTR_ERR(optee_shm_buf);

    gfn = gaddr_to_gfn(param->u.tmem.buf_ptr &
                       ~(OPTEE_MSG_NONCONTIG_PAGE_SIZE - 1));

    guest_page = get_page_from_gfn(current->domain, gfn_x(gfn), &p2m, P2M_ALLOC);
    if ( !guest_page || p2m != p2m_ram_rw )
        return -EINVAL;

    pages_data_guest = __map_domain_page(guest_page);
    pages_data_xen = __map_domain_page(xen_pages);

    while ( num_pages )
    {
        struct page_info *page;
        page = get_page_from_gfn(current->domain,
                  paddr_to_pfn(pages_data_guest->pages_list[entries_on_page]),
                  &p2m, P2M_ALLOC);

        if ( !page || p2m != p2m_ram_rw )
            goto err_unmap;

        optee_shm_buf->pages[optee_shm_buf->page_cnt++] = page;
        pages_data_xen->pages_list[entries_on_page] = page_to_maddr(page);
        entries_on_page++;

        if ( entries_on_page == PAGELIST_ENTRIES_PER_PAGE )
        {
            pages_data_xen->next_page_data = page_to_maddr(xen_pages + 1);
            unmap_domain_page(pages_data_xen);
            xen_pages++;

            gfn = gaddr_to_gfn(pages_data_guest->next_page_data);

            unmap_domain_page(pages_data_guest);
            put_page(guest_page);

            guest_page = get_page_from_gfn(current->domain, gfn_x(gfn), &p2m,
                                           P2M_ALLOC);
            if ( !guest_page || p2m != p2m_ram_rw )
                return -EINVAL;

            pages_data_guest = __map_domain_page(guest_page);
            pages_data_xen = __map_domain_page(xen_pages);
            /* Roll over to the next page */
            entries_on_page = 0;
        }
        num_pages--;
    }

    unmap_domain_page(pages_data_guest);
    unmap_domain_page(pages_data_xen);
    put_page(guest_page);

    param->u.tmem.buf_ptr = page_to_maddr(optee_shm_buf->pg_list) |
                            page_offset;

    return 0;

err_unmap:
    unmap_domain_page(pages_data_guest);
    unmap_domain_page(pages_data_xen);
    put_page(guest_page);
    free_optee_shm_buf(ctx, optee_shm_buf->cookie);

    return -EINVAL;
}

static int translate_params(struct optee_domain *ctx,
                            struct optee_std_call *call)
{
    unsigned int i;
    uint32_t attr;
    int ret = 0;

    for ( i = 0; i < call->xen_arg->num_params; i++ )
    {
        attr = call->xen_arg->params[i].attr;

        switch ( attr & OPTEE_MSG_ATTR_TYPE_MASK )
        {
        case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
        case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
        case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
            if ( attr & OPTEE_MSG_ATTR_NONCONTIG )
            {
                ret = translate_noncontig(ctx, call, call->xen_arg->params + i);
                if ( ret )
                    goto out;
            }
            else
            {
                gdprintk(XENLOG_WARNING, "Guest tries to use old tmem arg\n");
                ret = -EINVAL;
                goto out;
            }
            break;
        case OPTEE_MSG_ATTR_TYPE_NONE:
        case OPTEE_MSG_ATTR_TYPE_VALUE_INPUT:
        case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
        case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
        case OPTEE_MSG_ATTR_TYPE_RMEM_INPUT:
        case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
        case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
            continue;
        }
    }

out:
    if ( ret )
    {
        call->xen_arg->ret_origin = TEEC_ORIGIN_COMMS;
        if ( ret == -ENOMEM )
            call->xen_arg->ret = TEEC_ERROR_OUT_OF_MEMORY;
        else
            call->xen_arg->ret = TEEC_ERROR_BAD_PARAMETERS;
    }

    return ret;
}

/*
 * Copy command buffer into domheap memory to:
 * 1) Hide translated addresses from guest
 * 2) Make sure that guest wouldn't change data in command buffer during call
 */
static bool copy_std_request(struct cpu_user_regs *regs,
                             struct optee_std_call *call)
{
    paddr_t xen_addr;

    call->guest_arg_ipa = regpair_to_uint64(regs, 1);

    /*
     * Command buffer should start at page boundary.
     * This is OP-TEE ABI requirement.
     */
    if ( call->guest_arg_ipa & (OPTEE_MSG_NONCONTIG_PAGE_SIZE - 1) )
    {
        set_return(regs, OPTEE_SMC_RETURN_EBADADDR);
        return false;
    }

    BUILD_BUG_ON(OPTEE_MSG_NONCONTIG_PAGE_SIZE > PAGE_SIZE);

    call->xen_arg_pg = alloc_domheap_page(current->domain, 0);
    if ( !call->xen_arg_pg )
    {
        set_return(regs, OPTEE_SMC_RETURN_ENOMEM);
        return false;
    }

    map_xen_arg(call);

    if ( access_guest_memory_by_ipa(current->domain, call->guest_arg_ipa,
                                    call->xen_arg,
                                    OPTEE_MSG_NONCONTIG_PAGE_SIZE, false) )
    {
        set_return(regs, OPTEE_SMC_RETURN_EBADADDR);
        return false;
    }

    /* Send to OP-TEE maddr of the shadow buffer */
    xen_addr = page_to_maddr(call->xen_arg_pg);
    uint64_to_regpair(regs, 1, xen_addr);

    return true;
}

/*
 * Copy result of completed request back to guest's buffer.
 * We are copying only values that subjected to change to minimize
 * possible information leak.
 */
static void copy_std_request_back(struct optee_domain *ctx,
                                  struct cpu_user_regs *regs,
                                  struct optee_std_call *call)
{
    struct optee_msg_arg *guest_arg;
    struct page_info *page;
    p2m_type_t t;
    unsigned int i;
    uint32_t attr;

    page = get_page_from_gfn(current->domain,
                             gfn_x(gaddr_to_gfn(call->guest_arg_ipa)),
                             &t, P2M_ALLOC);
    if ( !page || t != p2m_ram_rw )
    {
        if ( page )
            put_page(page);

        /*
         * Guest did something to own command buffer during the call.
         * Now we even can't write error code to the command
         * buffer. Let's try to return generic error via
         * register. Problem is that OP-TEE does not know that guest
         * didn't received valid response. But at least guest will
         * know that something bad happened.
         */
        set_return(regs, OPTEE_SMC_RETURN_EBADADDR);

        return;
    }

    guest_arg = __map_domain_page(page);

    guest_arg->ret = call->xen_arg->ret;
    guest_arg->ret_origin = call->xen_arg->ret_origin;
    guest_arg->session = call->xen_arg->session;

    for ( i = 0; i < call->xen_arg->num_params; i++ )
    {
        attr = call->xen_arg->params[i].attr;

        switch ( attr & OPTEE_MSG_ATTR_TYPE_MASK )
        {
        case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
        case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
            guest_arg->params[i].u.tmem.size =
                call->xen_arg->params[i].u.tmem.size;
            continue;
        case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
        case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
            guest_arg->params[i].u.rmem.size =
                call->xen_arg->params[i].u.rmem.size;
            continue;
        case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
        case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
            guest_arg->params[i].u.value.a =
                call->xen_arg->params[i].u.value.a;
            guest_arg->params[i].u.value.b =
                call->xen_arg->params[i].u.value.b;
            guest_arg->params[i].u.value.c =
                call->xen_arg->params[i].u.value.c;
            continue;
        case OPTEE_MSG_ATTR_TYPE_NONE:
        case OPTEE_MSG_ATTR_TYPE_RMEM_INPUT:
        case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
            continue;
        }
    }

    unmap_domain_page(guest_arg);
    put_page(page);
}


static void free_shm_buffers(struct optee_domain *ctx,
                             struct optee_msg_arg *arg)
{
    unsigned int i;

    for ( i = 0; i < arg->num_params; i ++ )
    {
        switch ( arg->params[i].attr & OPTEE_MSG_ATTR_TYPE_MASK )
        {
        case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
        case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
        case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
            free_optee_shm_buf(ctx, arg->params[i].u.tmem.shm_ref);
            break;
        default:
            break;
        }
    }
}

/* Handle RPC return from OP-TEE */
static int handle_rpc_return(struct optee_domain *ctx,
                             struct cpu_user_regs *regs,
                             struct optee_std_call *call)
{
    int ret = 0;

    call->rpc_params[0] = get_user_reg(regs, 1);
    call->rpc_params[1] = get_user_reg(regs, 2);
    call->optee_thread_id = get_user_reg(regs, 3);
    call->rpc_op = OPTEE_SMC_RETURN_GET_RPC_FUNC(get_user_reg(regs, 0));

    if ( call->rpc_op == OPTEE_SMC_RPC_FUNC_CMD )
    {
        /* Copy RPC request from shadowed buffer to guest */
        uint64_t cookie = regpair_to_uint64(regs, 1);
        struct shm_rpc *shm_rpc = find_shm_rpc(ctx, cookie);
        if ( !shm_rpc )
        {
            /*
             * This is a very exceptional situation: OP-TEE used
             * cookie for unknown shared buffer. Something is very
             * wrong there. We can't even report error back to OP-TEE,
             * because there is no buffer where we can write return
             * code. Luckily, OP-TEE sets default error code into that
             * buffer before the call, expecting that normal world
             * will overwrite it with actual result. So we can just
             * continue the call.
             */
            gprintk(XENLOG_ERR, "Can't find SHM-RPC with cookie %lx\n", cookie);

            return -ERESTART;
        }

        shm_rpc->xen_arg = __map_domain_page(shm_rpc->xen_arg_pg);

        if ( access_guest_memory_by_ipa(current->domain,
                        gfn_to_gaddr(shm_rpc->gfn),
                        shm_rpc->xen_arg,
                        OPTEE_MSG_GET_ARG_SIZE(shm_rpc->xen_arg->num_params),
                        true) )
        {
            /*
             * We were unable to propagate request to guest, so let's return
             * back to OP-TEE.
             */
            shm_rpc->xen_arg->ret = TEEC_ERROR_GENERIC;
            ret = -ERESTART;
        }

        unmap_domain_page(shm_rpc->xen_arg);
    }

    return ret;
}

/*
 * (Re)start standard call. This function will be called in two cases:
 * 1. Guest initiates new standard call
 * 2. Guest finished RPC handling and asks OP-TEE to resume the call
 *
 * In any case OP-TEE can either complete call or issue another RPC.
 * If this is RPC - we need to store call context and return back to guest.
 * If call is complete - we need to return results with copy_std_request_back()
 * and then we will destroy the call context as it is not needed anymore.
 *
 * In some rare cases we can't propagate RPC request back to guest, so we will
 * restart the call, telling OP-TEE that request had failed.
 *
 * Shared buffers should be handled in a special way.
 */
static void execute_std_call(struct optee_domain *ctx,
                             struct cpu_user_regs *regs,
                             struct optee_std_call *call)
{
    register_t optee_ret;

    while ( true )
    {
        forward_call(regs);

        optee_ret = get_user_reg(regs, 0);
        if ( OPTEE_SMC_RETURN_IS_RPC(optee_ret) )
        {
            if ( handle_rpc_return(ctx, regs, call)  == -ERESTART )
            {
                set_user_reg(regs, 0, OPTEE_SMC_CALL_RETURN_FROM_RPC);
                continue;
            }

            put_std_call(ctx, call);
            return;
        }
        break;
    }

    copy_std_request_back(ctx, regs, call);

    switch ( call->xen_arg->cmd )
    {
    case OPTEE_MSG_CMD_REGISTER_SHM:
        if ( call->xen_arg->ret == 0 )
            free_optee_shm_buf_pg_list(ctx,
                                   call->xen_arg->params[0].u.tmem.shm_ref);
        else
            free_optee_shm_buf(ctx, call->xen_arg->params[0].u.tmem.shm_ref);
        break;
    case OPTEE_MSG_CMD_UNREGISTER_SHM:
        if ( call->xen_arg->ret == 0 )
            free_optee_shm_buf(ctx, call->xen_arg->params[0].u.rmem.shm_ref);
        break;
    default:
        free_shm_buffers(ctx, call->xen_arg);
    }

    put_std_call(ctx, call);
    free_std_call(ctx, call);
}

static void handle_std_call(struct optee_domain *ctx,
                            struct cpu_user_regs *regs)
{
    struct optee_std_call *call = allocate_std_call(ctx);

    if ( IS_ERR(call) )
    {
        if ( PTR_ERR(call) == -ENOMEM )
            set_return(regs, OPTEE_SMC_RETURN_ENOMEM);
        else
            set_return(regs, OPTEE_SMC_RETURN_ETHREAD_LIMIT);

        return;
    }

    if ( !copy_std_request(regs, call) )
        goto err;

    switch ( call->xen_arg->cmd )
    {
    case OPTEE_MSG_CMD_OPEN_SESSION:
    case OPTEE_MSG_CMD_CLOSE_SESSION:
    case OPTEE_MSG_CMD_INVOKE_COMMAND:
    case OPTEE_MSG_CMD_CANCEL:
    case OPTEE_MSG_CMD_REGISTER_SHM:
    case OPTEE_MSG_CMD_UNREGISTER_SHM:
        if( translate_params(ctx, call) )
        {
            /*
             * translate_params() sets xen_arg->ret value to non-zero.
             * So, technically, SMC was successful, but there was an error
             * during handling standard call encapsulated into this SMC.
             */
            copy_std_request_back(ctx, regs, call);
            set_return(regs, OPTEE_SMC_RETURN_OK);
            goto err;
        }
        execute_std_call(ctx, regs, call);
        return;
    default:
        set_return(regs, OPTEE_SMC_RETURN_EBADCMD);
        break;
    }

err:
    put_std_call(ctx, call);
    free_std_call(ctx, call);

    return;
}

static void handle_rpc_cmd_alloc(struct optee_domain *ctx,
                                 struct cpu_user_regs *regs,
                                 struct optee_std_call *call,
                                 struct shm_rpc *shm_rpc)
{
    if ( shm_rpc->xen_arg->ret || shm_rpc->xen_arg->num_params != 1 )
        return;

    if ( shm_rpc->xen_arg->params[0].attr != (OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT |
                                              OPTEE_MSG_ATTR_NONCONTIG) )
    {
        gdprintk(XENLOG_WARNING, "Invalid attrs for shared mem buffer: %lx\n",
                 shm_rpc->xen_arg->params[0].attr);
        return;
    }

    /* Free pg list for buffer */
    if ( call->rpc_data_cookie )
        free_optee_shm_buf_pg_list(ctx, call->rpc_data_cookie);

    if ( !translate_noncontig(ctx, call, &shm_rpc->xen_arg->params[0]) )
    {
        call->rpc_data_cookie =
            shm_rpc->xen_arg->params[0].u.tmem.shm_ref;
    }
    else
    {
        call->rpc_data_cookie = 0;
        /*
         * Okay, so there was problem with guest's buffer and we need
         * to tell about this to OP-TEE.
         */
        shm_rpc->xen_arg->ret = TEEC_ERROR_GENERIC;
        shm_rpc->xen_arg->num_params = 0;
        /*
         * TODO: With current implementation, OP-TEE will not issue
         * RPC to free this buffer. Guest and OP-TEE will be out of
         * sync: guest believes that it provided buffer to OP-TEE,
         * while OP-TEE thinks of opposite. Ideally, we need to
         * emulate RPC with OPTEE_MSG_RPC_CMD_SHM_FREE command.
         */
    }
}

static void handle_rpc_cmd(struct optee_domain *ctx, struct cpu_user_regs *regs,
                           struct optee_std_call *call)
{
    struct shm_rpc *shm_rpc;
    uint64_t cookie;
    size_t arg_size;

    cookie = regpair_to_uint64(regs, 1);

    shm_rpc = find_shm_rpc(ctx, cookie);

    if ( !shm_rpc )
    {
        gdprintk(XENLOG_ERR, "Can't find SHM-RPC with cookie %lx\n", cookie);
        return;
    }

    shm_rpc->xen_arg = __map_domain_page(shm_rpc->xen_arg_pg);

    /* First, copy only header to read number of arguments */
    if ( access_guest_memory_by_ipa(current->domain,
                                    gfn_to_gaddr(shm_rpc->gfn),
                                    shm_rpc->xen_arg,
                                    sizeof(struct optee_msg_arg),
                                    false) )
    {
        shm_rpc->xen_arg->ret = TEEC_ERROR_GENERIC;
        goto out;
    }

    arg_size = OPTEE_MSG_GET_ARG_SIZE(shm_rpc->xen_arg->num_params);
    if ( arg_size > OPTEE_MSG_NONCONTIG_PAGE_SIZE )
    {
        shm_rpc->xen_arg->ret = TEEC_ERROR_GENERIC;
        goto out;
    }

    /* Read the whole command structure */
    if ( access_guest_memory_by_ipa(current->domain, gfn_to_gaddr(shm_rpc->gfn),
                                    shm_rpc->xen_arg, arg_size, false) )
    {
        shm_rpc->xen_arg->ret = TEEC_ERROR_GENERIC;
        goto out;
    }

    switch (shm_rpc->xen_arg->cmd)
    {
    case OPTEE_MSG_RPC_CMD_GET_TIME:
    case OPTEE_MSG_RPC_CMD_WAIT_QUEUE:
    case OPTEE_MSG_RPC_CMD_SUSPEND:
        break;
    case OPTEE_MSG_RPC_CMD_SHM_ALLOC:
        handle_rpc_cmd_alloc(ctx, regs, call, shm_rpc);
        break;
    case OPTEE_MSG_RPC_CMD_SHM_FREE:
        free_optee_shm_buf(ctx, shm_rpc->xen_arg->params[0].u.value.b);
        if ( call->rpc_data_cookie == shm_rpc->xen_arg->params[0].u.value.b )
            call->rpc_data_cookie = 0;
        break;
    default:
        break;
    }

out:
    unmap_domain_page(shm_rpc->xen_arg);
}

static void handle_rpc_func_alloc(struct optee_domain *ctx,
                                  struct cpu_user_regs *regs)
{
    struct shm_rpc *shm_rpc;
    paddr_t ptr = regpair_to_uint64(regs, 1);
    uint64_t cookie = regpair_to_uint64(regs, 4);

    if ( ptr & (OPTEE_MSG_NONCONTIG_PAGE_SIZE - 1) )
    {
        gdprintk(XENLOG_WARNING, "Domain returned invalid RPC command buffer\n");
        /*
         * OP-TEE is waiting for a response to the RPC. We can't just
         * return error to the guest. We need to provide some invalid
         * value to OP-TEE, so it can handle error on its side.
         */
        ptr = 0;
        goto out;
    }

    shm_rpc = allocate_and_pin_shm_rpc(ctx, gaddr_to_gfn(ptr), cookie);
    if ( IS_ERR(shm_rpc) )
    {
        gdprintk(XENLOG_WARNING, "Failed to allocate shm_rpc object: %ld\n",
                 PTR_ERR(shm_rpc));
        ptr = 0;
    }
    else
        ptr = page_to_maddr(shm_rpc->xen_arg_pg);

out:
    uint64_to_regpair(regs, 1, ptr);
}

static void handle_rpc(struct optee_domain *ctx, struct cpu_user_regs *regs)
{
    struct optee_std_call *call;
    int optee_thread_id = get_user_reg(regs, 3);

    call = get_std_call(ctx, optee_thread_id);

    if ( !call )
    {
        set_return(regs, OPTEE_SMC_RETURN_ERESUME);
        return;
    }

    /*
     * This is to prevent race between new call with the same thread id.
     * OP-TEE can reuse thread id right after it finished handling the call,
     * before XEN had chance to free old call context.
     */
    call->optee_thread_id = -1;

    switch ( call->rpc_op )
    {
    case OPTEE_SMC_RPC_FUNC_ALLOC:
        handle_rpc_func_alloc(ctx, regs);
        break;
    case OPTEE_SMC_RPC_FUNC_FREE:
    {
        uint64_t cookie = (uint64_t)call->rpc_params[0] << 32 |
                          (uint32_t)call->rpc_params[1];
        free_shm_rpc(ctx, cookie);
        break;
    }
    case OPTEE_SMC_RPC_FUNC_FOREIGN_INTR:
        break;
    case OPTEE_SMC_RPC_FUNC_CMD:
        handle_rpc_cmd(ctx, regs, call);
        break;
    }

    execute_std_call(ctx, regs, call);

    return;
}

static void handle_exchange_capabilities(struct cpu_user_regs *regs)
{
    uint32_t caps;

    /* Filter out unknown guest caps */
    caps = get_user_reg(regs, 1);
    caps &= OPTEE_KNOWN_NSEC_CAPS;
    set_user_reg(regs, 1, caps);

    forward_call(regs);
    if ( get_user_reg(regs, 0) != OPTEE_SMC_RETURN_OK )
        return;

    caps = get_user_reg(regs, 1);

    /* Filter out unknown OP-TEE caps */
    caps &= OPTEE_KNOWN_SEC_CAPS;

    /* Drop static SHM_RPC cap */
    caps &= ~OPTEE_SMC_SEC_CAP_HAVE_RESERVED_SHM;

    /* Don't allow guests to work without dynamic SHM */
    if ( !(caps & OPTEE_SMC_SEC_CAP_DYNAMIC_SHM) )
    {
        set_return(regs, OPTEE_SMC_RETURN_ENOTAVAIL);
        return;
    }

    set_user_reg(regs, 1, caps);
}

static bool optee_handle_call(struct cpu_user_regs *regs)
{
    struct optee_domain *ctx = current->domain->arch.tee;

    if ( !ctx )
        return false;

    switch ( get_user_reg(regs, 0) )
    {
    case OPTEE_SMC_CALLS_COUNT:
    case OPTEE_SMC_CALLS_UID:
    case OPTEE_SMC_CALLS_REVISION:
    case OPTEE_SMC_CALL_GET_OS_UUID:
    case OPTEE_SMC_FUNCID_GET_OS_REVISION:
    case OPTEE_SMC_ENABLE_SHM_CACHE:
    case OPTEE_SMC_DISABLE_SHM_CACHE:
        forward_call(regs);
        return true;
    case OPTEE_SMC_GET_SHM_CONFIG:
        /* No static SHM available for guests */
        set_return(regs, OPTEE_SMC_RETURN_ENOTAVAIL);
        return true;
    case OPTEE_SMC_EXCHANGE_CAPABILITIES:
        handle_exchange_capabilities(regs);
        return true;
    case OPTEE_SMC_CALL_WITH_ARG:
        handle_std_call(ctx, regs);
        return true;
    case OPTEE_SMC_CALL_RETURN_FROM_RPC:
        handle_rpc(ctx, regs);
        return true;
    default:
        return false;
    }
}

static const struct tee_mediator_ops optee_ops =
{
    .probe = optee_probe,
    .domain_init = optee_domain_init,
    .domain_destroy = optee_domain_destroy,
    .relinquish_resources = optee_relinquish_resources,
    .handle_call = optee_handle_call,
};

REGISTER_TEE_MEDIATOR(optee, "OP-TEE", &optee_ops);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
