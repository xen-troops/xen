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

#include <asm/smccc.h>
#include <asm/tee/tee.h>
#include <asm/tee/optee_msg.h>
#include <asm/tee/optee_smc.h>

/* Client ID 0 is reserved for hypervisor itself */
#define OPTEE_CLIENT_ID(domain) ((domain)->domain_id + 1)

/*
 * Default maximal number concurrent threads that OP-TEE supports.
 * This limits number of standard calls that guest can have.
 */
#define DEF_MAX_OPTEE_THREADS 16

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
    bool in_flight;
};

/* Domain context */
struct optee_domain {
    struct list_head call_list;
    atomic_t call_count;
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
    atomic_set(&ctx->call_count, 0);
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

static int optee_relinquish_resources(struct domain *d)
{
    struct optee_std_call *call, *call_tmp;
    struct optee_domain *ctx = d->arch.tee;

    if ( !ctx )
        return 0;

    list_for_each_entry_safe( call, call_tmp, &ctx->call_list, list )
        free_std_call(ctx, call);

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

    XFREE(d->arch.tee);
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

/* Handle RPC return from OP-TEE */
static void handle_rpc_return(struct cpu_user_regs *regs,
                              struct optee_std_call *call)
{
    call->optee_thread_id = get_user_reg(regs, 3);
    call->rpc_op = OPTEE_SMC_RETURN_GET_RPC_FUNC(get_user_reg(regs, 0));
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
 */
static void execute_std_call(struct optee_domain *ctx,
                             struct cpu_user_regs *regs,
                             struct optee_std_call *call)
{
    register_t optee_ret;

    forward_call(regs);

    optee_ret = get_user_reg(regs, 0);
    if ( OPTEE_SMC_RETURN_IS_RPC(optee_ret) )
    {
        handle_rpc_return(regs, call);
        put_std_call(ctx, call);

        return;
    }

    copy_std_request_back(ctx, regs, call);

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
        /* TODO: Add handling */
        break;
    case OPTEE_SMC_RPC_FUNC_FREE:
        /* TODO: Add handling */
        break;
    case OPTEE_SMC_RPC_FUNC_FOREIGN_INTR:
        break;
    case OPTEE_SMC_RPC_FUNC_CMD:
        /* TODO: Add handling */
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
