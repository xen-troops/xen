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
#include <xen/guest_access.h>
#include <xen/sched.h>
#include <asm/smccc.h>
#include <asm/tee/tee.h>

#include <asm/tee/optee_msg.h>
#include <asm/tee/optee_smc.h>

/* Client ID 0 is reserved for hypervisor itself */
#define OPTEE_CLIENT_ID(domain) (domain->domain_id + 1)

/*
 * Maximal number of concurrent standard calls from one guest. This
 * corresponds to OPTEE configuration option CFG_NUM_THREADS, because
 * OP-TEE spawns a thread for every standard call.
 */
#define MAX_STD_CALLS   16
/*
 * Maximal number of pre-allocated SHM buffers. OP-TEE generally asks
 * for one SHM buffer per thread, so this also corresponds to OP-TEE
 * option CFG_NUM_THREADS
 */
#define MAX_RPC_SHMS    MAX_STD_CALLS

#define OPTEE_KNOWN_NSEC_CAPS OPTEE_SMC_NSEC_CAP_UNIPROCESSOR
#define OPTEE_KNOWN_SEC_CAPS (OPTEE_SMC_SEC_CAP_HAVE_RESERVED_SHM | \
                              OPTEE_SMC_SEC_CAP_UNREGISTERED_SHM |  \
                              OPTEE_SMC_SEC_CAP_DYNAMIC_SHM)

/*
 * Call context. OP-TEE can issue multiple RPC returns during one call.
 * We need to preserve context during them.
 */
struct optee_std_call {
    struct list_head list;
    struct optee_msg_arg *xen_arg;
    paddr_t guest_arg_ipa;
    int optee_thread_id;
    int rpc_op;
    bool in_flight;
    register_t rpc_params[2];
};

/* Pre-allocated SHM buffer for RPC commands */
struct shm_rpc {
    struct list_head list;
    struct page_info *guest_page;
    uint64_t cookie;
};

/* Domain context */
struct optee_domain {
    struct list_head call_list;
    struct list_head shm_rpc_list;
    atomic_t call_count;
    atomic_t shm_rpc_count;
    spinlock_t lock;
};

static bool optee_probe(void)
{
    struct dt_device_node *node;
    struct arm_smccc_res resp;

    /* Check for entry in dtb  */
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

    return true;
}

static int optee_enable(struct domain *d)
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
     * Right now OP-TEE just frees allocated memory, so it should be
     * really fast.
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

    atomic_set(&ctx->call_count, 0);
    atomic_set(&ctx->shm_rpc_count, 0);

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

static struct optee_std_call *allocate_std_call(struct optee_domain *ctx)
{
    struct optee_std_call *call;
    int count;

    /* Make sure that guest does not execute more than MAX_STD_CALLS */
    count = atomic_add_unless(&ctx->call_count, 1, MAX_STD_CALLS);
    if ( count == MAX_STD_CALLS )
        return NULL;

    call = xzalloc(struct optee_std_call);
    if ( !call )
    {
        atomic_dec(&ctx->call_count);
        return NULL;
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
    xfree(call->xen_arg);
    xfree(call);
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
                gprintk(XENLOG_WARNING, "Guest tries to execute call which is already in flight");
                goto out;
            }
            call->in_flight = true;
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
    call->in_flight = false;
    spin_unlock(&ctx->lock);
}

static struct shm_rpc *allocate_and_pin_shm_rpc(struct optee_domain *ctx,
                                                paddr_t gaddr,
                                                uint64_t cookie)
{
    struct shm_rpc *shm_rpc, *shm_rpc_tmp;
    int count;

    /* Make sure that guest does not allocate more than MAX_RPC_SHMS */
    count = atomic_add_unless(&ctx->shm_rpc_count, 1, MAX_RPC_SHMS);
    if ( count == MAX_RPC_SHMS )
        return NULL;

    shm_rpc = xzalloc(struct shm_rpc);
    if ( !shm_rpc )
        goto err;

    /* This page will be shared with OP-TEE, so we need to pin it */
    shm_rpc->guest_page = get_page_from_gfn(current->domain,
                                            paddr_to_pfn(gaddr),
                                            NULL,
                                            P2M_ALLOC);
    if ( !shm_rpc->guest_page )
        goto err;

    shm_rpc->cookie = cookie;

    spin_lock(&ctx->lock);
    /* Check if there is already SHM with the same cookie */
    list_for_each_entry( shm_rpc_tmp, &ctx->shm_rpc_list, list )
    {
        if ( shm_rpc_tmp->cookie == cookie )
        {
            spin_unlock(&ctx->lock);
            gprintk(XENLOG_WARNING, "Guest tries to use the same RPC SHM cookie");
            goto err;
        }
    }

    list_add_tail(&shm_rpc->list, &ctx->shm_rpc_list);
    spin_unlock(&ctx->lock);

    return shm_rpc;

err:
    atomic_dec(&ctx->shm_rpc_count);
    put_page(shm_rpc->guest_page);
    xfree(shm_rpc);

    return NULL;
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

    ASSERT(shm_rpc->guest_page);
    put_page(shm_rpc->guest_page);

    xfree(shm_rpc);
}

static void optee_domain_destroy(struct domain *d)
{
    struct arm_smccc_res resp;
    struct optee_std_call *call, *call_tmp;
    struct optee_domain *ctx = d->arch.tee;
    struct shm_rpc *shm_rpc, *shm_rpc_tmp;

    /* At this time all domain VCPUs should be stopped */

    /*
     * Inform OP-TEE that domain is shutting down. This is
     * also a fast SMC call, like OPTEE_SMC_VM_CREATED, so
     * it is also non-preemptible.
     */
    arm_smccc_smc(OPTEE_SMC_VM_DESTROYED, OPTEE_CLIENT_ID(d), 0, 0, 0, 0, 0, 0,
                  &resp);
    ASSERT(!spin_is_locked(&ctx->lock));

    list_for_each_entry_safe( call, call_tmp, &ctx->call_list, list )
        free_std_call(ctx, call);

    list_for_each_entry_safe( shm_rpc, shm_rpc_tmp, &ctx->shm_rpc_list, list )
        free_shm_rpc(ctx, shm_rpc->cookie);

    ASSERT(!atomic_read(&ctx->call_count));
    ASSERT(!atomic_read(&ctx->shm_rpc_count));

    xfree(d->arch.tee);
}

/*
 * Copy command buffer into xen memory to:
 * 1) Hide translated addresses from guest
 * 2) Make sure that guest wouldn't change data in command buffer during call
 */
static bool copy_std_request(struct cpu_user_regs *regs,
                             struct optee_std_call *call)
{
    paddr_t xen_addr;

    call->guest_arg_ipa = (paddr_t)get_user_reg(regs, 1) << 32 |
                            get_user_reg(regs, 2);

    /*
     * Command buffer should start at page boundary.
     * This is OP-TEE ABI requirement.
     */
    if ( call->guest_arg_ipa & (OPTEE_MSG_NONCONTIG_PAGE_SIZE - 1) )
        return false;

    call->xen_arg = _xmalloc(OPTEE_MSG_NONCONTIG_PAGE_SIZE,
                             OPTEE_MSG_NONCONTIG_PAGE_SIZE);
    if ( !call->xen_arg )
        return false;

    BUILD_BUG_ON(OPTEE_MSG_NONCONTIG_PAGE_SIZE > PAGE_SIZE);

    access_guest_memory_by_ipa(current->domain, call->guest_arg_ipa,
                               call->xen_arg, OPTEE_MSG_NONCONTIG_PAGE_SIZE,
                               false);

    xen_addr = virt_to_maddr(call->xen_arg);

    set_user_reg(regs, 1, xen_addr >> 32);
    set_user_reg(regs, 2, xen_addr & 0xFFFFFFFF);

    return true;
}

static void copy_std_request_back(struct optee_domain *ctx,
                                  struct cpu_user_regs *regs,
                                  struct optee_std_call *call)
{
    struct optee_msg_arg *guest_arg;
    struct page_info *page;
    unsigned int i;
    uint32_t attr;

    /* copy_std_request() validated IPA for us */
    page = get_page_from_gfn(current->domain, paddr_to_pfn(call->guest_arg_ipa),
                             NULL, P2M_ALLOC);
    if ( !page )
        return;

    guest_arg = map_domain_page(page_to_mfn(page));

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
        case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
        case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
            guest_arg->params[i].u.value.a =
                call->xen_arg->params[i].u.value.a;
            guest_arg->params[i].u.value.b =
                call->xen_arg->params[i].u.value.b;
            continue;
        case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
        case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
            guest_arg->params[i].u.rmem.size =
                call->xen_arg->params[i].u.rmem.size;
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

static void execute_std_call(struct optee_domain *ctx,
                             struct cpu_user_regs *regs,
                             struct optee_std_call *call)
{
    register_t optee_ret;

    forward_call(regs);

    optee_ret = get_user_reg(regs, 0);
    if ( OPTEE_SMC_RETURN_IS_RPC(optee_ret) )
    {
        call->rpc_params[0] = get_user_reg(regs, 1);
        call->rpc_params[1] = get_user_reg(regs, 2);
        call->optee_thread_id = get_user_reg(regs, 3);
        call->rpc_op = OPTEE_SMC_RETURN_GET_RPC_FUNC(optee_ret);
        put_std_call(ctx, call);
        return;
    }

    copy_std_request_back(ctx, regs, call);

    put_std_call(ctx, call);
    free_std_call(ctx, call);
}

static bool handle_std_call(struct optee_domain *ctx,
                            struct cpu_user_regs *regs)
{
    struct optee_std_call *call = allocate_std_call(ctx);

    if ( !call )
        return false;

    if ( !copy_std_request(regs, call) )
        goto err;

    /* Now we can safely examine contents of command buffer */
    if ( OPTEE_MSG_GET_ARG_SIZE(call->xen_arg->num_params) >
         OPTEE_MSG_NONCONTIG_PAGE_SIZE )
        goto err;

    switch ( call->xen_arg->cmd )
    {
    case OPTEE_MSG_CMD_OPEN_SESSION:
    case OPTEE_MSG_CMD_CLOSE_SESSION:
    case OPTEE_MSG_CMD_INVOKE_COMMAND:
    case OPTEE_MSG_CMD_CANCEL:
    case OPTEE_MSG_CMD_REGISTER_SHM:
    case OPTEE_MSG_CMD_UNREGISTER_SHM:
        break;
    default:
        goto err;
    }

    execute_std_call(ctx, regs, call);

    return true;

err:
    put_std_call(ctx, call);
    free_std_call(ctx, call);

    return false;
}

static void handle_rpc_func_alloc(struct optee_domain *ctx,
                                  struct cpu_user_regs *regs)
{
    paddr_t ptr = get_user_reg(regs, 1) << 32 | get_user_reg(regs, 2);

    if ( ptr & (OPTEE_MSG_NONCONTIG_PAGE_SIZE - 1) )
        gprintk(XENLOG_WARNING, "Domain returned invalid RPC command buffer\n");

    if ( ptr )
    {
        uint64_t cookie = get_user_reg(regs, 4) << 32 | get_user_reg(regs, 5);
        struct shm_rpc *shm_rpc;

        shm_rpc = allocate_and_pin_shm_rpc(ctx, ptr, cookie);
        if ( !shm_rpc )
        {
            gprintk(XENLOG_WARNING, "Failed to allocate shm_rpc object\n");
            ptr = 0;
        }
        else
            ptr = page_to_maddr(shm_rpc->guest_page);

        set_user_reg(regs, 1, ptr >> 32);
        set_user_reg(regs, 2, ptr & 0xFFFFFFFF);
    }
}

static bool handle_rpc(struct optee_domain *ctx, struct cpu_user_regs *regs)
{
    struct optee_std_call *call;
    int optee_thread_id = get_user_reg(regs, 3);

    call = get_std_call(ctx, optee_thread_id);

    if ( !call )
        return false;

    switch ( call->rpc_op )
    {
    case OPTEE_SMC_RPC_FUNC_ALLOC:
        handle_rpc_func_alloc(ctx, regs);
        break;
    case OPTEE_SMC_RPC_FUNC_FREE:
    {
        uint64_t cookie = call->rpc_params[0] << 32 |
                            (uint32_t)call->rpc_params[1];
        free_shm_rpc(ctx, cookie);
        break;
    }
    case OPTEE_SMC_RPC_FUNC_FOREIGN_INTR:
        break;
    case OPTEE_SMC_RPC_FUNC_CMD:
        /* TODO: Add handling */
        break;
    }

    execute_std_call(ctx, regs, call);
    return true;
}

static bool handle_exchange_capabilities(struct cpu_user_regs *regs)
{
    uint32_t caps;

    /* Filter out unknown guest caps */
    caps = get_user_reg(regs, 1);
    caps &= OPTEE_KNOWN_NSEC_CAPS;
    set_user_reg(regs, 1, caps);

    forward_call(regs);
    if ( get_user_reg(regs, 0) != OPTEE_SMC_RETURN_OK )
        return true;

    caps = get_user_reg(regs, 1);

    /* Filter out unknown OP-TEE caps */
    caps &= OPTEE_KNOWN_SEC_CAPS;

    /* Drop static SHM_RPC cap */
    caps &= ~OPTEE_SMC_SEC_CAP_HAVE_RESERVED_SHM;

    /* Don't allow guests to work without dynamic SHM */
    if ( !(caps & OPTEE_SMC_SEC_CAP_DYNAMIC_SHM) )
    {
        set_return(regs, OPTEE_SMC_RETURN_ENOTAVAIL);
        return true;
    }

    set_user_reg(regs, 1, caps);

    return true;
}

static bool optee_handle_call(struct cpu_user_regs *regs)
{
    struct optee_domain *ctx = current->domain->arch.tee;

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
        return handle_exchange_capabilities(regs);
    case OPTEE_SMC_CALL_WITH_ARG:
        return handle_std_call(ctx, regs);
    case OPTEE_SMC_CALL_RETURN_FROM_RPC:
        return handle_rpc(ctx, regs);
    default:
        return false;
    }
}

static const struct tee_mediator_ops optee_ops =
{
    .probe = optee_probe,
    .enable = optee_enable,
    .domain_destroy = optee_domain_destroy,
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
