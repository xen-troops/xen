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
#include <xen/sched.h>
#include <asm/smccc.h>
#include <asm/tee/tee.h>

#include <asm/tee/optee_msg.h>
#include <asm/tee/optee_smc.h>

/* Client ID 0 is reserved for hypervisor itself */
#define OPTEE_CLIENT_ID(domain) (domain->domain_id + 1)

#define OPTEE_KNOWN_NSEC_CAPS OPTEE_SMC_NSEC_CAP_UNIPROCESSOR
#define OPTEE_KNOWN_SEC_CAPS (OPTEE_SMC_SEC_CAP_HAVE_RESERVED_SHM | \
                              OPTEE_SMC_SEC_CAP_UNREGISTERED_SHM |  \
                              OPTEE_SMC_SEC_CAP_DYNAMIC_SHM)

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
        return -ENODEV;
    }

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

static void optee_domain_destroy(struct domain *d)
{
    struct arm_smccc_res resp;

    /* At this time all domain VCPUs should be stopped */

    /*
     * Inform OP-TEE that domain is shutting down. This is
     * also a fast SMC call, like OPTEE_SMC_VM_CREATED, so
     * it is also non-preemptible.
     */
    arm_smccc_smc(OPTEE_SMC_VM_DESTROYED, OPTEE_CLIENT_ID(d), 0, 0, 0, 0, 0, 0,
                  &resp);
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
    switch ( get_user_reg(regs, 0) )
    {
    case OPTEE_SMC_CALLS_COUNT:
    case OPTEE_SMC_CALLS_UID:
    case OPTEE_SMC_CALLS_REVISION:
    case OPTEE_SMC_CALL_GET_OS_UUID:
    case OPTEE_SMC_FUNCID_GET_OS_REVISION:
    case OPTEE_SMC_ENABLE_SHM_CACHE:
    case OPTEE_SMC_DISABLE_SHM_CACHE:
    case OPTEE_SMC_CALL_WITH_ARG:
    case OPTEE_SMC_CALL_RETURN_FROM_RPC:
        forward_call(regs);
        return true;
    case OPTEE_SMC_GET_SHM_CONFIG:
        /* No static SHM available for guests */
        set_return(regs, OPTEE_SMC_RETURN_ENOTAVAIL);
        return true;
    case OPTEE_SMC_EXCHANGE_CAPABILITIES:
        return handle_exchange_capabilities(regs);
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
