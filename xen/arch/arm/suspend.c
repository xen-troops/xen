#include <xen/sched.h>
#include <xen/cpu.h>
#include <asm/cpufeature.h>
#include <asm/event.h>
#include <asm/psci.h>

/* Reset values of VCPU architecture specific registers */
static void vcpu_arch_reset(struct vcpu *v)
{
    v->arch.ttbr0 = 0;
    v->arch.ttbr1 = 0;
    v->arch.ttbcr = 0;

    v->arch.csselr = 0;
    v->arch.cpacr = 0;
    v->arch.contextidr = 0;
    v->arch.tpidr_el0 = 0;
    v->arch.tpidrro_el0 = 0;
    v->arch.tpidr_el1 = 0;
    v->arch.vbar = 0;
    if ( is_32bit_domain(v->domain) )
        v->arch.dacr = 0;
    v->arch.par = 0;
#if defined(CONFIG_ARM_32)
    v->arch.mair0 = 0;
    v->arch.mair1 = 0;
    v->arch.amair0 = 0;
    v->arch.amair1 = 0;
#else
    v->arch.mair = 0;
    v->arch.amair = 0;
#endif
    /* Fault Status */
#if defined(CONFIG_ARM_32)
    v->arch.dfar = 0;
    v->arch.ifar = 0;
    v->arch.dfsr = 0;
#elif defined(CONFIG_ARM_64)
    v->arch.far = 0;
    v->arch.esr = 0;
#endif

    if ( is_32bit_domain(v->domain) )
        v->arch.ifsr  = 0;
    v->arch.afsr0 = 0;
    v->arch.afsr1 = 0;

#ifdef CONFIG_ARM_32
    v->arch.joscr = 0;
    v->arch.jmcr = 0;
#endif

    if ( is_32bit_domain(v->domain) && cpu_has_thumbee )
    {
        v->arch.teecr = 0;
        v->arch.teehbr = 0;
    }
}

/*
 * This function sets the context of current VCPU to the state which is expected
 * by the guest on resume. The expected VCPU state is:
 * 1) pc to contain resume entry point (1st argument of PSCI SYSTEM_SUSPEND)
 * 2) r0/x0 to contain context ID (2nd argument of PSCI SYSTEM_SUSPEND)
 * 3) All other general purpose and system registers should have reset values
 *
 * Note: this function has to return void because it has to always succeed. In
 * other words, this function is called from virtual PSCI SYSTEM_SUSPEND
 * implementation, which can return only a limited number of possible errors,
 * none of which could represent the fact that an error occurred when preparing
 * the domain for suspend.
 * Consequently, dynamic memory allocation cannot be done within this function,
 * because if malloc fails the error has nowhere to propagate.
 */
static void vcpu_suspend(register_t epoint, register_t cid)
{
    /* Static allocation because dynamic would need a non-void return */
    static struct vcpu_guest_context ctxt;
    struct vcpu *v = current;

    /* Make sure that VCPU guest regs are zeroied */
    memset(&ctxt, 0, sizeof(ctxt));

    /* Set non-zero values to the registers prior to copying */
    ctxt.user_regs.pc64 = (u64)epoint;

    if ( is_32bit_domain(current->domain) )
    {
        ctxt.user_regs.r0_usr = cid;
        ctxt.user_regs.cpsr = PSR_GUEST32_INIT;

        /* Thumb set is allowed only for 32-bit domain */
        if ( epoint & 1 )
        {
            ctxt.user_regs.cpsr |= PSR_THUMB;
            ctxt.user_regs.pc64 &= ~(u64)1;
        }
    }
#ifdef CONFIG_ARM_64
    else
    {
        ctxt.user_regs.x0 = cid;
        ctxt.user_regs.cpsr = PSR_GUEST64_INIT;
    }
#endif
    ctxt.sctlr = SCTLR_GUEST_INIT;
    ctxt.flags = VGCF_online;

    /* Reset architecture specific registers */
    vcpu_arch_reset(v);

    /* Initialize VCPU registers */
    _arch_set_info_guest(v, &ctxt);
}

/* Xen suspend. Note: data is not used (suspend is the suspend to RAM) */
static long system_suspend(void *data)
{
    int status;

    BUG_ON(system_state != SYS_STATE_active);

    system_state = SYS_STATE_suspend;
    freeze_domains();

    status = disable_nonboot_cpus();
    if ( status )
    {
        system_state = SYS_STATE_resume;
        goto resume_nonboot_cpus;
    }

    system_state = SYS_STATE_resume;

resume_nonboot_cpus:
    enable_nonboot_cpus();
    thaw_domains();
    system_state = SYS_STATE_active;
    dsb(sy);

    return status;
}

int32_t domain_suspend(register_t epoint, register_t cid)
{
    struct vcpu *v;
    struct domain *d = current->domain;
    bool is_thumb = epoint & 1;
    int status;

    dprintk(XENLOG_DEBUG,
            "Dom%d suspend: epoint=0x%"PRIregister", cid=0x%"PRIregister"\n",
            d->domain_id, epoint, cid);

    /* THUMB set is not allowed with 64-bit domain */
    if ( is_64bit_domain(d) && is_thumb )
        return PSCI_INVALID_ADDRESS;

    /* Ensure that all CPUs other than the calling one are offline */
    for_each_vcpu ( d, v )
    {
        if ( v != current && is_vcpu_online(v) )
            return PSCI_DENIED;
    }

    /*
     * Prepare the calling VCPU for suspend (reset its context, save entry point
     * into pc and context ID into r0/x0 as specified by PSCI SYSTEM_SUSPEND)
     */
    vcpu_suspend(epoint, cid);

    /*
     * Set the domain state to suspended (will be cleared when the domain
     * resumes, i.e. VCPU of this domain gets scheduled in).
     */
    d->is_shut_down = 1;
    d->shutdown_code = SHUTDOWN_suspend;

    /* Disable watchdogs of this domain */
    watchdog_domain_suspend(d);

    /*
     * The calling domain is suspended by blocking its last running VCPU. If an
     * event is pending the domain will resume right away (VCPU will not block,
     * but when scheduled in it will resume from the given entry point).
     */
    vcpu_block_unless_event_pending(current);

    /* If this was dom0 the whole system should suspend: trigger Xen suspend */
    if ( is_hardware_domain(d) )
    {
        /*
         * system_suspend should be called when Dom0 finalizes the suspend
         * procedure from its boot core (VCPU#0). However, Dom0's VCPU#0 could
         * be mapped to any PCPU (this function could be executed by any PCPU).
         * The suspend procedure has to be finalized by the PCPU#0 (non-boot
         * PCPUs will be disabled during the suspend).
         */
        status = continue_hypercall_on_cpu(0, system_suspend, NULL);
        /*
         * If an error happened, there is nothing that needs to be done here
         * because the system_suspend always returns in fully functional state
         * no matter what the outcome of suspend procedure is. If the system
         * suspended successfully the function will return 0 after the resume.
         * Otherwise, if an error is returned it means Xen did not suspended,
         * but it is still in the same state as if the system_suspend was never
         * called. We dump a debug message in case of an error for debugging/
         * logging purpose.
         */
        if ( status )
            dprintk(XENLOG_ERR, "Failed to suspend, errno=%d\n", status);
    }

    return PSCI_SUCCESS;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
