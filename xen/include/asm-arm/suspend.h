#ifndef __ASM_ARM_SUSPEND_H__
#define __ASM_ARM_SUSPEND_H__

#ifdef CONFIG_ARM_64
struct cpu_context {
    uint64_t callee_regs[12];
    uint64_t sp;
    uint64_t vbar_el2;
    uint64_t vtcr_el2;
    uint64_t vttbr_el2;
    uint64_t tpidr_el2;
    uint64_t mdcr_el2;
    uint64_t hstr_el2;
    uint64_t cptr_el2;
    uint64_t hcr_el2;
} __aligned(16);
#else
struct cpu_context {
    uint8_t pad;
};
#endif

extern struct cpu_context cpu_context;

int32_t domain_suspend(register_t epoint, register_t cid);
void hyp_resume(void);
int32_t hyp_suspend(struct cpu_context *ptr);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
