#ifndef __ASM_ARM_PLATFORMS_RCAR_H
#define __ASM_ARM_PLATFORMS_RCAR_H

struct rproc_ops {
	bool (*handle_smc)(struct cpu_user_regs *regs);
	int (*assign_domain)(struct domain *d, int chan);
	int (*remove_domain)(struct domain *d);
};


/* TODO: Use getter/setter */
extern struct rproc_ops *rproc_ops;

#endif /* __ASM_ARM_PLATFORMS_RCAR_H */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
