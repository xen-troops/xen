/*
 * xen/include/asm-arm/vscmi.h
 *
 * Volodymyr Babchuk <volodymyr_babchuk@epam.com>
 * Copyright (c) 2019 EPAM Systems.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; under version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */


#ifndef __ASM_VSCMI_H__
#define __ASM_VSCMI_H__

#include <xen/notifier.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <public/domctl.h>

#define ARM_SMCCC_SCMI_MBOX_TRIGGER 0x82000002
#define VSCMI_MAX_OPP XEN_DOMCTL_PM_OP_OPP_LIMIT
#define VSCMI_OPP_COUNT (VSCMI_MAX_OPP + 1)

void register_vscmi_notifier(struct notifier_block *nb);
void unregister_vscmi_notifier(struct notifier_block *nb);

int domain_vscmi_init(struct domain *d, gfn_t shmem_gfn);
void domain_vscmi_free(struct domain *d);

bool vscmi_handle_call(struct cpu_user_regs *regs);
int vcpu_vscmi_init(struct vcpu *vcpu);

unsigned int vscmi_scale_opp(int requested, unsigned int freq_min,
                             unsigned int freq_max);

static inline bool vscmi_enabled_for_domain(struct domain *d)
{
    return d->arch.scmi_base_pg;
}

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

