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

#define ARM_SMCCC_SCMI_MBOX_TRIGGER 0x82000002

enum vscmi_opp {
  VSCMI_OPP_MIN = 0,
  VSCMI_OPP_LOW,
  VSCMI_OPP_NOM,
  VSCMI_OPP_HIGH,
  VSCMI_OPP_TURBO
};

bool vscmi_handle_call(struct cpu_user_regs *regs);
int vcpu_vscmi_init(struct vcpu *vcpu);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

