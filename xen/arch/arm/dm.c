/*
 * Copyright (c) 2019 Arm ltd.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/hypercall.h>
#include <asm/vgic.h>

int arch_dm_op(struct xen_dm_op *op, struct domain *d,
               const struct dmop_args *op_args, bool *const_op)
{
    int rc;

    switch ( op->op )
    {
    case XEN_DMOP_set_irq_level:
    {
        const struct xen_dm_op_set_irq_level *data =
            &op->u.set_irq_level;

        /* XXX: Handle check */
        vgic_inject_irq(d, NULL, data->irq, data->level);
        rc = 0;
        break;
    }

    default:
        rc = -EOPNOTSUPP;
        break;
    }

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
