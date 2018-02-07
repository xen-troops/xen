/*
 * Copyright (C) 2015, 2016 ARM Ltd.
 * Imported from Linux ("new" KVM VGIC) and heavily adapted to Xen.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __XEN_ARM_VGIC_VGIC_H__
#define __XEN_ARM_VGIC_VGIC_H__

#define vgic_irq_is_sgi(intid) ((intid) < VGIC_NR_SGIS)

static inline bool irq_is_pending(struct vgic_irq *irq)
{
    if ( irq->config == VGIC_CONFIG_EDGE )
        return irq->pending_latch;
    else
        return irq->pending_latch || irq->line_level;
}

static inline bool vgic_irq_is_mapped_level(struct vgic_irq *irq)
{
    return irq->config == VGIC_CONFIG_LEVEL && irq->hw;
}

struct vgic_irq *vgic_get_irq(struct domain *d, struct vcpu *vcpu,
                              uint32_t intid);
void vgic_put_irq(struct domain *d, struct vgic_irq *irq);
void vgic_queue_irq_unlock(struct domain *d, struct vgic_irq *irq,
                           unsigned long flags);

static inline void vgic_get_irq_kref(struct vgic_irq *irq)
{
    if ( irq->intid < VGIC_MIN_LPI )
        return;

    atomic_inc(&irq->refcount);
}

void vgic_v2_fold_lr_state(struct vcpu *vcpu);
void vgic_v2_populate_lr(struct vcpu *vcpu, struct vgic_irq *irq, int lr);
void vgic_v2_set_underflow(struct vcpu *vcpu);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */