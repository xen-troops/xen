/*
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
#ifndef __ARCH_ARM_IOMMU_H__
#define __ARCH_ARM_IOMMU_H__

struct arch_iommu
{
    /* Private information for the IOMMU drivers */
    void *priv;
};

/*
 * The ARM domain always has a P2M table, but not every integrated into
 * ARM SoCs IOMMU can use it as page table.
 */
#define iommu_use_hap_pt(d) (iommu_hap_pt_share)

const struct iommu_ops *iommu_get_ops(void);
void __init iommu_set_ops(const struct iommu_ops *ops);

int __init iommu_hardware_setup(void);

#endif /* __ARCH_ARM_IOMMU_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
