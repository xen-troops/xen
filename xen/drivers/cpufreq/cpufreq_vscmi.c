/*
 *  xen/drivers/cpufreq/cpufreq_vscmi.c
 *
 *  Copyright (C)  2019 Volodymyr Babchuk <volodymyr_babchuk@epam.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <xen/cpu.h>
#include <xen/cpufreq.h>
#include <xen/cpumask.h>
#include <xen/init.h>
#include <xen/percpu.h>
#include <xen/sched.h>
#include <asm/vscmi.h>

static int cpufreq_governor_vscmi(struct cpufreq_policy *policy,
                                      unsigned int event)
{
    int ret = 0;
    unsigned int cpu;

    if (unlikely(!policy) ||
        unlikely(!cpu_online(cpu = policy->cpu)))
        return -EINVAL;

    switch (event) {
    case CPUFREQ_GOV_START:
        /* TODO: Start  */
        break;
    case CPUFREQ_GOV_STOP:
        /* TODO: Stop */
        /* per_cpu(cpu_set_freq, cpu) = 0; */
        break;
    case CPUFREQ_GOV_LIMITS:
        ret = __cpufreq_driver_target(policy, 1000000, CPUFREQ_RELATION_H);
        break;
    default:
        ret = -EINVAL;
        break;
    }

    return ret;
}

static int cpufreq_vscmi_cpu_callback(
    struct notifier_block *nfb, unsigned long action, void *hcpu)
{
    struct vcpu *vcpu = hcpu;
    struct cpufreq_policy *policy;
    int requested_opp = 0;
    struct domain *d;
    struct vcpu *v;
    int freq;
    int pcpu;
    cpumask_t mask;

    cpumask_copy(&mask, vcpu->cpu_hard_affinity);
    /* Check all domains to find the maximum opp requested */
    for_each_cpu ( pcpu, &mask )
    {
        for_each_domain ( d )
        {
            if ( !vscmi_enabled_for_domain(d) )
                continue;

            for_each_vcpu ( d, v )
            {
                if ( requested_opp < v->arch.opp )
                    requested_opp = v->arch.opp;
            }
        }

        policy = per_cpu(cpufreq_cpu_policy, pcpu);

        freq = vscmi_scale_opp(requested_opp, policy->min, policy->max);

        printk(XENLOG_INFO"cpufreq_vscmi: asking for freq %d for pcpu %d\n", freq, pcpu);

        /* TODO: Check the return value */
        __cpufreq_driver_target(policy, freq, CPUFREQ_RELATION_L);

        cpumask_andnot(&mask, &mask, policy->cpus);
    }

    return NOTIFY_DONE;
}

static struct notifier_block cpufreq_vscmi_cpu_nfb = {
    .notifier_call = cpufreq_vscmi_cpu_callback
};

struct cpufreq_governor cpufreq_gov_vscmi = {
    .name = "vscmi",
    .governor = cpufreq_governor_vscmi,
};

static int __init cpufreq_gov_vscmi_init(void)
{
    register_vscmi_notifier(&cpufreq_vscmi_cpu_nfb);
    return cpufreq_register_governor(&cpufreq_gov_vscmi);
}
__initcall(cpufreq_gov_vscmi_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
