/*
 * xen/arch/arm/cpufreq/scpi_cpufreq.c
 *
 * SCPI based CPUFreq driver
 *
 * Based on Xen arch/x86/acpi/cpufreq/cpufreq.c
 *
 * Oleksandr Tyshchenko <oleksandr_tyshchenko@epam.com>
 * Copyright (c) 2017 EPAM Systems.
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
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/types.h>
#include <xen/delay.h>
#include <xen/cpumask.h>
#include <xen/sched.h>
#include <xen/xmalloc.h>
#include <xen/err.h>
#include <xen/cpufreq.h>
#include <asm/bug.h>
#include <asm/percpu.h>

#include "scpi_protocol.h"

extern bool cpufreq_debug;

extern struct device *get_cpu_device(unsigned int cpu);

struct scpi_cpufreq_data
{
    struct processor_performance *perf;
    struct cpufreq_frequency_table *freq_table;
    struct scpi_dvfs_info *info; /* DVFS capabilities of the CPU's power domain */
    int domain; /* power domain id this CPU belongs to */
};

static struct scpi_cpufreq_data *cpufreq_driver_data[NR_CPUS];

static struct cpufreq_driver scpi_cpufreq_driver;

static struct scpi_ops *scpi_ops;

static int scpi_cpufreq_update(int cpuid, struct cpufreq_policy *policy)
{
    if ( !cpumask_test_cpu(cpuid, &cpu_online_map) )
        return -EINVAL;

    if ( policy->turbo != CPUFREQ_TURBO_UNSUPPORTED )
    {
        /* TODO Do we need some actions here? */
        if ( policy->turbo == CPUFREQ_TURBO_ENABLED )
            printk(XENLOG_INFO "cpu%u: Turbo Mode enabled\n", policy->cpu);
        else
            printk(XENLOG_INFO "cpu%u: Turbo Mode disabled\n", policy->cpu);
    }
    else
        printk(XENLOG_INFO "cpu%u: Turbo Mode unsupported\n", policy->cpu);

    return 0;
}

static unsigned int scpi_cpufreq_get(unsigned int cpu)
{
    struct scpi_cpufreq_data *data;
    struct cpufreq_policy *policy;
    const struct scpi_opp *opp;
    int idx;

    if ( cpu >= nr_cpu_ids || !cpu_online(cpu) )
        return 0;

    policy = per_cpu(cpufreq_cpu_policy, cpu);
    if ( !policy || !(data = cpufreq_driver_data[policy->cpu]) ||
         !data->info )
        return 0;

    idx = scpi_ops->dvfs_get_idx(data->domain);
    if ( idx < 0 )
        return 0;

    opp = data->info->opps + idx;

    /* Convert Hz -> kHz */
    return opp->freq / 1000;
}

static int scpi_cpufreq_set(unsigned int cpu, unsigned int freq)
{
    struct scpi_cpufreq_data *data;
    struct cpufreq_policy *policy;
    const struct scpi_opp *opp;
    int idx, max_opp;
    int result;

    if ( cpu >= nr_cpu_ids || !cpu_online(cpu) )
        return 0;

    policy = per_cpu(cpufreq_cpu_policy, cpu);
    if ( !policy || !(data = cpufreq_driver_data[policy->cpu]) ||
         !data->info )
        return 0;

    /* Find corresponding index */
    max_opp = data->info->count;
    opp = data->info->opps;
    for ( idx = 0; idx < max_opp; idx++, opp++ )
    {
        /* Compare in kHz */
        if ( opp->freq / 1000 == freq )
            break;
    }
    if ( idx == max_opp )
        return -EINVAL;

    result = scpi_ops->dvfs_set_idx(data->domain, idx);
    if ( result < 0 )
        return result;

    return 0;
}

static int scpi_cpufreq_target(struct cpufreq_policy *policy,
                               unsigned int target_freq, unsigned int relation)
{
    struct scpi_cpufreq_data *data = cpufreq_driver_data[policy->cpu];
    struct processor_performance *perf;
    struct cpufreq_freqs freqs;
    cpumask_t online_policy_cpus;
    unsigned int next_state = 0; /* Index into freq_table */
    unsigned int next_perf_state = 0; /* Index into perf table */
    unsigned int j;
    int result;

    if ( unlikely(!data || !data->perf || !data->freq_table || !data->info) )
        return -ENODEV;

    if ( policy->turbo == CPUFREQ_TURBO_DISABLED )
        if ( target_freq > policy->cpuinfo.second_max_freq )
            target_freq = policy->cpuinfo.second_max_freq;

    perf = data->perf;
    result = cpufreq_frequency_table_target(policy,
                                            data->freq_table,
                                            target_freq,
                                            relation, &next_state);
    if ( unlikely(result) )
        return -ENODEV;

    cpumask_and(&online_policy_cpus, &cpu_online_map, policy->cpus);

    next_perf_state = data->freq_table[next_state].index;
    if ( perf->state == next_perf_state )
    {
        if ( unlikely(policy->resume) )
            policy->resume = 0;
        else
            return 0;
    }

    /* Convert MHz -> kHz */
    freqs.old = perf->states[perf->state].core_frequency * 1000;
    freqs.new = data->freq_table[next_state].frequency;

    result = scpi_cpufreq_set(policy->cpu, freqs.new);
    if ( result < 0 )
        return result;

    if (cpufreq_debug)
        printk("Switch CPU freq: %u kHz --> %u kHz\n", freqs.old, freqs.new);

    for_each_cpu( j, &online_policy_cpus )
        cpufreq_statistic_update(j, perf->state, next_perf_state);

    perf->state = next_perf_state;
    policy->cur = freqs.new;

    return result;
}

static int scpi_cpufreq_verify(struct cpufreq_policy *policy)
{
    struct scpi_cpufreq_data *data;
    struct processor_performance *perf;

    if ( !policy || !(data = cpufreq_driver_data[policy->cpu]) ||
         !processor_pminfo[policy->cpu] )
        return -EINVAL;

    perf = &processor_pminfo[policy->cpu]->perf;

    /* Convert MHz -> kHz */
    cpufreq_verify_within_limits(policy, 0,
        perf->states[perf->platform_limit].core_frequency * 1000);

    return cpufreq_frequency_table_verify(policy, data->freq_table);
}

/* TODO Add a way to recognize Boost frequencies */
static inline bool is_turbo_freq(int index, int count)
{
    /* ugly Boost frequencies recognition */
    switch ( count )
    {
    /* H3 has 2 turbo-freq among 5 OPPs */
    case 5:
        return index <= 1 ? true : false;

    /* M3 has 3 turbo-freq among 6 OPPs */
    case 6:
        return index <= 2 ? true : false;

    default:
        return false;
    }
}

static int scpi_cpufreq_cpu_init(struct cpufreq_policy *policy)
{
    unsigned int i;
    unsigned int valid_states = 0;
    unsigned int curr_state, curr_freq;
    struct scpi_cpufreq_data *data;
    int result;
    struct processor_performance *perf;
    struct device *cpu_dev;
    struct scpi_dvfs_info *info;
    int domain;

    cpu_dev = get_cpu_device(policy->cpu);
    if ( !cpu_dev )
        return -ENODEV;

    data = xzalloc(struct scpi_cpufreq_data);
    if ( !data )
        return -ENOMEM;

    cpufreq_driver_data[policy->cpu] = data;

    data->perf = &processor_pminfo[policy->cpu]->perf;

    perf = data->perf;
    policy->shared_type = perf->shared_type;

    data->freq_table = xmalloc_array(struct cpufreq_frequency_table,
                                    (perf->state_count + 1));
    if ( !data->freq_table )
    {
        result = -ENOMEM;
        goto err_unreg;
    }

    /* Detect transition latency */
    policy->cpuinfo.transition_latency = 0;
    for ( i = 0; i < perf->state_count; i++ )
    {
        /* Compare in ns */
        if ( perf->states[i].transition_latency * 1000 >
             policy->cpuinfo.transition_latency )
            /* Convert us -> ns */
            policy->cpuinfo.transition_latency =
                perf->states[i].transition_latency * 1000;
    }

    policy->governor = cpufreq_opt_governor ? : CPUFREQ_DEFAULT_GOVERNOR;

    /* Boost is not supported by default */
    policy->turbo = CPUFREQ_TURBO_UNSUPPORTED;

    /* Initialize frequency table */
    for ( i = 0; i < perf->state_count; i++ )
    {
        /* Compare in MHz */
        if ( i > 0 && perf->states[i].core_frequency >=
             data->freq_table[valid_states - 1].frequency / 1000 )
            continue;

        data->freq_table[valid_states].index = i;
        /* Convert MHz -> kHz */
        data->freq_table[valid_states].frequency =
            perf->states[i].core_frequency * 1000;

        data->freq_table[valid_states].flags = 0;
        if ( is_turbo_freq(valid_states, perf->state_count) )
        {
            printk(XENLOG_INFO "cpu%u: Turbo freq detected: %u\n",
                   policy->cpu, data->freq_table[valid_states].frequency);
            data->freq_table[valid_states].flags |= CPUFREQ_BOOST_FREQ;

            if ( policy->turbo == CPUFREQ_TURBO_UNSUPPORTED )
            {
                printk(XENLOG_INFO "cpu%u: Turbo Mode detected and enabled\n",
                       policy->cpu);
                policy->turbo = CPUFREQ_TURBO_ENABLED;
            }
        }

        valid_states++;
    }
    data->freq_table[valid_states].frequency = CPUFREQ_TABLE_END;
    perf->state = 0;

    result = cpufreq_frequency_table_cpuinfo(policy, data->freq_table);
    if ( result )
        goto err_freqfree;

    /* Fill in fields needed for frequency changing */
    domain = scpi_ops->device_domain_id(cpu_dev);
    if ( domain < 0 )
    {
        result = domain;
        goto err_freqfree;
    }
    data->domain = domain;

    info = scpi_ops->dvfs_get_info(domain);
    if ( IS_ERR(info) )
    {
        result = PTR_ERR(info);
        goto err_freqfree;
    }
    data->info = info;

    /* Retrieve current frequency */
    curr_freq = scpi_cpufreq_get(policy->cpu);

    /* Find corresponding state */
    curr_state = 0;
    for ( i = 0; data->freq_table[i].frequency != CPUFREQ_TABLE_END; i++ )
    {
        if ( curr_freq == data->freq_table[i].frequency )
        {
            curr_state = i;
            break;
        }
    }

    /* Update fields with actual values */
    policy->cur = curr_freq;
    perf->state = data->freq_table[curr_state].index;

    /*
     * the first call to ->target() should result in us actually
     * writing something to the appropriate registers.
     */
    policy->resume = 1;

    return result;

err_freqfree:
    xfree(data->freq_table);
err_unreg:
    xfree(data);
    cpufreq_driver_data[policy->cpu] = NULL;

    return result;
}

static int scpi_cpufreq_cpu_exit(struct cpufreq_policy *policy)
{
    struct scpi_cpufreq_data *data = cpufreq_driver_data[policy->cpu];

    if ( data )
    {
        xfree(data->freq_table);
        xfree(data);
        cpufreq_driver_data[policy->cpu] = NULL;
    }

    return 0;
}

static struct cpufreq_driver scpi_cpufreq_driver = {
    .name   = "scpi-cpufreq",

    .verify = scpi_cpufreq_verify,
    .target = scpi_cpufreq_target,
    .get    = scpi_cpufreq_get,
    .init   = scpi_cpufreq_cpu_init,
    .exit   = scpi_cpufreq_cpu_exit,
    .update = scpi_cpufreq_update,
};

int __init scpi_cpufreq_register_driver(void)
{
    scpi_ops = get_scpi_ops();
    if ( !scpi_ops )
        return -ENXIO;

    return cpufreq_register_driver(&scpi_cpufreq_driver);
}

int cpufreq_cpu_init(unsigned int cpuid)
{
    return cpufreq_add_cpu(cpuid);
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
