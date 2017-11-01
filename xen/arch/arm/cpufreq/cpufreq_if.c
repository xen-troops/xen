/*
 * xen/arch/arm/cpufreq/cpufreq_if.c
 *
 * CPUFreq interface component
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

#include <xen/device_tree.h>
#include <xen/err.h>
#include <xen/sched.h>
#include <xen/cpufreq.h>
#include <xen/pmstat.h>
#include <xen/guest_access.h>

#include "scpi_protocol.h"

/*
 * TODO:
 * 1. Add __init to required funcs
 * 2. Put get_cpu_device() into common place
 * 3. Rework clock handling
 * 4. Clarify prints
 */

static struct scpi_ops *scpi_ops;

extern int scpi_cpufreq_register_driver(void);

#define dev_name(dev) dt_node_full_name(dev_to_dt(dev))

struct device *get_cpu_device(unsigned int cpu)
{
    if ( cpu < nr_cpu_ids && cpu_possible(cpu) )
        return dt_to_dev(cpu_dt_nodes[cpu]);
    else
        return NULL;
}

static int get_sharing_cpus(unsigned int cpu, cpumask_t *mask)
{
    struct device *cpu_dev, *tcpu_dev;
    unsigned int tcpu;
    int domain, tdomain;

    cpu_dev = get_cpu_device(cpu);
    if ( !cpu_dev )
        return -ENODEV;

    domain = scpi_ops->device_domain_id(cpu_dev);
    if ( domain < 0 )
        return domain;

    cpumask_clear(mask);
    cpumask_set_cpu(cpu, mask);

    for_each_possible_cpu( tcpu )
    {
        if ( tcpu == cpu )
            continue;

        tcpu_dev = get_cpu_device(tcpu);
        if ( !tcpu_dev )
            continue;

        tdomain = scpi_ops->device_domain_id(tcpu_dev);
        if ( tdomain == domain )
            cpumask_set_cpu(tcpu, mask);
    }

    return 0;
}

static int get_transition_latency(struct device *cpu_dev)
{
    return scpi_ops->get_transition_latency(cpu_dev);
}

static struct scpi_dvfs_info *get_dvfs_info(struct device *cpu_dev)
{
    int domain;

    domain = scpi_ops->device_domain_id(cpu_dev);
    if ( domain < 0 )
        return ERR_PTR(-EINVAL);

    return scpi_ops->dvfs_get_info(domain);
}

static int init_cpufreq_table(struct device *cpu_dev,
                              struct cpufreq_frequency_table **table)
{
    struct cpufreq_frequency_table *freq_table = NULL;
    struct scpi_dvfs_info *info;
    struct scpi_opp *opp;
    int i;

    info = get_dvfs_info(cpu_dev);
    if ( IS_ERR(info) )
        return PTR_ERR(info);

    if ( !info->opps )
        return -EIO;

    freq_table = xzalloc_array(struct cpufreq_frequency_table, info->count + 1);
    if ( !freq_table )
        return -ENOMEM;

    for ( opp = info->opps, i = 0; i < info->count; i++, opp++ )
    {
        freq_table[i].index = i;
        /* Convert Hz -> kHz */
        freq_table[i].frequency = opp->freq / 1000;

        printk("scpi: %s: Add opp %uHz %umV\n", dev_name(cpu_dev),
               opp->freq, opp->m_volt);
    }

    freq_table[i].index = i;
    freq_table[i].frequency = CPUFREQ_TABLE_END;

    *table = &freq_table[0];

    return 0;
}

static void free_cpufreq_table(struct cpufreq_frequency_table **table)
{
    if ( !table )
        return;

    xfree(*table);
    *table = NULL;
}

static int upload_cpufreq_data(cpumask_t *mask,
                               struct cpufreq_frequency_table *table)
{
    struct xen_processor_performance *perf;
    struct xen_processor_px *states;
    uint32_t platform_limit = 0, state_count = 0;
    unsigned int cpu, max_freq = 0, prev_freq = 0;
    int i, latency, ret = 0;

    perf = xzalloc(struct xen_processor_performance);
    if ( !perf )
        return -ENOMEM;

    /* Check frequency table and find max frequency */
    for ( i = 0; (table[i].frequency != CPUFREQ_TABLE_END); i++ )
    {
        unsigned int freq = table[i].frequency;

        if ( freq == CPUFREQ_ENTRY_INVALID )
            continue;

        if ( table[i].index != state_count || freq <= prev_freq )
        {
            printk("Frequency table format error\n");
            ret = -EINVAL;
            goto out;
        }

        prev_freq = freq;
        state_count++;
        if ( freq > max_freq )
            max_freq = freq;
    }

    if ( !state_count )
    {
        printk("No available performance states\n");
        ret = -EINVAL;
        goto out;
    }

    states = xzalloc_array(struct xen_processor_px, state_count);
    if ( !states )
    {
        ret = -ENOMEM;
        goto out;
    }

    set_xen_guest_handle(perf->states, states);
    perf->state_count = state_count;

    cpu = cpumask_first(mask);
    latency = get_transition_latency(get_cpu_device(cpu));

    /* Performance states must start from higher values */
    for ( i = 0; ( table[i].frequency != CPUFREQ_TABLE_END ); i++ )
    {
        unsigned int freq = table[i].frequency;
        unsigned int index = state_count - 1 - table[i].index;

        if ( freq == CPUFREQ_ENTRY_INVALID )
            continue;

        if ( freq == max_freq )
            platform_limit = index;

        /* Convert kHz -> MHz */
        states[index].core_frequency = freq / 1000;
        /* Convert ns -> us */
        states[index].transition_latency = DIV_ROUND_UP(latency, 1000);
    }

    perf->flags = XEN_PX_DATA; /* all info in a one-shot */
    perf->platform_limit = platform_limit;
    perf->shared_type = CPUFREQ_SHARED_TYPE_ANY;
    perf->domain_info.domain = cpumask_first(mask);
    perf->domain_info.num_processors = cpumask_weight(mask);

    for_each_cpu( cpu, mask )
    {
        ret = set_px_pminfo(cpu, perf);
        if ( ret )
        {
            if ( !cpu_online(cpu) )
            {
                /* CPU isn't online, skip it */
                ret = 0;
                continue;
            }
            break;
        }
    }

    xfree(states);
out:
    xfree(perf);

    return ret;
}

/*
 * TODO:
 * Handle case when some CPU(s) are not DVFS capable. Don't error, just skip
 * them if so.
 * Another question is which CPUs should we loop thought: possible or online?
 */
int __init scpi_cpufreq_postinit(void)
{
    struct cpufreq_frequency_table *freq_table = NULL;
    struct device *cpu_dev;
    cpumask_t processed_cpus, shared_cpus;
    unsigned int cpu;
    int ret;

    cpumask_clear(&processed_cpus);

    for_each_possible_cpu( cpu )
    {
        cpu_dev = get_cpu_device(cpu);
        if ( !cpu_dev )
        {
            printk("scpi: failed to get cpu%d device\n", cpu);
            return -ENODEV;
        }

        if ( cpumask_test_cpu(cpu, &processed_cpus) )
            continue;

        ret = get_sharing_cpus(cpu, &shared_cpus);
        if ( ret )
        {
            printk("scpi: %s: failed to get sharing cpumask (%d)\n",
                   dev_name(cpu_dev), ret);
            return ret;
        }

        BUG_ON(cpumask_empty(&shared_cpus));
        cpumask_or(&processed_cpus, &processed_cpus, &shared_cpus);

        ret = init_cpufreq_table(cpu_dev, &freq_table);
        if ( ret )
        {
            printk("scpi: %s: failed to init cpufreq table (%d)\n",
                   dev_name(cpu_dev), ret);
            return ret;
        }

        ret = upload_cpufreq_data(&shared_cpus, freq_table);
        free_cpufreq_table(&freq_table);
        if ( ret )
        {
            printk("scpi: %s: failed to upload cpufreq data (%d)\n",
                   dev_name(cpu_dev), ret);
            return ret;
        }
    }

    return 0;
}

static int __init scpi_clocks_init(struct dt_device_node *np)
{
    static const struct dt_device_match scpi_dvfs_clock_match[] __initconst =
    {
        DT_MATCH_COMPATIBLE("arm,scpi-dvfs-clocks"),
        { /* sentinel */ },
    };
    struct dt_device_node *child;
    int ret = -ENODEV;

    /* We are interested in DVFS feature only. So check for DVFS clock nodes. */
    dt_for_available_each_child_node( np, child )
    {
        int idx, count;

        if ( !dt_match_node(scpi_dvfs_clock_match, child) )
            continue;

        ret = dt_property_count_strings(child, "clock-output-names");
        if ( ret < 0 )
        {
            printk("scpi: %s: invalid clock output count @ %s\n",
                   dev_name(&np->dev), child->name);
            break;
        }
        count = ret;

        for ( idx = 0; idx < count; idx++ )
        {
            struct scpi_dvfs_info *info;
            const char *name;
            u32 domain;

            ret = dt_property_read_string_index(child, "clock-output-names",
                                                idx, &name);
            if ( ret )
            {
                printk("scpi: %s: invalid clock name @ %s\n",
                       dev_name(&np->dev), child->name);
                break;
            }

            ret = dt_property_read_u32_index(child, "clock-indices",
                                             idx, &domain);
            if ( ret )
            {
                printk("scpi: %s: invalid clock index @ %s\n",
                       dev_name(&np->dev), child->name);
                break;
            }

            info = scpi_ops->dvfs_get_info(domain);
            if ( IS_ERR(info) )
            {
                printk("scpi: %s: failed to get DVFS info of "
                       "power domain %u (clock '%s')\n",
                       dev_name(&np->dev), domain, name);
                ret = PTR_ERR(info);
                break;
            }

            printk(XENLOG_DEBUG "scpi: %s: found DVFS clock '%s'\n",
                   dev_name(&np->dev), name);
        }

        break;
    }

    if ( ret )
    {
        printk("scpi: %s: failed to init SCPI DVFS clocks (%d)\n",
               dev_name(&np->dev), ret);
        return ret;
    }

    return 0;
}

int __init scpi_cpufreq_preinit(void)
{
    static const struct dt_device_match scpi_clocks_match[] __initconst =
    {
        DT_MATCH_COMPATIBLE("arm,scpi-clocks"),
        { /* sentinel */ },
    };
    struct dt_device_node *child, *np;
    int ret;

    ret = scpi_init();
    if ( ret )
    {
        printk("scpi: failed to init SCPI (%d)\n", ret);
        return ret;
    }

    /* Sanity check */
    if ( !get_scpi_ops() || !get_scpi_dev() )
        return -ENXIO;

    np = get_scpi_dev()->of_node;
    scpi_ops = get_scpi_ops();

    ret = -ENODEV;

    /*
     * Check for clock child nodes for now. But it might additional nodes,
     * like thermal sensor, etc.
     */
    dt_for_each_child_node( np, child )
    {
        if ( !dt_match_node(scpi_clocks_match, child) )
            continue;

        ret = scpi_clocks_init(child);
        break;
    }

    if ( ret )
    {
        printk("scpi: %s: failed to init SCPI clocks (%d)\n",
               dev_name(&np->dev), ret);
        return ret;
    }

    return 0;
}

/* TODO Implement me */
void __init scpi_cpufreq_deinit(void)
{

}

static int __init cpufreq_driver_init(void)
{
    int ret;

    if ( cpufreq_controller != FREQCTL_xen )
        return 0;

    /*
     * Initialize everything needed SCPI based CPUFreq driver to be functional
     * (SCPI Message protocol, mailbox to communicate with SCP, etc).
     * Also find in a device-tree CPU DVFS clocks offered by SCP and retrieve
     * their DVFS capabilities using SCPI protocol. SCPI Message protocol driver
     * will populate DVFS info then.
     */
    ret = scpi_cpufreq_preinit();
    if ( ret )
        goto out;

    /* Register SCPI based CPUFreq driver */
    ret = scpi_cpufreq_register_driver();
    if ( ret )
        goto out;

    /*
     * Get DVFS capabilities (OPP list and the latency information) for all
     * DVFS capable CPUs, convert these capabilities into PM data the
     * CPUFreq framework expects to see followed by uploading it.
     *
     * Actually it is almost the same PM data which hwdom uploads in case of
     * x86 via platform hypercall after parsing ACPI tables. In our case we
     * don't need hwdom to be involved in, since we already have everything in
     * hand. Moreover, the hwdom doesn't even know anything about physical CPUs.
     * Not completely sure that it is the best place to do so, but certainly
     * it must be after driver registration.
     */
    ret = scpi_cpufreq_postinit();

out:
    if ( ret )
    {
        printk("failed to init SCPI based CPUFreq (%d)\n", ret);
        scpi_cpufreq_deinit();
    }

    return ret;
}
__initcall(cpufreq_driver_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
