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

static bool is_dvfs_capable(unsigned int cpu)
{
    static const struct dt_device_match scpi_dvfs_clock_match[] =
    {
        DT_MATCH_COMPATIBLE("arm,scpi-dvfs-clocks"),
        { /* sentinel */ },
    };
    struct device *cpu_dev;
    struct dt_phandle_args clock_spec;
    struct scpi_dvfs_info *info;
    u32 domain;
    int i, ret, count;

    cpu_dev = get_cpu_device(cpu);
    if ( !cpu_dev )
    {
        printk("cpu%d: failed to get device\n", cpu);
        return false;
    }

    /* First of all find a clock node this CPU is a consumer of */
    ret = dt_parse_phandle_with_args(cpu_dev->of_node,
                                     "clocks",
                                     "#clock-cells",
                                     0,
                                     &clock_spec);
    if ( ret )
    {
        printk("cpu%d: failed to get clock node\n", cpu);
        return false;
    }

    /* Make sure it is an available DVFS clock node */
    if ( !dt_match_node(scpi_dvfs_clock_match, clock_spec.np) ||
         !dt_device_is_available(clock_spec.np) )
    {
        printk("cpu%d: clock node '%s' is either non-DVFS or non-available\n",
               cpu, dev_name(&clock_spec.np->dev));
        return false;
    }

    /*
     * Actually we already have a power domain id this CPU belongs to,
     * it is a stored in args[0] CPU clock specifier, so we could ask SCP
     * to provide its DVFS info. But we want to dig a little bit deeper
     * to make sure that everything is correct.
     */

    /* Check how many clock ids a DVFS clock node has */
    ret = dt_property_count_elems_of_size(clock_spec.np,
                                          "clock-indices",
                                          sizeof(u32));
    if ( ret < 0 )
    {
        printk("cpu%d: failed to get clock-indices count in '%s'\n",
               cpu, dev_name(&clock_spec.np->dev));
        return false;
    }
    count = ret;

    /* Check if a clock id the CPU clock specifier points to is present */
    for ( i = 0; i < count; i++ )
    {
        ret = dt_property_read_u32_index(clock_spec.np,
                                         "clock-indices",
                                         i,
                                         &domain);
        if ( ret )
        {
            printk("cpu%d: failed to get clock index in '%s'\n",
                   cpu, dev_name(&clock_spec.np->dev));
            return false;
        }

        /* Match found */
        if ( clock_spec.args[0] == domain )
            break;
    }

    if ( i == count )
    {
        printk("cpu%d: failed to find matching clk_id (pd) %d\n",
               cpu, clock_spec.args[0]);
        return false;
    }

    /*
     * Check if a SCP is aware of this power domain. SCPI Message protocol
     * driver will populate power domain's DVFS info then.
     */
    info = scpi_ops->dvfs_get_info(domain);
    if ( IS_ERR(info) )
    {
        printk("cpu%d: failed to get DVFS info of pd%u\n", cpu, domain);
        return false;
    }

    printk(XENLOG_DEBUG "cpu%d: is DVFS capable, belongs to pd%u\n",
           cpu, domain);

    return true;
}

static int get_sharing_cpus(unsigned int cpu, cpumask_t *mask)
{
    struct device *cpu_dev = get_cpu_device(cpu), *tcpu_dev;
    unsigned int tcpu;
    int domain, tdomain;

    BUG_ON(!cpu_dev);

    domain = scpi_ops->device_domain_id(cpu_dev);
    if ( domain < 0 )
        return domain;

    cpumask_clear(mask);
    cpumask_set_cpu(cpu, mask);

    for_each_online_cpu( tcpu )
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

static int init_cpufreq_table(unsigned int cpu,
                              struct cpufreq_frequency_table **table)
{
    struct cpufreq_frequency_table *freq_table = NULL;
    struct device *cpu_dev = get_cpu_device(cpu);
    struct scpi_dvfs_info *info;
    struct scpi_opp *opp;
    int i;

    BUG_ON(!cpu_dev);

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
    unsigned int max_freq = 0, prev_freq = 0, cpu = cpumask_first(mask);
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
            printk("cpu%d: frequency table format error\n", cpu);
            ret = -EINVAL;
            goto out;
        }

        prev_freq = freq;
        state_count++;
        if ( freq > max_freq )
            max_freq = freq;
    }

    /*
     * The frequency table we have is just a temporary place for storing
     * provided by SCP DVFS info. Create performance states array.
     */
    if ( !state_count )
    {
        printk("cpu%d: no available performance states\n", cpu);
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

    latency = get_transition_latency(get_cpu_device(cpu));

    /* Performance states must start from higher values */
    for ( i = 0; (table[i].frequency != CPUFREQ_TABLE_END); i++ )
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

    perf->flags = XEN_PX_PSD | XEN_PX_PSS | XEN_PX_PCT | XEN_PX_PPC |
                  XEN_PX_DATA; /* all P-state data in a one-shot */
    perf->platform_limit = platform_limit;
    perf->shared_type = CPUFREQ_SHARED_TYPE_ANY;
    perf->domain_info.domain = cpumask_first(mask);
    perf->domain_info.num_processors = cpumask_weight(mask);

    /* Iterate through all CPUs which are on the same boat */
    for_each_cpu( cpu, mask )
    {
        ret = set_px_pminfo(cpu, perf);
        if ( ret )
        {
            printk("cpu%d: failed to set Px states (%d)\n", cpu, ret);
            break;
        }

        printk(XENLOG_DEBUG "cpu%d: set Px states\n", cpu);
    }

    xfree(states);
out:
    xfree(perf);

    return ret;
}

static int __init scpi_cpufreq_postinit(void)
{
    struct cpufreq_frequency_table *freq_table = NULL;
    cpumask_t processed_cpus, shared_cpus;
    unsigned int cpu;
    int ret = -ENODEV;

    cpumask_clear(&processed_cpus);

    for_each_online_cpu( cpu )
    {
        if ( cpumask_test_cpu(cpu, &processed_cpus) )
            continue;

        if ( !is_dvfs_capable(cpu) )
        {
            printk(XENLOG_DEBUG "cpu%d: isn't DVFS capable, skip it\n", cpu);
            continue;
        }

        ret = get_sharing_cpus(cpu, &shared_cpus);
        if ( ret )
        {
            printk("cpu%d: failed to get sharing cpumask (%d)\n", cpu, ret);
            return ret;
        }

        BUG_ON(cpumask_empty(&shared_cpus));
        cpumask_or(&processed_cpus, &processed_cpus, &shared_cpus);

        /* Create intermediate frequency table */
        ret = init_cpufreq_table(cpu, &freq_table);
        if ( ret )
        {
            printk("cpu%d: failed to initialize frequency table (%d)\n",
                   cpu, ret);
            return ret;
        }

        ret = upload_cpufreq_data(&shared_cpus, freq_table);
        /* Destroy intermediate frequency table */
        free_cpufreq_table(&freq_table);
        if ( ret )
        {
            printk("cpu%d: failed to upload cpufreq data (%d)\n", cpu, ret);
            return ret;
        }

        printk(XENLOG_DEBUG "cpu%d: uploaded cpufreq data\n", cpu);
    }

    return ret;
}

static int __init scpi_cpufreq_preinit(void)
{
    struct dt_device_node *scpi, *clk, *dvfs_clk;
    int ret;

    /* Initialize SCPI Message protocol */
    ret = scpi_init();
    if ( ret )
    {
        printk("failed to initialize SCPI (%d)\n", ret);
        return ret;
    }

    /* Sanity check */
    if ( !get_scpi_ops() || !get_scpi_dev() )
        return -ENXIO;

    scpi = get_scpi_dev()->of_node;
    scpi_ops = get_scpi_ops();

    ret = -ENODEV;

    /*
     * Check for clock related nodes for now. But it might additional nodes,
     * like thermal sensor, etc.
     */
    dt_for_each_child_node( scpi, clk )
    {
        /*
         * First of all there must be a container node which contains all
         * clocks provided by SCP.
         */
        if ( !dt_device_is_compatible(clk, "arm,scpi-clocks") )
            continue;

        /*
         * As we are interested in DVFS feature only, check for DVFS clock
         * sub-node. At the current stage check for it presence only.
         * Without it there is no point to register SCPI based CPUFreq. We will
         * perform a thorough check later when populating DVFS clock consumers.
         */
        dt_for_each_child_node( clk, dvfs_clk )
        {
            if ( !dt_device_is_compatible(dvfs_clk, "arm,scpi-dvfs-clocks") )
                continue;

            return 0;
        }

        break;
    }

    printk("failed to find SCPI DVFS clocks (%d)\n", ret);

    return ret;
}

/* TODO Implement me */
static void scpi_cpufreq_deinit(void)
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
     * Also preliminary check if SCPI DVFS clock nodes offered by SCP are
     * present in a device tree.
     */
    ret = scpi_cpufreq_preinit();
    if ( ret )
        goto out;

    /* Register SCPI based CPUFreq driver */
    ret = scpi_cpufreq_register_driver();
    if ( ret )
        goto out;

    /*
     * Populate CPUs. Get DVFS info (OPP list and the latency information)
     * for all DVFS capable CPUs using SCPI protocol, convert these capabilities
     * into PM data the CPUFreq framework expects to see followed by
     * uploading it.
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
        printk("failed to initialize SCPI based CPUFreq (%d)\n", ret);
        scpi_cpufreq_deinit();
        return ret;
    }

    printk("initialized SCPI based CPUFreq\n");

    return 0;
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
