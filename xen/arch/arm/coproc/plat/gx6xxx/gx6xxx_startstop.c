#include <xen/delay.h>

#include "gx6xxx_coproc.h"
#include "gx6xxx_fw.h"
#include "gx6xxx_startstop.h"

/* these are the registers we must save during context switch */
static uint32_t gx6xxx_ctx_reg_offsets[] =
{
    RGX_CR_PBE_INDIRECT,
    RGX_CR_PBE_PERF_INDIRECT,
    RGX_CR_TPU_PERF_INDIRECT,
    RGX_CR_RASTERISATION_PERF_INDIRECT,
    RGX_CR_TPU_MCU_L0_PERF_INDIRECT,
    RGX_CR_USC_PERF_INDIRECT,
    RGX_CR_BLACKPEARL_INDIRECT,
    RGX_CR_BLACKPEARL_PERF_INDIRECT,
    RGX_CR_TEXAS3_PERF_INDIRECT,
    RGX_CR_TEXAS_PERF_INDIRECT,
    RGX_CR_BX_TU_PERF_INDIRECT,
    RGX_CR_CLK_CTRL,
    RGX_CR_CLK_STATUS,
#if defined THESE_ARE_READ_ONLY
    RGX_CR_CORE_ID,
    RGX_CR_CORE_REVISION,
    RGX_CR_DESIGNER_REV_FIELD1,
    RGX_CR_DESIGNER_REV_FIELD2,
    RGX_CR_CHANGESET_NUMBER,
#endif
    RGX_CR_CLK_XTPLUS_CTRL,
    RGX_CR_CLK_XTPLUS_STATUS,
    RGX_CR_SOFT_RESET,
#if defined(RGX_FEATURE_S7_TOP_INFRASTRUCTURE)
    RGX_CR_SOFT_RESET2,
#endif
    RGX_CR_EVENT_STATUS,
    RGX_CR_TIMER,
    RGX_CR_TLA_STATUS,
    RGX_CR_PM_PARTIAL_RENDER_ENABLE,
    RGX_CR_SIDEKICK_IDLE,
    RGX_CR_VDM_CONTEXT_STORE_STATUS,
    RGX_CR_VDM_CONTEXT_STORE_TASK0,
    RGX_CR_VDM_CONTEXT_STORE_TASK1,
    RGX_CR_VDM_CONTEXT_STORE_TASK2,
    RGX_CR_VDM_CONTEXT_RESUME_TASK0,
    RGX_CR_VDM_CONTEXT_RESUME_TASK1,
    RGX_CR_VDM_CONTEXT_RESUME_TASK2,
    RGX_CR_CDM_CONTEXT_STORE_STATUS,
    RGX_CR_CDM_CONTEXT_PDS0,
    RGX_CR_CDM_CONTEXT_PDS1,
    RGX_CR_CDM_TERMINATE_PDS,
    RGX_CR_CDM_TERMINATE_PDS1,
    RGX_CR_CDM_CONTEXT_LOAD_PDS0,
    RGX_CR_CDM_CONTEXT_LOAD_PDS1,
#if !defined(RGX_FEATURE_META)
    RGX_CR_MIPS_WRAPPER_CONFIG,
    RGX_CR_MIPS_ADDR_REMAP1_CONFIG1,
    RGX_CR_MIPS_ADDR_REMAP1_CONFIG2,
    RGX_CR_MIPS_ADDR_REMAP2_CONFIG1,
    RGX_CR_MIPS_ADDR_REMAP2_CONFIG2,
    RGX_CR_MIPS_ADDR_REMAP3_CONFIG1,
    RGX_CR_MIPS_ADDR_REMAP3_CONFIG2,
    RGX_CR_MIPS_ADDR_REMAP4_CONFIG1,
    RGX_CR_MIPS_ADDR_REMAP4_CONFIG2,
    RGX_CR_MIPS_ADDR_REMAP5_CONFIG1,
    RGX_CR_MIPS_ADDR_REMAP5_CONFIG2,
    RGX_CR_MIPS_WRAPPER_IRQ_ENABLE,
    RGX_CR_MIPS_WRAPPER_IRQ_STATUS,
    RGX_CR_MIPS_WRAPPER_IRQ_CLEAR,
    RGX_CR_MIPS_WRAPPER_NMI_ENABLE,
    RGX_CR_MIPS_WRAPPER_NMI_EVENT,
    RGX_CR_MIPS_DEBUG_CONFIG,
    RGX_CR_MIPS_EXCEPTION_STATUS,
#endif
    RGX_CR_META_SP_MSLVDATAX,
    RGX_CR_META_SP_MSLVDATAT,
    RGX_CR_META_SP_MSLVCTRL0,
    RGX_CR_META_SP_MSLVCTRL1,
    RGX_CR_META_SP_MSLVHANDSHKE,
    RGX_CR_META_SP_MSLVT0KICK,
    RGX_CR_META_SP_MSLVT0KICKI,
    RGX_CR_META_SP_MSLVT1KICK,
    RGX_CR_META_SP_MSLVT1KICKI,
    RGX_CR_META_SP_MSLVT2KICK,
    RGX_CR_META_SP_MSLVT2KICKI,
    RGX_CR_META_SP_MSLVT3KICK,
    RGX_CR_META_SP_MSLVT3KICKI,
    RGX_CR_META_SP_MSLVRST,
    RGX_CR_META_SP_MSLVIRQSTATUS,
    RGX_CR_META_SP_MSLVIRQENABLE,
    RGX_CR_META_SP_MSLVIRQLEVEL,
    RGX_CR_MTS_SCHEDULE,
#if defined DO_THESE_NEED_TO_BE_ADDED_TOO
    RGX_CR_MTS_SCHEDULE1,
    RGX_CR_MTS_SCHEDULE2,
    RGX_CR_MTS_SCHEDULE3,
    RGX_CR_MTS_SCHEDULE4,
    RGX_CR_MTS_SCHEDULE5,
    RGX_CR_MTS_SCHEDULE6,
    RGX_CR_MTS_SCHEDULE7,
#endif
    RGX_CR_MTS_BGCTX_THREAD0_DM_ASSOC,
    RGX_CR_MTS_BGCTX_THREAD1_DM_ASSOC,
    RGX_CR_MTS_INTCTX_THREAD0_DM_ASSOC,
    RGX_CR_MTS_INTCTX_THREAD1_DM_ASSOC,
    RGX_CR_MTS_GARTEN_WRAPPER_CONFIG,
    RGX_CR_MTS_INTCTX,
    RGX_CR_MTS_BGCTX,
    RGX_CR_MTS_BGCTX_COUNTED_SCHEDULE,
    RGX_CR_MTS_GPU_INT_STATUS,
    RGX_CR_META_BOOT,
    RGX_CR_GARTEN_SLC,
    RGX_CR_PPP,
    RGX_CR_ISP_RENDER,
    RGX_CR_ISP_CTL,
    RGX_CR_ISP_STATUS,
    RGX_CR_ISP_XTP_RESUME0,
    RGX_CR_ISP_XTP_STORE0,
    RGX_CR_BIF_CAT_BASE0,
    RGX_CR_BIF_CAT_BASE1,
    RGX_CR_BIF_CAT_BASE2,
    RGX_CR_BIF_CAT_BASE3,
    RGX_CR_BIF_CAT_BASE4,
    RGX_CR_BIF_CAT_BASE5,
    RGX_CR_BIF_CAT_BASE6,
    RGX_CR_BIF_CAT_BASE7,
    RGX_CR_BIF_CAT_BASE_INDEX,
    RGX_CR_BIF_PM_CAT_BASE_VCE0,
    RGX_CR_BIF_PM_CAT_BASE_TE0,
    RGX_CR_BIF_PM_CAT_BASE_ALIST0,
    RGX_CR_BIF_PM_CAT_BASE_VCE1,
    RGX_CR_BIF_PM_CAT_BASE_TE1,
    RGX_CR_BIF_PM_CAT_BASE_ALIST1,
    RGX_CR_BIF_MMU_ENTRY_STATUS,
    RGX_CR_BIF_MMU_ENTRY,
    RGX_CR_BIF_CTRL_INVAL,
    RGX_CR_BIF_CTRL,
    RGX_CR_BIF_FAULT_BANK0_MMU_STATUS,
    RGX_CR_BIF_FAULT_BANK0_REQ_STATUS,
    RGX_CR_BIF_FAULT_BANK1_MMU_STATUS,
    RGX_CR_BIF_FAULT_BANK1_REQ_STATUS,
    RGX_CR_BIF_MMU_STATUS,
    RGX_CR_BIF_READS_EXT_STATUS,
    RGX_CR_BIF_READS_INT_STATUS,
    RGX_CR_BIFPM_READS_INT_STATUS,
    RGX_CR_BIFPM_READS_EXT_STATUS,
    RGX_CR_BIFPM_STATUS_MMU,
    RGX_CR_BIF_STATUS_MMU,
    RGX_CR_BIF_FAULT_READ,
    RGX_CR_TEXAS_BIF_FAULT_BANK0_MMU_STATUS,
    RGX_CR_TEXAS_BIF_FAULT_BANK0_REQ_STATUS,
    RGX_CR_MCU_FENCE,
    RGX_CR_SPFILTER_SIGNAL_DESCR,
    RGX_CR_SPFILTER_SIGNAL_DESCR_MIN,
    RGX_CR_SLC_CTRL_MISC,
    RGX_CR_SLC_CTRL_FLUSH_INVAL,
    RGX_CR_SLC_STATUS0,
    RGX_CR_SLC_CTRL_BYPASS,
    RGX_CR_SLC_STATUS1,
    RGX_CR_SLC_IDLE,
    RGX_CR_SLC_STATUS2,
    RGX_CR_SLC_CTRL_MISC2,
    RGX_CR_SLC_CROSSBAR_LOAD_BALANCE,
    RGX_CR_USC_UVS0_CHECKSUM,
    RGX_CR_USC_UVS1_CHECKSUM,
    RGX_CR_USC_UVS2_CHECKSUM,
    RGX_CR_USC_UVS3_CHECKSUM,
    RGX_CR_PPP_SIGNATURE,
    RGX_CR_TE_SIGNATURE,
    RGX_CR_TE_CHECKSUM,
    RGX_CR_USC_UVB_CHECKSUM,
    RGX_CR_VCE_CHECKSUM,
    RGX_CR_ISP_PDS_CHECKSUM,
    RGX_CR_ISP_TPF_CHECKSUM,
    RGX_CR_TFPU_PLANE0_CHECKSUM,
    RGX_CR_TFPU_PLANE1_CHECKSUM,
    RGX_CR_PBE_CHECKSUM,
    RGX_CR_PDS_DOUTM_STM_SIGNATURE,
    RGX_CR_IFPU_ISP_CHECKSUM,
    RGX_CR_USC_UVS4_CHECKSUM,
    RGX_CR_USC_UVS5_CHECKSUM,
    RGX_CR_PPP_CLIP_CHECKSUM,
    RGX_CR_PERF_TA_PHASE,
    RGX_CR_PERF_3D_PHASE,
    RGX_CR_PERF_COMPUTE_PHASE,
    RGX_CR_PERF_TA_CYCLE,
    RGX_CR_PERF_3D_CYCLE,
    RGX_CR_PERF_COMPUTE_CYCLE,
    RGX_CR_PERF_TA_OR_3D_CYCLE,
    RGX_CR_PERF_INITIAL_TA_CYCLE,
    RGX_CR_PERF_SLC0_READ_STALL,
    RGX_CR_PERF_SLC0_WRITE_STALL,
    RGX_CR_PERF_SLC1_READ_STALL,
    RGX_CR_PERF_SLC1_WRITE_STALL,
    RGX_CR_PERF_SLC2_READ_STALL,
    RGX_CR_PERF_SLC2_WRITE_STALL,
    RGX_CR_PERF_SLC3_READ_STALL,
    RGX_CR_PERF_SLC3_WRITE_STALL,
    RGX_CR_PERF_3D_SPINUP,
    RGX_CR_AXI_ACE_LITE_CONFIGURATION,
    RGX_CR_POWER_ESTIMATE_RESULT,
    RGX_CR_TA_PERF,
    RGX_CR_TA_PERF_SELECT0,
    RGX_CR_TA_PERF_SELECT1,
    RGX_CR_TA_PERF_SELECT2,
    RGX_CR_TA_PERF_SELECT3,
    RGX_CR_TA_PERF_SELECTED_BITS,
    RGX_CR_TA_PERF_COUNTER_0,
    RGX_CR_TA_PERF_COUNTER_1,
    RGX_CR_TA_PERF_COUNTER_2,
    RGX_CR_TA_PERF_COUNTER_3,
    RGX_CR_RASTERISATION_PERF,
    RGX_CR_RASTERISATION_PERF_SELECT0,
    RGX_CR_RASTERISATION_PERF_COUNTER_0,
    RGX_CR_HUB_BIFPMCACHE_PERF,
    RGX_CR_HUB_BIFPMCACHE_PERF_SELECT0,
    RGX_CR_HUB_BIFPMCACHE_PERF_COUNTER_0,
    RGX_CR_TPU_MCU_L0_PERF,
    RGX_CR_TPU_MCU_L0_PERF_SELECT0,
    RGX_CR_TPU_MCU_L0_PERF_COUNTER_0,
    RGX_CR_USC_PERF,
    RGX_CR_USC_PERF_SELECT0,
    RGX_CR_USC_PERF_COUNTER_0,
    RGX_CR_JONES_IDLE,
    RGX_CR_TORNADO_PERF,
    RGX_CR_TORNADO_PERF_SELECT0,
    RGX_CR_TORNADO_PERF_COUNTER_0,
    RGX_CR_TEXAS_PERF,
    RGX_CR_TEXAS_PERF_SELECT0,
    RGX_CR_TEXAS_PERF_COUNTER_0,
    RGX_CR_JONES_PERF,
    RGX_CR_JONES_PERF_SELECT0,
    RGX_CR_JONES_PERF_COUNTER_0,
    RGX_CR_BLACKPEARL_PERF,
    RGX_CR_BLACKPEARL_PERF_SELECT0,
    RGX_CR_BLACKPEARL_PERF_COUNTER_0,
    RGX_CR_PBE_PERF,
    RGX_CR_PBE_PERF_SELECT0,
    RGX_CR_PBE_PERF_COUNTER_0,
    RGX_CR_OCP_REVINFO,
    RGX_CR_OCP_SYSCONFIG,
    RGX_CR_OCP_IRQSTATUS_RAW_0,
    RGX_CR_OCP_IRQSTATUS_RAW_1,
    RGX_CR_OCP_IRQSTATUS_RAW_2,
    RGX_CR_OCP_IRQSTATUS_0,
    RGX_CR_OCP_IRQSTATUS_1,
    RGX_CR_OCP_IRQSTATUS_2,
    RGX_CR_OCP_IRQENABLE_SET_0,
    RGX_CR_OCP_IRQENABLE_SET_1,
    RGX_CR_OCP_IRQENABLE_SET_2,
    RGX_CR_OCP_IRQENABLE_CLR_0,
    RGX_CR_OCP_IRQENABLE_CLR_1,
    RGX_CR_OCP_IRQENABLE_CLR_2,
    RGX_CR_OCP_IRQ_EVENT,
    RGX_CR_OCP_DEBUG_CONFIG,
    RGX_CR_OCP_DEBUG_STATUS,
    RGX_CR_BIF_TRUST,
    RGX_CR_SYS_BUS_SECURE,
#if defined(RGX_FEATURE_RAY_TRACING)
    RGX_CR_FBA_FC0_CHECKSUM,
    RGX_CR_FBA_FC1_CHECKSUM,
    RGX_CR_FBA_FC2_CHECKSUM,
    RGX_CR_FBA_FC3_CHECKSUM,
#endif
    RGX_CR_CLK_CTRL2,
    RGX_CR_CLK_STATUS2,
#if defined(RGX_FEATURE_RAY_TRACING)
    RGX_CR_RPM_SHF_FPL,
    RGX_CR_RPM_SHF_FPL_READ,
    RGX_CR_RPM_SHF_FPL_WRITE,
    RGX_CR_RPM_SHG_FPL,
    RGX_CR_RPM_SHG_FPL_READ,
    RGX_CR_RPM_SHG_FPL_WRITE,
#endif
    RGX_CR_SH_PERF,
    RGX_CR_SH_PERF_SELECT0,
    RGX_CR_SH_PERF_COUNTER_0,
#if defined(RGX_FEATURE_RAY_TRACING)
    RGX_CR_SHF_SHG_CHECKSUM,
    RGX_CR_SHF_VERTEX_BIF_CHECKSUM,
    RGX_CR_SHF_VARY_BIF_CHECKSUM,
    RGX_CR_RPM_BIF_CHECKSUM,
    RGX_CR_SHG_BIF_CHECKSUM,
    RGX_CR_SHG_FE_BE_CHECKSUM,
    DPX_CR_BF_PERF,
    DPX_CR_BF_PERF_SELECT0,
    DPX_CR_BF_PERF_COUNTER_0,
    DPX_CR_BT_PERF,
    DPX_CR_BT_PERF_SELECT0,
    DPX_CR_BT_PERF_COUNTER_0,
    DPX_CR_RQ_USC_DEBUG,
    DPX_CR_BIF_FAULT_BANK_MMU_STATUS,
    DPX_CR_BIF_FAULT_BANK_REQ_STATUS,
    DPX_CR_BIF_MMU_STATUS,
    DPX_CR_RT_PERF,
    DPX_CR_RT_PERF_SELECT0,
    DPX_CR_RT_PERF_COUNTER_0,
    DPX_CR_BX_TU_PERF,
    DPX_CR_BX_TU_PERF_SELECT0,
    DPX_CR_BX_TU_PERF_COUNTER_0,
    DPX_CR_RS_PDS_RR_CHECKSUM,
#endif
    RGX_CR_MMU_CBASE_MAPPING_CONTEXT,
    RGX_CR_MMU_CBASE_MAPPING,
    RGX_CR_MMU_FAULT_STATUS,
    RGX_CR_MMU_FAULT_STATUS_META,
    RGX_CR_SLC3_CTRL_MISC,
    RGX_CR_SLC3_SCRAMBLE,
    RGX_CR_SLC3_SCRAMBLE2,
    RGX_CR_SLC3_SCRAMBLE3,
    RGX_CR_SLC3_SCRAMBLE4,
    RGX_CR_SLC3_STATUS,
    RGX_CR_SLC3_IDLE,
    RGX_CR_SLC3_FAULT_STOP_STATUS,
    RGX_CR_VDM_CONTEXT_STORE_MODE,
    RGX_CR_CONTEXT_MAPPING0,
    RGX_CR_CONTEXT_MAPPING1,
    RGX_CR_CONTEXT_MAPPING2,
    RGX_CR_CONTEXT_MAPPING3,
    RGX_CR_BIF_JONES_OUTSTANDING_READ,
    RGX_CR_BIF_BLACKPEARL_OUTSTANDING_READ,
    RGX_CR_BIF_DUST_OUTSTANDING_READ,
    RGX_CR_CONTEXT_MAPPING4,
};

static inline bool gx6xxx_is_irq_pending(struct gx6xxx_info *info)
{
    uint32_t irq_status;

#if 1
    irq_status = readl(info->reg_vaddr_irq_status);
#else
    irq_status = gx6xxx_read32(coproc, RGXFW_CR_IRQ_STATUS);
#endif
    return irq_status & RGXFW_CR_IRQ_STATUS_EVENT_EN;
}

static int gx6xxx_poll_reg32(struct coproc_device *coproc, uint32_t offset,
                             uint32_t expected, uint32_t mask)
{
    uint32_t val;
    int retry = GX6XXX_POLL_TO_NUM_US;

    do
    {
        /* read current register value and mask only those bits requested */
        val = gx6xxx_read32(coproc, offset) & mask;
        if ( val == expected )
            return 0;
        cpu_relax();
        udelay(1);
    } while (retry--);
    COPROC_VERBOSE(NULL, "%s expected %08x got %08x ))))))))))))))))))))))))))))))))))))))))\n",
                   __FUNCTION__, expected, val);
    return -ETIMEDOUT;
}

static int gx6xxx_poll_val32(struct coproc_device *coproc,
                             volatile uint32_t *val, uint32_t expected,
                             uint32_t mask)
{
    int retry = GX6XXX_POLL_TO_NUM_US;

    do
    {
        if ( (*val & mask) == expected )
            return 0;
        cpu_relax();
        udelay(1);
    } while (retry--);
    COPROC_VERBOSE(NULL, "%s expected %08x got %08x ))))))))))))))))))))))))))))))))))))))))\n",
                   __FUNCTION__, expected, *val);
    return -ETIMEDOUT;
}

static int gx6xxx_poll_reg64(struct coproc_device *coproc, uint32_t offset,
                             uint64_t expected, uint64_t mask)
{
    uint64_t val;
    int retry = GX6XXX_POLL_TO_NUM_US;

    do
    {
        /* read current register value and mask only those bits requested */
        val = gx6xxx_read64(coproc, offset) & mask;
        if ( val == expected )
            return 0;
        cpu_relax();
        udelay(1);
    } while (retry--);
    COPROC_VERBOSE(NULL, "%s expected %016lx got %016lx ))))))))))))))))))))))))))))))))))))))))\n",
                   __FUNCTION__, expected, val);
    return -ETIMEDOUT;
}

static int gx6xxx_write_via_slave_port32(struct coproc_device *coproc,
                                         uint32_t offset, uint32_t val)
{
    int ret;

    /* Wait for Slave Port to be Ready */
    ret = gx6xxx_poll_reg32(coproc, RGX_CR_META_SP_MSLVCTRL1,
                          RGX_CR_META_SP_MSLVCTRL1_READY_EN|RGX_CR_META_SP_MSLVCTRL1_GBLPORT_IDLE_EN,
                          RGX_CR_META_SP_MSLVCTRL1_READY_EN|RGX_CR_META_SP_MSLVCTRL1_GBLPORT_IDLE_EN);
    if ( ret < 0 )
        return ret;

    /* Issue a Write */
    gx6xxx_write32(coproc, RGX_CR_META_SP_MSLVCTRL0, offset);
    gx6xxx_write32(coproc, RGX_CR_META_SP_MSLVDATAT, val);

    return 0;
}

static int gx6xxx_read_via_slave_port32(struct coproc_device *coproc,
                                        uint32_t offset, uint32_t *val)
{
    int ret;

    /* Wait for Slave Port to be Ready */
    ret = gx6xxx_poll_reg32(coproc, RGX_CR_META_SP_MSLVCTRL1,
                            RGX_CR_META_SP_MSLVCTRL1_READY_EN|RGX_CR_META_SP_MSLVCTRL1_GBLPORT_IDLE_EN,
                            RGX_CR_META_SP_MSLVCTRL1_READY_EN|RGX_CR_META_SP_MSLVCTRL1_GBLPORT_IDLE_EN);
    if ( ret < 0 )
        return ret;

    /* Issue a Read */
    gx6xxx_write32(coproc, RGX_CR_META_SP_MSLVCTRL0, offset | RGX_CR_META_SP_MSLVCTRL0_RD_EN);

    /* Wait for Slave Port to be Ready */
    ret = gx6xxx_poll_reg32(coproc, RGX_CR_META_SP_MSLVCTRL1,
                            RGX_CR_META_SP_MSLVCTRL1_READY_EN|RGX_CR_META_SP_MSLVCTRL1_GBLPORT_IDLE_EN,
                            RGX_CR_META_SP_MSLVCTRL1_READY_EN|RGX_CR_META_SP_MSLVCTRL1_GBLPORT_IDLE_EN);
    if ( ret < 0 )
        return ret;

    *val = gx6xxx_read32(coproc, RGX_CR_META_SP_MSLVDATAX);
    return 0;
}

static inline int gx6xxx_wait_fw_started(struct vcoproc_instance *vcoproc,
                                         struct vgx6xxx_info *vinfo,
                                         IMG_BOOL expected)
{
    /* TODO: this needs to be done on framework level, e.g.
     * currently on ctx switch to we have no possibility to return wait_time
     * needed to wait for the FW to be started.
     * Temporarily use re-try counter
     */
    int ret, retry = 10;

    while (retry--)
    {
        ret = gx6xxx_poll_val32(vcoproc->coproc,
                                (volatile IMG_BOOL *)&vinfo->fw_init->bFirmwareStarted,
                                expected, 0xFFFFFFFF);
        COPROC_VERBOSE(NULL, "vinfo->fw_init->bFirmwareStarted %d\n",
                       vinfo->fw_init->bFirmwareStarted);
        if ( !ret )
            break;
    }
    return ret;
}

static s_time_t gx6xxx_save_reg_ctx(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;
    int i;

    for (i = 0; i < vinfo->reg_ctx.count; i++)
    {
        vinfo->reg_ctx.regs[i].val = gx6xxx_read64(vcoproc->coproc,
                                                   gx6xxx_ctx_reg_offsets[i]);
        gx6xxx_write64(vcoproc->coproc, gx6xxx_ctx_reg_offsets[i], 0);
    }
    return 0;
}

static void gx6xxx_restore_reg_ctx(struct vcoproc_instance *vcoproc,
                                   struct vgx6xxx_info *vinfo)
{
    int i;

    for (i = 0; i < vinfo->reg_ctx.count; i++)
        gx6xxx_write64(vcoproc->coproc, gx6xxx_ctx_reg_offsets[i],
                       vinfo->reg_ctx.regs[i].val);
    COPROC_VERBOSE(NULL, "restored %d registers\n",
                   vinfo->reg_ctx.count);
    /* force all clocks on */
    gx6xxx_write64(vcoproc->coproc, RGX_CR_CLK_CTRL, RGX_CR_CLK_CTRL_ALL_ON);
}

static inline bool gx6xxx_run_if_not_idle_or_off(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;

    if ( unlikely((vinfo->fw_trace_buf->ePowState == RGXFWIF_POW_FORCED_IDLE) ||
                  (vinfo->fw_trace_buf->ePowState == RGXFWIF_POW_OFF)) )
        return false;
    return true;
}

static inline bool gx6xxx_run_if_not_off(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;

    return vinfo->fw_trace_buf->ePowState != RGXFWIF_POW_OFF;
}

static inline bool gx6xxx_run_always(struct vcoproc_instance *vcoproc)
{
    return true;
}

static inline bool gx6xxx_run_if_kccb_pending(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;

    return vinfo->state_kccb_read_ofs != ~0;
}

static inline bool gx6xxx_run_if_psync_pending(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;

    return vinfo->state_psync_pending;
}

static s_time_t gx6xxx_wait_kccb(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;
    int ret;

    ret = gx6xxx_fw_wait_kccb_cmd(vcoproc, vinfo);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;
    vinfo->state_kccb_read_ofs = ~0;
    return 0;
}

static s_time_t gx6xxx_wait_psync(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;
    int ret, retry = 10;

    /* wait for GPU to finish current workload */
    do
    {
        ret = gx6xxx_poll_val32(vcoproc->coproc, vinfo->fw_power_sync,
                                0x1, 0xFFFFFFFF);
        if ( ret < 0 )
            continue;
    } while (retry--);
    if ( ret < 0 )
        return GX6XXX_WAIT_TIME_US;
    return 0;
}

static s_time_t gx6xxx_force_idle(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;
    RGXFWIF_KCCB_CMD pow_cmd;
    int ret;


    pow_cmd.eDM = RGXFWIF_DM_GP;
    pow_cmd.eCmdType = RGXFWIF_KCCB_CMD_POW;
    pow_cmd.uCmdData.sPowData.ePowType = RGXFWIF_POW_FORCED_IDLE_REQ;
    pow_cmd.uCmdData.sPowData.uPoweReqData.bCancelForcedIdle = IMG_FALSE;

    vinfo->fw_power_sync[0] = 0;
    vinfo->state_psync_pending = true;
    ret = gx6xxx_fw_send_kccb_cmd(vcoproc, vinfo, &pow_cmd, 1);
    if ( unlikely(ret < 0) )
    {
        COPROC_ERROR(vcoproc->coproc->dev,
                     "failed to send forced idle command to FW\n");
        return ret;
    }
    return 0;
}

static s_time_t gx6xxx_force_idle_check(struct vcoproc_instance *vcoproc)
{
    /* we are forcing IDLE state, if FW is not OFF or IDLE, then something
     * goes wrong, Run condition for this check is not IDLE and not OFF,
     * so just return error
     */
    return -EAGAIN;
}

static s_time_t gx6xxx_request_power_off(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;
    RGXFWIF_KCCB_CMD pow_cmd[RGXFWIF_DM_MAX];
    int i, ret;

    /* prepare commands to be sent to the FW */
    for (i = 0; i < ARRAY_SIZE(pow_cmd); i++)
    {
        pow_cmd[i].eCmdType = RGXFWIF_KCCB_CMD_POW;
        pow_cmd[i].uCmdData.sPowData.ePowType = RGXFWIF_POW_OFF_REQ;
        pow_cmd[i].uCmdData.sPowData.uPoweReqData.bForced = IMG_TRUE;
        pow_cmd[i].eDM = i;
    }
    /* prepare to sync with the FW and send out requests */
    vinfo->fw_power_sync[0] = 0;
    vinfo->state_psync_pending = true;
    ret = gx6xxx_fw_send_kccb_cmd(vcoproc, vinfo, pow_cmd, ARRAY_SIZE(pow_cmd));
    if ( unlikely(ret < 0) )
    {
        COPROC_ERROR(vcoproc->coproc->dev,
                     "failed to send power off command to FW\n");
        return ret;
    }
    return 0;
}

static s_time_t gx6xxx_wait_for_interrupts(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;
    struct gx6xxx_info *info = (struct gx6xxx_info *)vcoproc->coproc->priv;
    int to_us = GX6XXX_POLL_TO_NUM_US;

    while ( (atomic_read(&vinfo->irq_count) !=
             vinfo->fw_trace_buf->aui32InterruptCount[0]) && to_us-- )
    {
        if ( gx6xxx_is_irq_pending(info) )
            return 1;
        cpu_relax();
        udelay(1);
    }
    if (!to_us)
    {
        COPROC_DEBUG(NULL, "TIMEDOUT, IRQs: FW %d vs Xen %d\n",
                     vinfo->fw_trace_buf->aui32InterruptCount[0],
                     atomic_read(&vinfo->irq_count));
        return GX6XXX_WAIT_TIME_US;
    }
    return 0;
}

static s_time_t gx6xxx_wait_for_slc_idle(struct vcoproc_instance *vcoproc)
{
    struct coproc_device *coproc = vcoproc->coproc;
    int ret;

    ret = gx6xxx_poll_reg32(coproc, RGX_CR_SIDEKICK_IDLE,
                            RGX_CR_SIDEKICK_IDLE_MASKFULL^(RGX_CR_SIDEKICK_IDLE_GARTEN_EN|RGX_CR_SIDEKICK_IDLE_SOCIF_EN|RGX_CR_SIDEKICK_IDLE_HOSTIF_EN),
                            RGX_CR_SIDEKICK_IDLE_MASKFULL^(RGX_CR_SIDEKICK_IDLE_GARTEN_EN|RGX_CR_SIDEKICK_IDLE_SOCIF_EN|RGX_CR_SIDEKICK_IDLE_HOSTIF_EN));
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    ret = gx6xxx_poll_reg32(coproc, RGX_CR_SLC_IDLE,
                            RGX_CR_SLC_IDLE_MASKFULL,
                            RGX_CR_SLC_IDLE_MASKFULL);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;
    return 0;
}

static s_time_t gx6xxx_deassoc_threads(struct vcoproc_instance *vcoproc)
{
    struct coproc_device *coproc = vcoproc->coproc;

    gx6xxx_write32(coproc, RGX_CR_MTS_INTCTX_THREAD0_DM_ASSOC,
                   RGX_CR_MTS_INTCTX_THREAD0_DM_ASSOC_DM_ASSOC_CLRMSK
                   & RGX_CR_MTS_INTCTX_THREAD0_DM_ASSOC_MASKFULL);

    gx6xxx_write32(coproc, RGX_CR_MTS_BGCTX_THREAD0_DM_ASSOC,
                   RGX_CR_MTS_BGCTX_THREAD0_DM_ASSOC_DM_ASSOC_CLRMSK
                   & RGX_CR_MTS_BGCTX_THREAD0_DM_ASSOC_MASKFULL);

    gx6xxx_write32(coproc, RGX_CR_MTS_INTCTX_THREAD1_DM_ASSOC,
                   RGX_CR_MTS_INTCTX_THREAD1_DM_ASSOC_DM_ASSOC_CLRMSK
                   & RGX_CR_MTS_INTCTX_THREAD1_DM_ASSOC_MASKFULL);

    gx6xxx_write32(coproc, RGX_CR_MTS_BGCTX_THREAD1_DM_ASSOC,
                   RGX_CR_MTS_BGCTX_THREAD1_DM_ASSOC_DM_ASSOC_CLRMSK
                   & RGX_CR_MTS_BGCTX_THREAD1_DM_ASSOC_MASKFULL);
    return 0;
}

static s_time_t gx6xxx_disable_threads(struct vcoproc_instance *vcoproc)
{
    struct coproc_device *coproc = vcoproc->coproc;
    int ret;

    /* disable thread 0 */
    ret = gx6xxx_write_via_slave_port32(coproc,
                                        META_CR_T0ENABLE_OFFSET,
                                        ~META_CR_TXENABLE_ENABLE_BIT);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    /* disable thread 1 */
    ret = gx6xxx_write_via_slave_port32(coproc,
                                        META_CR_T1ENABLE_OFFSET,
                                        ~META_CR_TXENABLE_ENABLE_BIT);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;
    /* clear down any irq raised by META (done after disabling the FW
     * threads to avoid a race condition).
     */
    gx6xxx_write32(coproc, RGX_CR_META_SP_MSLVIRQSTATUS, 0x0);
    return 0;
}

static s_time_t gx6xxx_wait_all_idle(struct vcoproc_instance *vcoproc)
{
    struct coproc_device *coproc = vcoproc->coproc;
    uint32_t val;
    int ret;

    /* wait for the slave port to finish all the transactions */
    ret = gx6xxx_poll_reg32(coproc, RGX_CR_META_SP_MSLVCTRL1,
                            RGX_CR_META_SP_MSLVCTRL1_READY_EN | RGX_CR_META_SP_MSLVCTRL1_GBLPORT_IDLE_EN,
                            RGX_CR_META_SP_MSLVCTRL1_READY_EN | RGX_CR_META_SP_MSLVCTRL1_GBLPORT_IDLE_EN);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    /* extra idle checks */
    ret = gx6xxx_poll_reg32(coproc, RGX_CR_BIF_STATUS_MMU,
                            0, RGX_CR_BIF_STATUS_MMU_MASKFULL);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    ret = gx6xxx_poll_reg32(coproc, RGX_CR_BIFPM_STATUS_MMU,
                            0, RGX_CR_BIFPM_STATUS_MMU_MASKFULL);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    ret = gx6xxx_poll_reg32(coproc, RGX_CR_BIFPM_READS_EXT_STATUS,
                            0, RGX_CR_BIFPM_READS_EXT_STATUS_MASKFULL);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    ret = gx6xxx_poll_reg64(coproc, RGX_CR_SLC_STATUS1,
                            0, RGX_CR_SLC_STATUS1_MASKFULL);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    ret = gx6xxx_poll_reg32(coproc, RGX_CR_SLC_IDLE,
                            RGX_CR_SLC_IDLE_MASKFULL,
                            RGX_CR_SLC_IDLE_MASKFULL);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    ret = gx6xxx_poll_reg32(coproc, RGX_CR_SIDEKICK_IDLE,
                            RGX_CR_SIDEKICK_IDLE_MASKFULL^(RGX_CR_SIDEKICK_IDLE_GARTEN_EN|RGX_CR_SIDEKICK_IDLE_SOCIF_EN|RGX_CR_SIDEKICK_IDLE_HOSTIF_EN),
                            RGX_CR_SIDEKICK_IDLE_MASKFULL^(RGX_CR_SIDEKICK_IDLE_GARTEN_EN|RGX_CR_SIDEKICK_IDLE_SOCIF_EN|RGX_CR_SIDEKICK_IDLE_HOSTIF_EN));
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    ret =  gx6xxx_read_via_slave_port32(coproc, META_CR_TxVECINT_BHALT, &val);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;

    if ( (val & 0xFFFFFFFFU) == 0 )
    {
        /* Wait for Sidekick/Jones to signal IDLE including
         * the Garten Wrapper if there is no debugger attached
         * (TxVECINT_BHALT = 0x0) */
        ret = gx6xxx_poll_reg32(coproc, RGX_CR_SIDEKICK_IDLE,
                                RGX_CR_SIDEKICK_IDLE_GARTEN_EN,
                                RGX_CR_SIDEKICK_IDLE_GARTEN_EN);
        if ( unlikely(ret < 0) )
            return GX6XXX_WAIT_TIME_US;
    }
    return 0;
}

static s_time_t gx6xxx_wait_fw_stopped(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;
    int ret;

    ret = gx6xxx_wait_fw_started(vcoproc, vinfo, IMG_FALSE);
    if ( unlikely(ret < 0) )
        return GX6XXX_WAIT_TIME_US;
    return 0;
}

struct gx6xxx_ctx_switch_state gx6xxx_ctx_gpu_stop_states[] =
{
    /* FORCE IDLE */
    {
        .handler = gx6xxx_force_idle,
        .run_condition = gx6xxx_run_if_not_idle_or_off,
        .name = "force_idle",
    },
    {
        .handler = gx6xxx_wait_kccb,
        .run_condition = gx6xxx_run_if_kccb_pending,
        .name = "\tidle wait_kccb",
    },
    {
        .handler = gx6xxx_wait_psync,
        .run_condition = gx6xxx_run_if_psync_pending,
        .name = "\tidle wait_psync",
    },
    {
        .handler = gx6xxx_force_idle_check,
        .run_condition = gx6xxx_run_if_not_idle_or_off,
        .name = "\tforce_idle_check",
    },
    /* REQUEST POWER OFF */
    {
        .handler = gx6xxx_request_power_off,
        .run_condition = gx6xxx_run_if_not_off,
        .name = "request_power_off",
    },
    {
        .handler = gx6xxx_wait_kccb,
        .run_condition = gx6xxx_run_if_kccb_pending,
        .name = "\tpoff wait_kccb",
    },
    {
        .handler = gx6xxx_wait_psync,
        .run_condition = gx6xxx_run_if_psync_pending,
        .name = "\tpoff wait_psync",
    },
    /* WAIT FOR LAST CHANCE INTERRUPTS */
    {
        .handler = gx6xxx_wait_for_interrupts,
        .run_condition = gx6xxx_run_always,
        .name = "wait_for_interrupts",
    },
    /* FIXME: SAVE REGISTERS NOW */
    {
        .handler = gx6xxx_save_reg_ctx,
        .run_condition = gx6xxx_run_always,
        .name = "save_reg_ctx",
    },
    /* WAIT FOR SLC AND SIDEKICK */
    {
        .handler = gx6xxx_wait_for_slc_idle,
        .run_condition = gx6xxx_run_always,
        .name = "wait_for_slc_idle",
    },
    /* DE-ASSOCIATE ALL THREADS */
    {
        .handler = gx6xxx_deassoc_threads,
        .run_condition = gx6xxx_run_always,
        .name = "deassoc_threads",
    },
    /* DISABLE ALL THREADS */
    {
        .handler = gx6xxx_disable_threads,
        .run_condition = gx6xxx_run_always,
        .name = "disable_threads",
    },
    /* WAIT FOR ALL IDLE */
    {
        .handler = gx6xxx_wait_all_idle,
        .run_condition = gx6xxx_run_always,
        .name = "wait_all_idle",
    },
    /* WAIT FOR FW STOPPED */
    {
        .handler = gx6xxx_wait_fw_stopped,
        .run_condition = gx6xxx_run_always,
        .name = "wait_fw_stopped",
    },
    {
        NULL
    }
};

static const char *power_state_to_str(RGXFWIF_POW_STATE state)
{
    switch (state)
    {
    case RGXFWIF_POW_OFF:
        return "RGXFWIF_POW_OFF";
    case RGXFWIF_POW_ON:
        return "RGXFWIF_POW_ON";
    case RGXFWIF_POW_FORCED_IDLE:
        return "RGXFWIF_POW_FORCED_IDLE";
    case RGXFWIF_POW_IDLE:
        return "RGXFWIF_POW_IDLE";
    default:
        break;
    }
    return "Unknown";
}

#define RGX_CR_SOFT_RESET_ALL   (RGX_CR_SOFT_RESET_MASKFULL)

static __maybe_unused s_time_t gx6xxx_slc_flush_inval(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;
    RGXFWIF_KCCB_CMD flush_cmd;
    int ret;

    flush_cmd.eDM = RGXFWIF_DM_GP;
    flush_cmd.eCmdType = RGXFWIF_KCCB_CMD_SLCFLUSHINVAL;
    flush_cmd.uCmdData.sSLCFlushInvalData.bDMContext = IMG_FALSE;
    /* FIXME: the below don't care if no context provided which is the case */
    flush_cmd.uCmdData.sSLCFlushInvalData.bInval = IMG_TRUE;
    flush_cmd.uCmdData.sSLCFlushInvalData.eDM = 0;
    flush_cmd.uCmdData.sSLCFlushInvalData.psContext.ui32Addr = 0;

    vinfo->fw_power_sync[0] = 0;
    ret = gx6xxx_fw_send_kccb_cmd(vcoproc, vinfo, &flush_cmd, 1);
    if ( unlikely(ret < 0) )
    {
        COPROC_ERROR(vcoproc->coproc->dev,
                     "failed to send SLC flush/invalidate command to FW\n");
        return ret;
    }
    return 0;
}

static __maybe_unused s_time_t gx6xxx_mmu_flush_inval(struct vcoproc_instance *vcoproc)
{
    struct vgx6xxx_info *vinfo = (struct vgx6xxx_info *)vcoproc->priv;
    RGXFWIF_KCCB_CMD flush_cmd;
    int ret;

    flush_cmd.eDM = RGXFWIF_DM_GP;
    flush_cmd.eCmdType = RGXFWIF_KCCB_CMD_MMUCACHE;
    flush_cmd.uCmdData.sMMUCacheData.ui32Flags = RGXFWIF_MMUCACHEDATA_FLAGS_CTX_ALL;
    flush_cmd.uCmdData.sMMUCacheData.ui32Flags = 0xfffffff;
    flush_cmd.uCmdData.sMMUCacheData.psMemoryContext.ui32Addr = 0;

    vinfo->fw_power_sync[0] = 0;
    ret = gx6xxx_fw_send_kccb_cmd(vcoproc, vinfo, &flush_cmd, 1);
    if ( unlikely(ret < 0) )
    {
        COPROC_ERROR(vcoproc->coproc->dev,
                     "failed to send MMU flush/invalidate command to FW\n");
        return ret;
    }
    return 0;
}

int gx6xxx_ctx_gpu_start(struct vcoproc_instance *vcoproc,
                         struct vgx6xxx_info *vinfo)
{
    struct coproc_device *coproc = vcoproc->coproc;
    int ret;

    vinfo->state_kccb_read_ofs = ~0;
    vinfo->state_psync_pending = false;

    gx6xxx_restore_reg_ctx(vcoproc, vinfo);

    /* perform soft-reset */
    gx6xxx_write64(coproc, RGX_CR_SOFT_RESET, RGX_CR_SOFT_RESET_ALL);
    gx6xxx_write64(coproc, RGX_CR_SOFT_RESET,
                   RGX_CR_SOFT_RESET_ALL ^ RGX_CR_SOFT_RESET_RASCALDUSTS_EN);
    (void)gx6xxx_read64(coproc, RGX_CR_SOFT_RESET);

    /* start everything, but META */
    gx6xxx_write64(coproc, RGX_CR_SOFT_RESET, RGX_CR_SOFT_RESET_GARTEN_EN);

    gx6xxx_write32(coproc, RGX_CR_SLC_CTRL_MISC,
                   vinfo->reg_val_cr_slc_ctrl_misc.as.lo);
    gx6xxx_write32(coproc, RGX_CR_META_BOOT,
                   vinfo->reg_val_cr_meta_boot.as.lo);
    gx6xxx_write64(coproc, RGX_CR_MTS_GARTEN_WRAPPER_CONFIG,
                   vinfo->reg_val_cr_mts_garten_wrapper_config.val);
    gx6xxx_write64(coproc, RGX_CR_AXI_ACE_LITE_CONFIGURATION,
                   vinfo->reg_val_cr_axi_ace_lite_configuration.val);
    gx6xxx_write64(coproc, RGX_CR_BIF_CAT_BASE0,
                   vinfo->reg_val_cr_bif_cat_base0.val);

    /* wait for at least 16 cycles */
    udelay(32);

    gx6xxx_write64(coproc, RGX_CR_SOFT_RESET, 0x0);
    (void)gx6xxx_read64(coproc, RGX_CR_SOFT_RESET);

    /* wait for at least 16 cycles */
    udelay(32);

    /* FIXME: if slave is booting then it needs a kick to start */

    /* finally check that FW reports it's started */
    ret = gx6xxx_wait_fw_started(vcoproc, vinfo, IMG_TRUE);
    if ( ret < 0 )
    {
        COPROC_ERROR(coproc->dev, "Firmware has not yet started\n");
        /* TODO: context switch to cannot handle wait_time as context
         * switch from does. this needs to be addressed
         */
        BUG();
#if 0
        return ret;
#endif
    }
#if 0 /* FIXME: With new version of pvr_km these commands are not functional. */
    gx6xxx_slc_flush_inval(vcoproc);
    gx6xxx_wait_kccb(vcoproc);
//    gx6xxx_wait_psync(vcoproc);
    gx6xxx_mmu_flush_inval(vcoproc);
    gx6xxx_wait_kccb(vcoproc);
//    gx6xxx_wait_psync(vcoproc);
#endif
    /* flush scheduled work */
    if ( likely(vinfo->reg_cr_mts_schedule_lo_wait_cnt) )
    {
        COPROC_ERROR(NULL, "dom %d has %d scheduled tasks\n",
                     vcoproc->domain->domain_id,
                     vinfo->reg_cr_mts_schedule_lo_wait_cnt);
        do
        {
            gx6xxx_write32(coproc, RGX_CR_MTS_SCHEDULE,
                           RGX_CR_MTS_SCHEDULE_TASK_COUNTED);
        }
        while (--vinfo->reg_cr_mts_schedule_lo_wait_cnt);
    }
    return 0;
}

#ifdef GX6XXX_DEBUG_PERF
/* FIXME: we don't care about overflows...
 * FIXME: we collect stats for all vcoprocs
 */
static void gx6xxx_ctx_dbg_update(struct gx6xxx_ctx_switch_state *state,
                                  s_time_t start, s_time_t end)
{
    s_time_t delta;

    delta = end - start;

    /* TODO: find a better way to initialize */
    if ( unlikely(!state->time_min) )
        state->time_min = STIME_MAX;

    if ( state->time_min > delta )
        state->time_min = delta;
    if ( state->time_max < delta )
        state->time_max = delta;
}
#endif

/* try stopping the GPU: 0 on success, <0 if still busy */
int gx6xxx_ctx_gpu_stop(struct vcoproc_instance *vcoproc,
                        struct vgx6xxx_info *vinfo)
{
    struct coproc_device *coproc = vcoproc->coproc;
    struct gx6xxx_info *info = (struct gx6xxx_info *)coproc->priv;
    s_time_t wait_time;
#ifdef GX6XXX_DEBUG_PERF
    s_time_t dbg_time_start;
#endif

    /* XXX: we CANNOT receive interrupts at this time - scheduler has
     * disabled the interrupts
     */
    COPROC_DEBUG(NULL, "%s sPowerState is %s\n", __FUNCTION__,
                  power_state_to_str(vinfo->fw_trace_buf->ePowState));
    COPROC_DEBUG(NULL, "%s FW reports %d vs Xen %d IRQs\n", __FUNCTION__,
                 vinfo->fw_trace_buf->aui32InterruptCount[0],
           atomic_read(&vinfo->irq_count));
    while ( info->state_curr->handler )
    {
        COPROC_VERBOSE(NULL, "%s state %s\n", __FUNCTION__,
                       info->state_curr->name);
#ifdef GX6XXX_DEBUG_PERF
        dbg_time_start = NOW();
#endif
        /* if there is an interrupt pending return minimally possible
         * time, so scheduler unlocks interrupts and we have a chance to
         * handle it
         */
        if ( gx6xxx_is_irq_pending(info) )
            return 1;

        if ( likely(info->state_curr->run_condition(vcoproc)) )
        {
            wait_time = info->state_curr->handler(vcoproc);
            if ( wait_time == 0)
                info->state_curr->num_retries = 0;
            else if ( wait_time > 0 )
            {
                info->state_curr->num_retries++;
#if GX6XXX_DEBUG_PERF
                gx6xxx_ctx_dbg_update(info->state_curr, dbg_time_start, NOW());
#endif
                return wait_time;
            }
            else
            {
                COPROC_VERBOSE(NULL, "%s wait_time %ld\n",
                               __FUNCTION__, wait_time);
                /* step failed */
                if ( wait_time == -EAGAIN )
                {
                    COPROC_DEBUG(NULL, "%s wait_time %ld step failed\n",
                                 __FUNCTION__, wait_time);
                }
                break;
            }
        }
#ifdef GX6XXX_DEBUG_PERF
        gx6xxx_ctx_dbg_update(info->state_curr, dbg_time_start, NOW());
#endif
        /* ready for the next step */
        info->state_curr++;
    }
    if ( unlikely(!info->state_curr->handler) )
        COPROC_DEBUG(NULL, "%s GPU stopped\n", __FUNCTION__);
    return 0;
}

int gx6xxx_ctx_init(struct vcoproc_instance *vcoproc,
                        struct vgx6xxx_info *vinfo)
{
    int ret;

    vinfo->reg_ctx.count = ARRAY_SIZE(gx6xxx_ctx_reg_offsets);
    COPROC_DEBUG(vcoproc->coproc->dev,
                 "allocating register context for %d registers\n",
                 vinfo->reg_ctx.count);
    vinfo->reg_ctx.regs = (union reg64_t *)xzalloc_array(struct vgx6xxx_ctx,
                    vinfo->reg_ctx.count);
    if ( !vinfo->reg_ctx.regs )
    {
        COPROC_ERROR(vcoproc->coproc->dev,
                     "failed to allocate vcoproc register context buffer\n");
        ret = -ENOMEM;
        goto fail;
    }
    return 0;
fail:
    xfree(vinfo->reg_ctx.regs);
    return ret;
}

void gx6xxx_ctx_deinit(struct vcoproc_instance *vcoproc,
                           struct vgx6xxx_info *vinfo)
{
    xfree(vinfo->reg_ctx.regs);
}
