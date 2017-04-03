#include "gx6xxx_coproc.h"
#include "gx6xxx_hexdump.h"

void gx6xxx_dump(uint32_t *vaddr, int size)
{
    int i, j;
    uint32_t *ptr = (uint32_t *)vaddr;

    for (i = 0; i < size / sizeof(uint32_t) / 4; i++)
    {
        for (j = 0; j < 4; j++)
            printk(" %08x", *ptr++);
        printk("\n");
    }
}

void gx6xxx_1_to_1_mapping_chk(struct vcoproc_instance *vcoproc,
                               paddr_t start, paddr_t end)
{
#ifdef GX6XXX_DEBUG
    struct domain *d = vcoproc->domain;
    mfn_t mfn;
    pfn_t i;

    for (i = paddr_to_pfn(start); i < paddr_to_pfn(end + 1); i++)
    {
        mfn = p2m_lookup(d, _gfn(i), NULL);
        if ( i != mfn )
        {
            printk("mfn %lx != pfn %lx\n", mfn, i);
        }
    }
#endif
}
