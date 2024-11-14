/* SPDX-License-Identifier: MIT */
/*
  This file is based on libafl_qemu_impl.h, libafl_qemu_qemu_arch.h
  and libafl_qemu_defs.h from LibAFL project.
*/
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/kernel.h>
#include <xen/spinlock.h>
#include <xen/libafl-qemu.h>
#include <asm/libafl-qemu.h>

/* Generates sync exit functions */
LIBAFL_DEFINE_FUNCTIONS(sync_exit, LIBAFL_SYNC_EXIT_OPCODE)

    void libafl_qemu_end(enum LibaflQemuEndStatus status)
{
    _libafl_sync_exit_call1(LIBAFL_QEMU_COMMAND_END, status);
}

void libafl_qemu_internal_error(void)
{
    _libafl_sync_exit_call0(LIBAFL_QEMU_COMMAND_INTERNAL_ERROR);
}

void lqprintf(const char *fmt, ...)
{
    static DEFINE_SPINLOCK(lock);
    static char buffer[LIBAFL_QEMU_PRINTF_MAX_SIZE] = {0};
    va_list args;
    int res;

    spin_lock(&lock);

    va_start(args, fmt);
    res = vsnprintf(buffer, LIBAFL_QEMU_PRINTF_MAX_SIZE, fmt, args);
    va_end(args);

    if ( res >= LIBAFL_QEMU_PRINTF_MAX_SIZE )
    {
        /* buffer is not big enough, either recompile the target with more */
        /* space or print less things */
        libafl_qemu_internal_error();
    }

    _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_LQPRINTF,
                            (libafl_word)buffer, res);
    spin_unlock(&lock);
}

void libafl_qemu_trace_vaddr_range(libafl_word start,
                                   libafl_word end)
{
    _libafl_sync_exit_call2(LIBAFL_QEMU_COMMAND_VADDR_FILTER_ALLOW, start, end);
}

static int init_afl(void)
{
    vaddr_t xen_text_start = (vaddr_t)_stext;
    vaddr_t xen_text_end = (vaddr_t)_etext;

    lqprintf("Telling AFL about code section: %lx - %lx\n", xen_text_start,
             xen_text_end);

    libafl_qemu_trace_vaddr_range(xen_text_start, xen_text_end);

    return 0;
}

__initcall(init_afl);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

