/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef XEN__FUZZER_H
#define XEN__FUZZER_H

#include <xen/compiler.h>

#ifdef CONFIG_FUZZER_LIBAFL_QEMU
#include <xen/libafl-qemu.h>
#endif

/* Unconditional failure */
static always_inline void fuzzer_crash(void)
{
#ifdef CONFIG_FUZZER_LIBAFL_QEMU
    libafl_qemu_end(LIBAFL_QEMU_END_CRASH);
#endif
}

/* Unconditional success */
static always_inline void fuzzer_success(void)
{
#ifdef CONFIG_FUZZER_LIBAFL_QEMU
    libafl_qemu_end(LIBAFL_QEMU_END_OK);
#endif
}

/*
 * Conditional success
 *
 * Sometimes a fuzzer might make Xen to do something that prevents
 * from returning to the caller: reboot or turn off the machine, block
 * calling vCPU, crash a domain, etc. Depending on fuzzing goal this
 * may be a valid behavior, but as control is not returned to the
 * fuzzing harness, it can't tell the fuzzer about success, so we need
 * to do this ourselves.
 */
static always_inline void fuzzer_on_block(void)
{
#ifdef CONFIG_FUZZER_PASS_BLOCKING
    fuzzer_success();
#endif
}

#endif
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
