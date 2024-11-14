/* SPDX-License-Identifier: MIT */
/*
 * Arch-specific portions of LibAFL-QEMU interface
 */
#ifndef __ASM_ARM_LIBAFL_QEMU_H
#define __ASM_ARM_LIBAFL_QEMU_H

#define LIBAFL_DEFINE_FUNCTIONS(name, opcode)                           \
    libafl_word _libafl_##name##_call0(                                 \
        libafl_word action) {                                           \
        register unsigned long r0 ASM_REG(0) = action;                  \
        __asm__ volatile (                                              \
            ".word " XSTRINGIFY(opcode) "\n"                            \
            : "+r"(r0)                                                  \
            :                                                           \
            : "memory"                                                  \
            );                                                          \
        return r0;                                                      \
    }                                                                   \
                                                                        \
    libafl_word _libafl_##name##_call1(                                 \
        libafl_word action, libafl_word arg1) {                         \
        register unsigned long r0 ASM_REG(0) = action;                  \
        register unsigned long r1 ASM_REG(1) = arg1;                    \
        __asm__ volatile (                                              \
            ".word " XSTRINGIFY(opcode) "\n"                            \
            : "+r"(r0)                                                  \
            : "r"(r1)                                                   \
            : "memory"                                                  \
            );                                                          \
        return r0;                                                      \
    }                                                                   \
                                                                        \
    libafl_word _libafl_##name##_call2(                                 \
        libafl_word action, libafl_word arg1, libafl_word arg2) {       \
        register unsigned long r0 ASM_REG(0) = action;                  \
        register unsigned long r1 ASM_REG(1) = arg1;                    \
        register unsigned long r2 ASM_REG(2) = arg2;                    \
        __asm__ volatile (                                              \
            ".word " XSTRINGIFY(opcode) "\n"                            \
            : "+r"(r0)                                                  \
            : "r"(r1), "r"(r2)                                          \
            : "memory"                                                  \
            );                                                          \
        return r0;                                                      \
    }

#endif
