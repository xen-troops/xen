/*
 * xen/arch/arm/arm32/smc.S
 *
 * Wrapper for Secure Monitors Calls
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <asm/macros.h>

/*
 * void call_smccc_smc(register_t a0, register_t a1, register_t a2,
 *                     register_t a3, register_t a4, register_t a5,
 *                     register_t a6, register_t a7, register_t res[4])
 */
ENTRY(call_smccc_smc)
        mov     r12, sp
        push    {r4-r7}
        ldm     r12, {r4-r7}
        smc     #0
        pop     {r4-r7}
        ldr     r12, [sp, #(4 * 4)]
        stm     r12, {r0-r3}
        bx      lr
