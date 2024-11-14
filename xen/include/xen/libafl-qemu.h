/* SPDX-License-Identifier: MIT */
#ifndef __XEN_LIBAFL_QEMU_H
#define __XEN_LIBAFL_QEMU_H

#include <xen/stdint.h>
#define LIBAFL_QEMU_PRINTF_MAX_SIZE 4096

#define LIBAFL_STRINGIFY(s) #s
#define XSTRINGIFY(s) LIBAFL_STRINGIFY(s)

#define LIBAFL_SYNC_EXIT_OPCODE 0x66f23a0f

typedef enum LibaflQemuCommand
{
  LIBAFL_QEMU_COMMAND_START_VIRT = 0,
  LIBAFL_QEMU_COMMAND_START_PHYS = 1,
  LIBAFL_QEMU_COMMAND_INPUT_VIRT = 2,
  LIBAFL_QEMU_COMMAND_INPUT_PHYS = 3,
  LIBAFL_QEMU_COMMAND_END = 4,
  LIBAFL_QEMU_COMMAND_SAVE = 5,
  LIBAFL_QEMU_COMMAND_LOAD = 6,
  LIBAFL_QEMU_COMMAND_VERSION = 7,
  LIBAFL_QEMU_COMMAND_VADDR_FILTER_ALLOW = 8,
  LIBAFL_QEMU_COMMAND_INTERNAL_ERROR = 9,
  LIBAFL_QEMU_COMMAND_LQPRINTF = 10,
  LIBAFL_QEMU_COMMAND_TEST = 11,
} LibaflExit;

typedef uint64_t libafl_word;

/**
 * LibAFL QEMU header file.
 *
 * This file is a portable header file used to build target harnesses more
 * conveniently. Its main purpose is to generate ready-to-use calls to
 * communicate with the fuzzer. The list of commands is available at the bottom
 * of this file. The rest mostly consists of macros generating the code used by
 * the commands.
 */

enum LibaflQemuEndStatus
{
  LIBAFL_QEMU_END_UNKNOWN = 0,
  LIBAFL_QEMU_END_OK = 1,
  LIBAFL_QEMU_END_CRASH = 2,
};

void libafl_qemu_end(enum LibaflQemuEndStatus status);

void libafl_qemu_internal_error(void);

void __attribute__((format(printf, 1, 2))) lqprintf(const char *fmt, ...);

void libafl_qemu_trace_vaddr_range(libafl_word start, libafl_word end);

static always_inline void libafl_qemu_success_on_block(void)
{
#ifdef CONFIG_LIBAFL_QEMU_FUZZER_PASS_BLOCKING
    libafl_qemu_end(LIBAFL_QEMU_END_OK);
#endif
}

#endif
