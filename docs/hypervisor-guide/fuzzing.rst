.. SPDX-License-Identifier: CC-BY-4.0

Fuzzing
=======

It is possible to use LibAFL-QEMU for fuzzing hypervisor. Right now
only aarch64 is supported and only hypercall fuzzing is enabled in the
test harness, but there are plans to add vGIC interface fuzzing, PSCI
fuzzing and vPL011 fuzzing as well.


Principle of operation
----------------------

LibAFL-QEMU is a part of American Fuzzy lop plus plus (AKA AFL++)
project. It uses special build of QEMU, that allows to fuzz baremetal
software like Xen hypervisor or Linux kernel. Basic idea is that we
have software under test (Xen hypervisor in our case) and a test
harness application. Test harness uses special protocol to communicate
with LibAFL outside of QEMU to get input data and report test
result. LibAFL monitors which branches are taken by Xen and mutates
input data in attempt to discover new code paths that eventually can
lead to a crash or other unintended behavior.

LibAFL uses QEMU's `snapshot` feature to run multiple test without
restarting the whole system every time. This speeds up fuzzing process
greatly.

So, to try Xen fuzzing we need three components: LibAFL-based fuzzer,
test harness and Xen itself.

Building Xen for fuzzing with LibAFL-QEMU
-----------------------------------------

Xen hypervisor should be built with these three options::

  CONFIG_FUZZING=y
  CONFIG_FUZZER_LIBAFL_QEMU=y
  CONFIG_FUZZER_PASS_BLOCKING=y

Building LibAFL-QEMU based fuzzer
---------------------------------

Fuzzer is written in Rust, so you need Rust toolchain and `cargo` tool
in your system. Please refer to your distro documentation on how to
obtain them.

Once Rust is ready, fetch and build the fuzzer::

  # git clone https://github.com/xen-troops/xen-fuzzer-rs
  # cd xen-fuzzer-rs
  # cargo build

Building test harness
---------------------

We need to make low-level actions, like issuing random hypercalls, so
for test harness we use special build of XTF (Xen Testing Framework).
You can build XTF manually, or let fuzzer to do this::

  # cargo make build_xtf

This fill download and build XTF for ARM.

Running the fuzzer
------------------

Please refer to README.md that comes with the fuzzer, but the most
versatile way is to run it like this::

  # target/debug/xen_fuzzer -t 3600 /path/to/xen \
      target/xtf/tests/arm-vgic-fuzzer/test-mmu64le-arm-vgic-fuzzer

(assuming that you built XTF with `cargo make build_xtf`)

Any inputs that led to crashes will be found in `crashes` directory.

You can replay a crash with `-r` option::

  # target/debug/xen_fuzzer -r crashes/0195e4fc65828c17 run \
      /path/to/xen \
      /path/to/harness


Fuzzer will return non-zero error code if it encountered any crashes.

TODOs
-----

 - Add x86 support.
 - Implement fuzzing of other external hypervisor interfaces.
