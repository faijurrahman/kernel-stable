#!/bin/bash

${HOME}/fuzzer/qemu/build/qemu-system-aarch64 \
  -machine virt \
  -cpu cortex-a57 \
  -nographic -smp 1 \
  -hda ${HOME}/fuzzer/buildroot/output/images/rootfs.ext3 \
  -kernel ${HOME}/fuzzer/kernel-stable/arch/arm64/boot/Image \
  -append "console=ttyAMA0 root=/dev/vda oops=panic panic_on_warn=1 panic=-1 ftrace_dump_on_oops=orig_cpu debug earlyprintk=serial slub_debug=UZ" \
  -m 2048 \
  -net user,hostfwd=tcp::10023-:22 -net nic
