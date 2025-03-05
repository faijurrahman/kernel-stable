#!/bin/bash

#-----------------------------------------------------------------------
# Setup Source Code
#-----------------------------------------------------------------------
git clone https://github.com/gregkh/linux.git kernel-stable
cd kernel-stable

#git remote add origin https://github.com/gregkh/linux.git
#git branch --set-upstream-to=origin/master master

git branch -vv
git remote -vv

git remote add upstream https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
git remote add cros https://chromium.googlesource.com/chromiumos/third_party/kernel
git remote add dev git@github.com:faijurrahman/kernel-stable.git

git branch -vv
git remote -vv


#-----------------------------------------------------------------------
# Build Qemu for Syzkaller
#-----------------------------------------------------------------------
# Details doc here:
# https://github.com/faijurrahman/syzkaller/blob/master/docs/linux/setup_linux-host_qemu-vm_arm64-kernel.md


# Get the ARM64 toolchain from Linaro:
# You will require an ARM64 kernel with gcc plugin support. If not, obtain 
# the ARM64 toolchain from Linaro. Get gcc-linaro-6.1.1-2016.08-x86_64_aarch64-linux-gnu.tar.xz 
# from here. Extract and add its bin/ to your PATH. If you have another ARM64 
# toolchain on your machine, ensure that this newly downloaded toolchain takes precedence.

# Compile the kernel:
# Get the source code of the Linux kernel version you want to fuzz, and do the following.

$ ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- make defconfig
$ nano .config

# Change the following options :
#    CONFIG_KCOV=y
#    CONFIG_KASAN=y
#    CONFIG_DEBUG_INFO=y
#    CONFIG_CMDLINE="console=ttyAMA0"
#    CONFIG_KCOV_INSTRUMENT_ALL=y
#    CONFIG_DEBUG_FS=y
#    CONFIG_NET_9P=y
#    CONFIG_NET_9P_VIRTIO=y
#    CONFIG_CROSS_COMPILE="aarch64-linux-gnu-"
    
$ ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- make -j40

# If the build was successful, you should have a arch/arm64/boot/Image file.
