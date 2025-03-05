#!/bin/bash

#/home/faijur/syzkaller/kernel-stable/scripts/kconfig/merge_config.sh -m /home/faijur/syzkaller/kernel-stable/arch/arm64/configs/defconfig /home/faijur/syzkaller/kernel-stable/mywork/config/syzkaller.extra.defconfig

ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- make defconfig
cat /home/faijur/syzkaller/kernel-stable/mywork/config/syzkaller.extra.defconfig >> /home/faijur/syzkaller/kernel-stable/.config
ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- make olddefconfig
