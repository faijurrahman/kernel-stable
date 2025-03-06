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
# Kernel Build Environment
#-----------------------------------------------------------------------
