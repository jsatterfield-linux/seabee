// SPDX-License-Identifier: Apache-2.0
#ifndef SEABEE_VMLINUX_H_
#define SEABEE_VMLINUX_H_
/**
 * @file vmlinux.h
 */

#include <linux/version.h>

// Before 6.1, `LOCKDOWN_REASON_BPF_WRITE_USER` was 16.
// After Linux 6.1, `LOCKDOWN_REASON_DEVICE_TREE` was added as lockdown reason 10,
//   causing `LOCKDOWN_REASON_BPF_WRITE_USER` to be 17.
// #if defined(__aarch64__)
#include "vmlinux_aarch64.h"
// #el
// #if BPF_CODE_VERSION >= KERNEL_VERSION(6, 1, 0)
// #include "vmlinux_6_11_4.h"
// #else
// #include "vmlinux_6_0_18.h"
// #endif

#endif //SEABEE_VMLINUX_H_
