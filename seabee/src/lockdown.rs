// SPDX-License-Identifier: Apache-2.0
use std::collections::HashSet;

use anyhow::Result;
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

use crate::config::Config;

pub fn lockdown_seabee(config: &Config, prog_filter: &mut HashSet<String>) {
    // if forking is allowed or a seccomp filter is created
    // then do not load 'seabee_task_alloc'
    if config.test || add_seccomp_filter().is_ok() {
        prog_filter.insert(String::from("seabee_task_alloc"));
    }
}

/// Attempts to add a syscall filter using seccomp to prevent any syscall
/// that could copy the BPF file descriptors from running or change the
/// execution of the userspace.
///
/// In addition, we prevent the `prctl` and `seccomp` syscalls to prevent
/// further manipulation to the userspace
///
/// See `man 2 seccomp` for more information
fn add_seccomp_filter() -> Result<()> {
    let filter = SeccompFilter::new(
        vec![
            (libc::SYS_clone, vec![]),
            (libc::SYS_clone3, vec![]),
            (libc::SYS_execve, vec![]),
            (libc::SYS_execveat, vec![]),
            //(libc::SYS_fork, vec![]),
            (libc::SYS_prctl, vec![]),
            (libc::SYS_seccomp, vec![]),
            //(libc::SYS_vfork, vec![]),
        ]
        .into_iter()
        .collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        std::env::consts::ARCH.try_into()?,
    )?;
    let seccomp_prog: BpfProgram = filter.try_into()?;
    seccompiler::apply_filter_all_threads(&seccomp_prog)?;
    Ok(())
}
