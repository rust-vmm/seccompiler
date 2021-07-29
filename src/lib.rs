// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
#![deny(missing_docs)]
#![cfg(target_endian = "little")]
//! Provides easy-to-use Linux seccomp-bpf jailing.
//!
//! Seccomp is a Linux kernel security feature which enables a tight control over what kernel-level
//! mechanisms a process has access to. This is typically used to reduce the attack surface and
//! exposed resources when running untrusted code. This works by allowing users to write and set a
//! BPF (Berkeley Packet Filter) program for each process or thread, that intercepts syscalls and
//! decides whether the syscall is safe to execute.
//!
//! Writing BPF programs by hand is difficult and error-prone. This crate provides high-level
//! wrappers for working with system call filtering.

mod backend;

use std::fmt::{Display, Formatter};
use std::io;

// Re-export the IR public types.
pub use backend::{
    sock_filter, BpfProgram, BpfProgramRef, Error as BackendError, SeccompAction, SeccompCmpArgLen,
    SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
};

// BPF structure definition for filter array.
// See /usr/include/linux/filter.h .
#[repr(C)]
struct sock_fprog {
    pub len: ::std::os::raw::c_ushort,
    pub filter: *const sock_filter,
}

/// Library Result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Library errors.
#[derive(Debug)]
pub enum Error {
    /// Error originating in the backend compiler.
    Backend(BackendError),
    /// Attempting to install an empty filter.
    EmptyFilter,
    /// System error related to calling `prctl`.
    Prctl(io::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            Backend(error) => {
                write!(f, "Backend error: {}", error)
            }
            EmptyFilter => {
                write!(f, "Cannot install empty filter.")
            }
            Prctl(errno) => {
                write!(f, "Error calling `prctl`: {}", errno)
            }
        }
    }
}

/// Apply a BPF filter to the calling thread.
pub fn apply_filter(bpf_filter: BpfProgramRef) -> Result<()> {
    // If the program is empty, don't install the filter.
    if bpf_filter.is_empty() {
        return Err(Error::EmptyFilter);
    }

    // Safe because syscall arguments are valid.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(Error::Prctl(io::Error::last_os_error()));
    }

    let bpf_prog = sock_fprog {
        len: bpf_filter.len() as u16,
        filter: bpf_filter.as_ptr(),
    };
    let bpf_prog_ptr = &bpf_prog as *const sock_fprog;

    // Safe because the kernel performs a `copy_from_user` on the filter and leaves the memory
    // untouched. We can therefore use a reference to the BpfProgram, without needing ownership.
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            bpf_prog_ptr,
        )
    };
    if rc != 0 {
        return Err(Error::Prctl(io::Error::last_os_error()));
    }

    Ok(())
}
