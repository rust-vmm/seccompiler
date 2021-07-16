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

// Re-export the IR public types.
pub use backend::*;
