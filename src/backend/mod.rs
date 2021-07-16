// Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//! This module defines the data structures used for the intermmediate representation (IR),
//! as well as the logic for compiling the filter into BPF code, the final form of the filter.

use core::fmt::Formatter;
use std::convert::TryFrom;
use std::fmt::Display;

/// Backend Result type.
pub type Result<T> = std::result::Result<T, Error>;

/// Backend-related errors.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Invalid TargetArch.
    InvalidTargetArch(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        use self::Error::*;

        match self {
            InvalidTargetArch(arch) => write!(f, "Invalid target arch: {}.", arch.to_string()),
        }
    }
}

/// Supported target architectures.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TargetArch {
    /// x86_64 arch
    x86_64,
    /// aarch64 arch
    aarch64,
}

impl TryFrom<&str> for TargetArch {
    type Error = Error;
    fn try_from(input: &str) -> Result<Self> {
        match input.to_lowercase().as_str() {
            "x86_64" => Ok(TargetArch::x86_64),
            "aarch64" => Ok(TargetArch::aarch64),
            _ => Err(Error::InvalidTargetArch(input.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_arch() {
        assert!(TargetArch::try_from("invalid").is_err());
        assert!(TargetArch::try_from("x8664").is_err());

        assert_eq!(TargetArch::try_from("x86_64").unwrap(), TargetArch::x86_64);
        assert_eq!(TargetArch::try_from("X86_64").unwrap(), TargetArch::x86_64);

        assert_eq!(
            TargetArch::try_from("aarch64").unwrap(),
            TargetArch::aarch64
        );
        assert_eq!(
            TargetArch::try_from("aARch64").unwrap(),
            TargetArch::aarch64
        );
    }
}
