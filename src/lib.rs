// Copyright 2018-2019 CrowdStrike, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(unused)]
#![deny(missing_docs)]

//! A generic abstraction around virtual CPU (vCPU) functionality
//!
//! This crate offers a trait abstraction for vCPUs, as well as architecture
//! and platform-dependent structure definitions necessary for vCPU functions.
//!
//! # Platform support
//!
//! - x86_64
//! - arm64 (experimental)
//!

/// Module defining vCPU trait and required data structures
pub mod vcpu;

#[cfg(unix)]
extern crate kvm_bindings;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
/// Module defining x86_64 architecture-dependent structures
pub mod x86_64;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
/// Module defining arm architecture-dependent structures
pub mod arm;
