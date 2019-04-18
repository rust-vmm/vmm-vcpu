// Copyright 2018-2019 CrowdStrike, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub mod vcpu;

#[cfg(unix)]
extern crate kvm_bindings;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86_64;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
mod arm;
