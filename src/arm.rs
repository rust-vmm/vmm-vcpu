// Copyright 2018-2019 CrowdStrike, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// ARM-specific data structures.

///
/// Type of CPU to present to the guest, and the optional features it should have.
///
#[cfg(windows)]
pub struct VcpuInit {
    pub target: u32,
    pub features: [u32; 7usize],
}

#[cfg(unix)]
pub use kvm_bindings::kvm_vcpu_init as VcpuInit;
