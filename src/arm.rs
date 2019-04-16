// Copyright 2018-2019 CrowdStrike, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

///
/// Use kvm_bindings behind the scenes as these are architectural structures and
/// not actually KVM-dependent, but export as generically-named data
/// structures to be consumed by any VMM's vCPU implementation
///

/// Type of CPU to present to the guest, and the optional features it should have.
///
/// pub struct kvm_vcpu_init {
///     pub target: __u32,
///     pub features: [__u32; 7usize],
/// }
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub use kvm_bindings::kvm_vcpu_init as VcpuInit;
