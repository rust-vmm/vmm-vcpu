// Copyright 2018-2019 CrowdStrike, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Cloudbase Solutions Srl
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::mem::size_of;

///
/// Use kvm_bindings behind the scenes as these are architectural structures and
/// not actually KVM-dependent, but export as generically-named data
/// structures to be consumed by any VMM's vCPU implementation
///

/// Single MSR to be read/written
///
/// pub struct kvm_msr_entry {
///     pub index: __u32,
///     pub reserved: __u32,
///     pub data: __u64,
/// }
pub use kvm_bindings::kvm_msr_entry as MsrEntry;

/// Array of MSR entries
///
///
/// pub struct kvm_msrs {
///     pub nmsrs: __u32,
///     pub pad: __u32,
///     pub entries: __IncompleteArrayField<kvm_msr_entry>,
/// }
pub use kvm_bindings::kvm_msrs as MsrEntries;

/// Standard registers (general purpose plus instruction pointer and flags)
///
/// pub struct kvm_regs {
///    pub rax: __u64,
///    pub rbx: __u64,
///    pub rcx: __u64,
///    pub rdx: __u64,
///    pub rsi: __u64,
///    pub rdi: __u64,
///    pub rsp: __u64,
///    pub rbp: __u64,
///    pub r8: __u64,
///    pub r9: __u64,
///    pub r10: __u64,
///    pub r11: __u64,
///    pub r12: __u64,
///    pub r13: __u64,
///    pub r14: __u64,
///    pub r15: __u64,
///    pub rip: __u64,
///    pub rflags: __u64,
/// }
pub use kvm_bindings::kvm_regs as StandardRegisters;

/// Special registers (segment, task, descriptor table, control, and additional
/// registers, plus the interrupt bitmap)
///
/// pub struct kvm_sregs {
///    pub cs: kvm_segment,
///    pub ds: kvm_segment,
///    pub es: kvm_segment,
///    pub fs: kvm_segment,
///    pub gs: kvm_segment,
///    pub ss: kvm_segment,
///    pub tr: kvm_segment,
///    pub ldt: kvm_segment,
///    pub gdt: kvm_dtable,
///    pub idt: kvm_dtable,
///    pub cr0: __u64,
///    pub cr2: __u64,
///    pub cr3: __u64,
///    pub cr4: __u64,
///    pub cr8: __u64,
///    pub efer: __u64,
///    pub apic_base: __u64,
///    pub interrupt_bitmap: [__u64; 4usize],
/// }
pub use kvm_bindings::kvm_sregs as SpecialRegisters;

/// Segment register (used for CS, DS, ES, FS, GS, SS)
///
/// pub struct kvm_segment {
///    pub base: __u64,
///    pub limit: __u32,
///    pub selector: __u16,
///    pub type_: __u8,
///    pub present: __u8,
///    pub dpl: __u8,
///    pub db: __u8,
///    pub s: __u8,
///    pub l: __u8,
///    pub g: __u8,
///    pub avl: __u8,
///    pub unusable: __u8,
///    pub padding: __u8,
/// }
pub use kvm_bindings::kvm_segment as SegmentRegister;

/// Descriptor Table
///
/// pub struct kvm_dtable {
///     pub base: __u64,
///     pub limit: __u16,
///     pub padding: [__u16; 3usize],
/// }
pub use kvm_bindings::kvm_dtable as DescriptorTable;

/// Floating Pointe Unit State
///
/// pub struct kvm_fpu {
///    pub fpr: [[__u8; 16usize]; 8usize],
///    pub fcw: __u16,
///    pub fsw: __u16,
///    pub ftwx: __u8,
///    pub pad1: __u8,
///    pub last_opcode: __u16,
///    pub last_ip: __u64,
///    pub last_dp: __u64,
///    pub xmm: [[__u8; 16usize]; 16usize],
///    pub mxcsr: __u32,
///    pub pad2: __u32,
/// }
pub use kvm_bindings::kvm_fpu as FpuState;

/// Entry describing a CPUID feature/leaf. Features can be set as responses to
/// the CPUID instruction.
/// pub struct kvm_cpuid_entry2 {
///    pub function: __u32,
///    pub index: __u32,
///    pub flags: __u32,
///    pub eax: __u32,
///    pub ebx: __u32,
///    pub ecx: __u32,
///    pub edx: __u32,
///    pub padding: [__u32; 3usize],
/// }
use kvm_bindings::kvm_cpuid_entry2 as CpuIdEntry2;

/// Array of CpuId2 entries, each of which describing a feature/leaf to be set
/// pub struct kvm_cpuid2 {
///    pub nent: __u32,
///    pub padding: __u32,
///    pub entries: __IncompleteArrayField<kvm_cpuid_entry2>,
/// }
use kvm_bindings::kvm_cpuid2 as CpuId2;

/// Unix definition of the LAPIC state, the set of memory mapped registers that
/// describe the Local APIC. Unix-based VMMs only require 1KB of memory to
/// describe the LAPIC state.
///
/// pub struct kvm_lapic_state {
///    pub regs: [::std::os::raw::c_char; 1024usize],
/// }
#[cfg(unix)]
pub use kvm_bindings::kvm_lapic_state as LapicState;

/// Windows definition of the LAPIC state, the set of memory mapped registers
/// that describe the Local APIC. Windows-based VMMs require 4KB of memory to
/// describe the LAPIC state, or the Windows APIs will fail, even though the
/// architecture-specified space requirement is only 1KB.
#[cfg(windows)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct LapicState {
    pub regs: [::std::os::raw::c_char; 4096usize],
}

#[cfg(windows)]
impl Default for LapicState {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

#[cfg(windows)]
impl ::std::fmt::Debug for LapicState {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        self.regs[..].fmt(fmt)
    }
}

#[test]
fn vcpu_test_layout_lapic_state() {
    assert_eq!(
        ::std::mem::size_of::<LapicState>(),
        1024usize,
        concat!("Size of: ", stringify!(LapicState))
    );
    assert_eq!(
        ::std::mem::align_of::<LapicState>(),
        1usize,
        concat!("Alignment of ", stringify!(LapicState))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<LapicState>())).regs as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(LapicState),
            "::",
            stringify!(regs)
        )
    );
}

// Returns a `Vec<T>` with a size in bytes at least as large as `size_in_bytes`.
fn vec_with_size_in_bytes<T: Default>(size_in_bytes: usize) -> Vec<T> {
    let rounded_size = (size_in_bytes + size_of::<T>() - 1) / size_of::<T>();
    let mut v = Vec::with_capacity(rounded_size);
    for _ in 0..rounded_size {
        v.push(T::default())
    }
    v
}

// The kvm API has many structs that resemble the following `Foo` structure:
//
// ```
// #[repr(C)]
// struct Foo {
//    some_data: u32
//    entries: __IncompleteArrayField<__u32>,
// }
// ```
//
// In order to allocate such a structure, `size_of::<Foo>()` would be too small because it would not
// include any space for `entries`. To make the allocation large enough while still being aligned
// for `Foo`, a `Vec<Foo>` is created. Only the first element of `Vec<Foo>` would actually be used
// as a `Foo`. The remaining memory in the `Vec<Foo>` is for `entries`, which must be contiguous
// with `Foo`. This function is used to make the `Vec<Foo>` with enough space for `count` entries.
fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * size_of::<F>();
    let vec_size_bytes = size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
}

/// Wrapper for `CpuId2` which has a zero length array at the end.
/// Hides the zero length array behind a bounds check.
pub struct CpuId {
    /// Wrapper over `CpuId2` from which we only use the first element.
    kvm_cpuid: Vec<CpuId2>,
    // Number of `CpuIdEntry2` structs at the end of CpuId2.
    allocated_len: usize,
}

impl Clone for CpuId {
    fn clone(&self) -> Self {
        let mut kvm_cpuid = Vec::with_capacity(self.kvm_cpuid.len());
        for _ in 0..self.kvm_cpuid.len() {
            kvm_cpuid.push(CpuId2::default());
        }

        let num_bytes = self.kvm_cpuid.len() * size_of::<CpuId2>();

        let src_byte_slice =
            unsafe { std::slice::from_raw_parts(self.kvm_cpuid.as_ptr() as *const u8, num_bytes) };

        let dst_byte_slice =
            unsafe { std::slice::from_raw_parts_mut(kvm_cpuid.as_mut_ptr() as *mut u8, num_bytes) };

        dst_byte_slice.copy_from_slice(src_byte_slice);

        CpuId {
            kvm_cpuid,
            allocated_len: self.allocated_len,
        }
    }
}

#[cfg(test)]
impl PartialEq for CpuId {
    fn eq(&self, other: &CpuId) -> bool {
        let entries: &[CpuIdEntry2] =
            unsafe { self.kvm_cpuid[0].entries.as_slice(self.allocated_len) };
        let other_entries: &[CpuIdEntry2] =
            unsafe { self.kvm_cpuid[0].entries.as_slice(other.allocated_len) };
        self.allocated_len == other.allocated_len && entries == other_entries
    }
}

impl CpuId {
    /// Creates a new `CpuId` structure that can contain at most `array_len` KVM CPUID entries.
    ///
    /// # Arguments
    ///
    /// * `array_len` - Maximum number of CPUID entries.
    ///
    pub fn new(array_len: usize) -> CpuId {
        let mut kvm_cpuid = vec_with_array_field::<CpuId2, CpuIdEntry2>(array_len);
        kvm_cpuid[0].nent = array_len as u32;

        CpuId {
            kvm_cpuid,
            allocated_len: array_len,
        }
    }

    /// Get the mutable entries slice so they can be modified before passing to the VCPU.
    ///
    pub fn mut_entries_slice(&mut self) -> &mut [CpuIdEntry2] {
        // Mapping the unsized array to a slice is unsafe because the length isn't known.  Using
        // the length we originally allocated with eliminates the possibility of overflow.
        if self.kvm_cpuid[0].nent as usize > self.allocated_len {
            self.kvm_cpuid[0].nent = self.allocated_len as u32;
        }
        let nent = self.kvm_cpuid[0].nent as usize;
        unsafe { self.kvm_cpuid[0].entries.as_mut_slice(nent) }
    }

    /// Get a  pointer so it can be passed to the kernel. Using this pointer is unsafe.
    ///
    pub fn as_ptr(&self) -> *const CpuId2 {
        &self.kvm_cpuid[0]
    }

    /// Get a mutable pointer so it can be passed to the kernel. Using this pointer is unsafe.
    ///
    pub fn as_mut_ptr(&mut self) -> *mut CpuId2 {
        &mut self.kvm_cpuid[0]
    }
}
