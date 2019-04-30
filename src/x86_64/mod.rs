// Copyright 2018-2019 CrowdStrike, Inc.
// SPDX-License-Identifier: Apache-2.0 OR MIT

/// Windows definitions of data structures
#[cfg(windows)]
pub mod windows;

use std::mem::size_of;

///
/// Export generically-named explicitly-defined structures for Windows platforms
///
#[cfg(windows)]
pub use {
    self::windows::StandardRegisters,
    self::windows::SpecialRegisters,
    self::windows::FpuState,
    self::windows::MsrEntries,
    self::windows::MsrEntry,
    self::windows::SegmentRegister,
    self::windows::DescriptorTable,
    self::windows::CpuId2,
    self::windows::CpuIdEntry2,
    self::windows::LapicState,
    };

///
/// Export generically-named wrappers of kvm-bindings for Unix-based platforms
/// 
#[cfg(unix)]
pub use {
    kvm_bindings::kvm_regs as StandardRegisters,
    kvm_bindings::kvm_sregs as SpecialRegisters,
    kvm_bindings::kvm_msr_entry as MsrEntry,
    kvm_bindings::kvm_msrs as MsrEntries,
    kvm_bindings::kvm_segment as SegmentRegister,
    kvm_bindings::kvm_dtable as DescriptorTable,
    kvm_bindings::kvm_fpu as FpuState,
    kvm_bindings::kvm_cpuid_entry2 as CpuIdEntry2,
    kvm_bindings::kvm_cpuid2 as CpuId2,
    kvm_bindings::kvm_lapic_state as LapicState,
    };

/// Returns a `Vec<T>` with a size in bytes at least as large as `size_in_bytes`.
fn vec_with_size_in_bytes<T: Default>(size_in_bytes: usize) -> Vec<T> {
    let rounded_size = (size_in_bytes + size_of::<T>() - 1) / size_of::<T>();
    let mut v = Vec::with_capacity(rounded_size);
    for _ in 0..rounded_size {
        v.push(T::default())
    }
    v
}

/// The kvm API has many structs that resemble the following `Foo` structure:
///
/// ```
/// #[repr(C)]
/// struct Foo {
///    some_data: u32
///    entries: __IncompleteArrayField<__u32>,
/// }
/// ```
///
/// In order to allocate such a structure, `size_of::<Foo>()` would be too small because it would not
/// include any space for `entries`. To make the allocation large enough while still being aligned
/// for `Foo`, a `Vec<Foo>` is created. Only the first element of `Vec<Foo>` would actually be used
/// as a `Foo`. The remaining memory in the `Vec<Foo>` is for `entries`, which must be contiguous
/// with `Foo`. This function is used to make the `Vec<Foo>` with enough space for `count` entries.
pub fn vec_with_array_field<T: Default, F>(count: usize) -> Vec<T> {
    let element_space = count * size_of::<F>();
    let vec_size_bytes = size_of::<T>() + element_space;
    vec_with_size_in_bytes(vec_size_bytes)
}

/// Maximum number of CPUID entries that can be returned by a call to KVM ioctls.
///
/// This value is taken from Linux Kernel v4.14.13 (arch/x86/include/asm/kvm_host.h).
/// It can be used for calls to [get_supported_cpuid](struct.Kvm.html#method.get_supported_cpuid) and
/// [get_emulated_cpuid](struct.Kvm.html#method.get_emulated_cpuid).
pub const MAX_CPUID_ENTRIES: usize = 80;

/// Wrapper over the `CpuId2` structure.
///
/// The structure has a zero length array at the end, hidden behind bounds check.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub struct CpuId {
    /// Wrapper over `CpuId2` from which we only use the first element.
    pub cpuid_vec: Vec<CpuId2>,
    /// Number of `CpuIdEntry2` structs at the end of CpuId2.
    pub allocated_len: usize,
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl Clone for CpuId {
    fn clone(&self) -> Self {
        let mut cpuid_vec = Vec::with_capacity(self.cpuid_vec.len());
        for _ in 0..self.cpuid_vec.len() {
            cpuid_vec.push(CpuId2::default());
        }

        let num_bytes = self.cpuid_vec.len() * size_of::<CpuId2>();

        let src_byte_slice =
            unsafe { std::slice::from_raw_parts(self.cpuid_vec.as_ptr() as *const u8, num_bytes) };

        let dst_byte_slice =
            unsafe { std::slice::from_raw_parts_mut(cpuid_vec.as_mut_ptr() as *mut u8, num_bytes) };

        dst_byte_slice.copy_from_slice(src_byte_slice);

        CpuId {
            cpuid_vec,
            allocated_len: self.allocated_len,
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl PartialEq for CpuId {
    fn eq(&self, other: &CpuId) -> bool {
        let entries: &[CpuIdEntry2] =
            unsafe { self.cpuid_vec[0].entries.as_slice(self.allocated_len) };
        let other_entries: &[CpuIdEntry2] =
            unsafe { self.cpuid_vec[0].entries.as_slice(other.allocated_len) };
        self.allocated_len == other.allocated_len && entries == other_entries
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl CpuId {
    /// Creates a new `CpuId` structure that contains at most `array_len` CPUID entries.
    ///
    /// # Arguments
    ///
    /// * `array_len` - Maximum number of CPUID entries.
    ///
    /// # Example
    ///
    /// ```
    /// use vmm_vcpu::x86_64::CpuId;
    /// let cpu_id = CpuId::new(32);
    /// ```
    pub fn new(array_len: usize) -> CpuId {
        let mut cpuid_vec = vec_with_array_field::<CpuId2, CpuIdEntry2>(array_len);
        cpuid_vec[0].nent = array_len as u32;

        CpuId {
            cpuid_vec,
            allocated_len: array_len,
        }
    }

    /// Creates a new `CpuId` structure based on a supplied vector of `CpuIdEntry2`.
    ///
    /// # Arguments
    ///
    /// * `entries` - The vector of `CpuIdEntry2` entries.
    ///
    /// # Example
    ///
    /// ```rust
    /// # extern crate vmm_vcpu;
    ///
    /// use vmm_vcpu::x86_64::CpuIdEntry2;
    /// use vmm_vcpu::x86_64::CpuId;
    /// // Create a Cpuid to hold one entry.
    /// let mut cpuid = CpuId::new(1);
    /// let mut entries = cpuid.mut_entries_slice().to_vec();
    /// let new_entry = CpuIdEntry2 {
    ///     function: 0x4,
    ///     index: 0,
    ///     flags: 1,
    ///     eax: 0b1100000,
    ///     ebx: 0,
    ///     ecx: 0,
    ///     edx: 0,
    ///     padding: [0, 0, 0],
    /// };
    /// entries.insert(0, new_entry);
    /// cpuid = CpuId::from_entries(&entries);
    /// ```
    ///
    pub fn from_entries(entries: &[CpuIdEntry2]) -> CpuId {
        let mut cpuid_vec = vec_with_array_field::<CpuId2, CpuIdEntry2>(entries.len());
        cpuid_vec[0].nent = entries.len() as u32;

        unsafe {
            cpuid_vec[0]
                .entries
                .as_mut_slice(entries.len())
                .copy_from_slice(entries);
        }

        CpuId {
            cpuid_vec,
            allocated_len: entries.len(),
        }
    }

    /// Returns the mutable entries slice so they can be modified before passing to the VCPU.
    ///
    /// ```cfg(unix)
    /// extern crate kvm_ioctls;
    /// 
    /// use kvm_ioctls::Kvm;
    /// use vmm_vcpu::x86_64::{CpuId, MAX_CPUID_ENTRIES};
    /// 
    /// # fn main() {
    ///     let kvm = Kvm::new().unwrap();
    ///     let mut cpuid = kvm.get_supported_cpuid(MAX_CPUID_ENTRIES).unwrap();
    ///     let cpuid_entries = cpuid.mut_entries_slice();
    /// # }
    /// 
    /// ```
    ///
    pub fn mut_entries_slice(&mut self) -> &mut [CpuIdEntry2] {
        // Mapping the unsized array to a slice is unsafe because the length isn't known.  Using
        // the length we originally allocated with eliminates the possibility of overflow.
        if self.cpuid_vec[0].nent as usize > self.allocated_len {
            self.cpuid_vec[0].nent = self.allocated_len as u32;
        }
        let nent = self.cpuid_vec[0].nent as usize;
        unsafe { self.cpuid_vec[0].entries.as_mut_slice(nent) }
    }

    /// Get a  pointer so it can be passed to the kernel. Using this pointer is unsafe.
    ///
    pub fn as_ptr(&self) -> *const CpuId2 {
        &self.cpuid_vec[0]
    }

    /// Get a mutable pointer so it can be passed to the kernel. Using this pointer is unsafe.
    ///
    pub fn as_mut_ptr(&mut self) -> *mut CpuId2 {
        &mut self.cpuid_vec[0]
    }
}
