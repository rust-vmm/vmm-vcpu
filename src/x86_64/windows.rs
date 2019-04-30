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

///
/// Standard registers (general purpose plus instruction pointer and flags)
///
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct StandardRegisters {
    /// RAX general purpose register
    pub rax: u64,
    /// RBX general purpose register
    pub rbx: u64,
    /// RCX general purpose register
    pub rcx: u64,
    /// RDX general purpose register
    pub rdx: u64,
    /// Source index general purpose register
    pub rsi: u64,
    /// Destination index general purpose register
    pub rdi: u64,
    /// Stack Pointer register
    pub rsp: u64,
    /// Base Pointer register
    pub rbp: u64,
    /// R8 general purpose register
    pub r8: u64,
    /// R9 general purpose register
    pub r9: u64,
    /// R10 general purpose register
    pub r10: u64,
    /// R11 general purpose register
    pub r11: u64,
    /// R12 general purpose register
    pub r12: u64,
    /// R13 general purpose register
    pub r13: u64,
    /// R14 general purpose register
    pub r14: u64,
    /// R15 general purpose register
    pub r15: u64,
    /// Instruction Pointer register
    pub rip: u64,
    /// RFLAGS register
    pub rflags: u64,
}

///
/// Special registers (segment, task, descriptor table, control, and additional
/// registers, plus the interrupt bitmap)
///
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct SpecialRegisters {
    /// Code Segment register
    pub cs: SegmentRegister,
    /// Data Segment register
    pub ds: SegmentRegister,
    /// Extra Segment register
    pub es: SegmentRegister,
    /// Additional segment register
    pub fs: SegmentRegister,
    /// Additional segment register
    pub gs: SegmentRegister,
    /// Stack Segment register
    pub ss: SegmentRegister,
    /// Task register
    pub tr: SegmentRegister,
    /// Local Descriptor Table register
    pub ldt: SegmentRegister,
    /// Global Descriptor Table register
    pub gdt: DescriptorTable,
    /// Interrupt Descriptor Table register
    pub idt: DescriptorTable,
    /// Control Register 0
    pub cr0: u64,
    /// Control Register 2
    pub cr2: u64,
    /// Control Register 3
    pub cr3: u64,
    /// Control Register 4
    pub cr4: u64,
    /// Control Register 8
    pub cr8: u64,
    /// Extended Feature Enable register
    pub efer: u64,
    /// APIC base register
    pub apic_base: u64,
    /// Bitmap of external interrupts (unused)
    pub interrupt_bitmap: [u64; 4usize],
}

///
/// Segment register (used for CS, DS, ES, FS, GS, SS)
///
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct SegmentRegister {
    /// Starting memory address of the segment
    pub base: u64,
    /// Length of the segment
    pub limit: u32,
    /// Offset of a descriptor table entry
    pub selector: u16,
    /// Segment type
    pub type_: u8,
    /// Present
    pub present: u8,
    /// Descriptor privilege level
    pub dpl: u8,
    /// Default (set to 0 when Long set)
    pub db: u8,
    /// System-segment field
    pub s: u8,
    /// Long field
    pub l: u8,
    /// Granularity field
    pub g: u8,
    /// Available
    pub avl: u8,
    /// Unused
    pub unusable: u8,
    /// Padding
    pub padding: u8,
}

///
/// Descriptor Table
///
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct DescriptorTable {
    /// Base address
    pub base: u64,
    /// Limit (size of table in bytes)
    pub limit: u16,
    /// Padding
    pub padding: [u16; 3usize],
}

///
/// Floating Point Unit State
///
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct FpuState {
    /// Floating point registers
    pub fpr: [[u8; 16usize]; 8usize],
    /// Floating Point Control register
    pub fcw: u16,
    /// Floating Point Status register
    pub fsw: u16,
    /// Floating Point Tag register
    pub ftwx: u8,
    /// Padding
    pub pad1: u8,
    /// Floating point exception state - last opcode
    pub last_opcode: u16,
    /// Floating point exception state - last instruction pointer
    pub last_ip: u64,
    /// Floating point exception state - last data pointer
    pub last_dp: u64,
    /// SSE registers
    pub xmm: [[u8; 16usize]; 16usize],
    /// Media control and status register
    pub mxcsr: u32,
    /// Padding
    pub pad2: u32,
}

///
/// Single MSR to be read/written
///
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct MsrEntry {
    /// MSR address index
    pub index: u32,
    /// Reserved
    pub reserved: u32,
    /// MSR data
    pub data: u64,
}

///
/// Array of MSR entries
///
#[repr(C)]
#[derive(Debug, Default)]
pub struct MsrEntries {
    /// Number of MSR entries in array
    pub nmsrs: u32,
    /// Padding
    pub pad: u32,
    /// Array of MSR entries
    pub entries: __IncompleteArrayField<MsrEntry>,
}

///
/// Entry describing a CPUID feature/leaf. Features can be set as responses to
/// the CPUID instruction.
///
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq)]
pub struct CpuIdEntry2 {
    /// The EAX value used to obtain the entry
    pub function: u32,
    /// The ECX value used to obtain the entry (if affected)
    pub index: u32,
    /// An OR of zero or more of the following:
    /// - The index field is valid
    /// - CPUID for this function returns different values for successive invocations
    /// - Set if this entry is the first entry to be read by a CPU
    pub flags: u32,
    /// Value returned in EAX by CPUID for this function/index combination
    pub eax: u32,
    /// Value returned in EBX by CPUID for this function/index combination
    pub ebx: u32,
    /// Value returned in ECX by CPUID for this function/index combination
    pub ecx: u32,
    /// Value returned in EDX by CPUID for this function/index combination
    pub edx: u32,
    /// Padding
    pub padding: [u32; 3usize],
}

///
/// Array of CpuId2 entries, each of which describing a feature/leaf to be set
///
#[repr(C)]
#[derive(Debug, Default)]
pub struct CpuId2 {
    /// Number of entries
    pub nent: u32,
    /// Padding
    pub padding: u32,
    /// Array of entries
    pub entries: __IncompleteArrayField<CpuIdEntry2>,
}

/// Windows definition of the LAPIC state, the set of memory mapped registers
/// that describe the Local APIC. Windows-based VMMs require 4KB of memory to
/// describe the LAPIC state, or the Windows APIs will fail, even though the
/// architecture-specified space requirement is only 1KB.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct LapicState {
    /// Set of all registers that describe the Local APIC state
    pub regs: [::std::os::raw::c_char; 4096usize],
}

impl Default for LapicState {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}

impl ::std::fmt::Debug for LapicState {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        self.regs[..].fmt(fmt)
    }
}

#[repr(C)]
#[derive(Default)]
/// Zero-sized array
pub struct __IncompleteArrayField<T>(::std::marker::PhantomData<T>, [T; 0]);

impl<T> __IncompleteArrayField<T> {
    #[inline]
    /// Creates a new `__IncompleteArrayField` structure
    pub fn new() -> Self {
        __IncompleteArrayField(::std::marker::PhantomData, [])
    }
    #[inline]
    /// Get a pointer. Using this pointer is unsafe.
    pub unsafe fn as_ptr(&self) -> *const T {
        ::std::mem::transmute(self)
    }
    #[inline]
    /// Get a mutable pointer. Using this pointer is unsafe.
    pub unsafe fn as_mut_ptr(&mut self) -> *mut T {
        ::std::mem::transmute(self)
    }
    #[inline]
    /// Extracts a slice ontaining the entire array. Using this slice is unsafe.
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        ::std::slice::from_raw_parts(self.as_ptr(), len)
    }
    #[inline]
    /// Extacts a mutable slice containing the entire array. Using this slice
    /// is unsafe.
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        ::std::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}

impl<T> ::std::fmt::Debug for __IncompleteArrayField<T> {
    fn fmt(&self, fmt: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        fmt.write_str("__IncompleteArrayField")
    }
}

#[cfg(test)]
impl<T> ::std::clone::Clone for __IncompleteArrayField<T> {
    #[inline]
    fn clone(&self) -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcpu_test_layout_lapic_state() {
        assert_eq!(
            ::std::mem::size_of::<LapicState>(),
            4096usize,
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

    #[test]
    fn vcpu_test_layout_standard_registers() {
        assert_eq!(
            ::std::mem::size_of::<StandardRegisters>(),
            144usize,
            concat!("Size of: ", stringify!(StandardRegisters))
        );
        assert_eq!(
            ::std::mem::align_of::<StandardRegisters>(),
            8usize,
            concat!("Alignment of ", stringify!(StandardRegisters))
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).rax as *const _ as usize },
            0usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(rax)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).rbx as *const _ as usize },
            8usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(rbx)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).rcx as *const _ as usize },
            16usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(rcx)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).rdx as *const _ as usize },
            24usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(rdx)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).rsi as *const _ as usize },
            32usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(rsi)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).rdi as *const _ as usize },
            40usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(rdi)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).rsp as *const _ as usize },
            48usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(rsp)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).rbp as *const _ as usize },
            56usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(rbp)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).r8 as *const _ as usize },
            64usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(r8)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).r9 as *const _ as usize },
            72usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(r9)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).r10 as *const _ as usize },
            80usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(r10)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).r11 as *const _ as usize },
            88usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(r11)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).r12 as *const _ as usize },
            96usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(r12)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).r13 as *const _ as usize },
            104usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(r13)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).r14 as *const _ as usize },
            112usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(r14)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).r15 as *const _ as usize },
            120usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(r15)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).rip as *const _ as usize },
            128usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(rip)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<StandardRegisters>())).rflags as *const _ as usize },
            136usize,
            concat!(
                "Offset of field: ",
                stringify!(StandardRegisters),
                "::",
                stringify!(rflags)
            )
        );
    }

    #[test]
    fn vcpu_test_layout_special_registers() {
        assert_eq!(
            ::std::mem::size_of::<SpecialRegisters>(),
            312usize,
            concat!("Size of: ", stringify!(SpecialRegisters))
        );
        assert_eq!(
            ::std::mem::align_of::<SpecialRegisters>(),
            8usize,
            concat!("Alignment of ", stringify!(SpecialRegisters))
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).cs as *const _ as usize },
            0usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(cs)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).ds as *const _ as usize },
            24usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(ds)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).es as *const _ as usize },
            48usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(es)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).fs as *const _ as usize },
            72usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(fs)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).gs as *const _ as usize },
            96usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(gs)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).ss as *const _ as usize },
            120usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(ss)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).tr as *const _ as usize },
            144usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(tr)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).ldt as *const _ as usize },
            168usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(ldt)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).gdt as *const _ as usize },
            192usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(gdt)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).idt as *const _ as usize },
            208usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(idt)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).cr0 as *const _ as usize },
            224usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(cr0)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).cr2 as *const _ as usize },
            232usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(cr2)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).cr3 as *const _ as usize },
            240usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(cr3)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).cr4 as *const _ as usize },
            248usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(cr4)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).cr8 as *const _ as usize },
            256usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(cr8)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).efer as *const _ as usize },
            264usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(efer)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).apic_base as *const _ as usize },
            272usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(apic_base)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SpecialRegisters>())).interrupt_bitmap as *const _ as usize },
            280usize,
            concat!(
                "Offset of field: ",
                stringify!(SpecialRegisters),
                "::",
                stringify!(interrupt_bitmap)
            )
        );
    }

    #[test]
    fn vcpu_test_layout_msr_entry() {
        assert_eq!(
            ::std::mem::size_of::<MsrEntry>(),
            16usize,
            concat!("Size of: ", stringify!(MsrEntry))
        );
        assert_eq!(
            ::std::mem::align_of::<MsrEntry>(),
            8usize,
            concat!("Alignment of ", stringify!(MsrEntry))
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<MsrEntry>())).index as *const _ as usize },
            0usize,
            concat!(
                "Offset of field: ",
                stringify!(MsrEntry),
                "::",
                stringify!(index)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<MsrEntry>())).reserved as *const _ as usize },
            4usize,
            concat!(
                "Offset of field: ",
                stringify!(MsrEntry),
                "::",
                stringify!(reserved)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<MsrEntry>())).data as *const _ as usize },
            8usize,
            concat!(
                "Offset of field: ",
                stringify!(MsrEntry),
                "::",
                stringify!(data)
            )
        );
    }

    #[test]
    fn vcpu_test_layout_msr_entries() {
        assert_eq!(
            ::std::mem::size_of::<MsrEntries>(),
            8usize,
            concat!("Size of: ", stringify!(MsrEntries))
        );
        assert_eq!(
            ::std::mem::align_of::<MsrEntries>(),
            8usize,
            concat!("Alignment of ", stringify!(MsrEntries))
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<MsrEntries>())).nmsrs as *const _ as usize },
            0usize,
            concat!(
                "Offset of field: ",
                stringify!(MsrEntries),
                "::",
                stringify!(nmsrs)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<MsrEntries>())).pad as *const _ as usize },
            4usize,
            concat!(
                "Offset of field: ",
                stringify!(MsrEntries),
                "::",
                stringify!(pad)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<MsrEntries>())).entries as *const _ as usize },
            8usize,
            concat!(
                "Offset of field: ",
                stringify!(MsrEntries),
                "::",
                stringify!(entries)
            )
        );
    }

    #[test]
    fn vcpu_test_layout_segment_register() {
        assert_eq!(
            ::std::mem::size_of::<SegmentRegister>(),
            24usize,
            concat!("Size of: ", stringify!(SegmentRegister))
        );
        assert_eq!(
            ::std::mem::align_of::<SegmentRegister>(),
            8usize,
            concat!("Alignment of ", stringify!(SegmentRegister))
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SegmentRegister>())).base as *const _ as usize },
            0usize,
            concat!(
                "Offset of field: ",
                stringify!(SegmentRegister),
                "::",
                stringify!(base)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SegmentRegister>())).limit as *const _ as usize },
            8usize,
            concat!(
                "Offset of field: ",
                stringify!(SegmentRegister),
                "::",
                stringify!(limit)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SegmentRegister>())).selector as *const _ as usize },
            12usize,
            concat!(
                "Offset of field: ",
                stringify!(SegmentRegister),
                "::",
                stringify!(selector)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SegmentRegister>())).type_ as *const _ as usize },
            14usize,
            concat!(
                "Offset of field: ",
                stringify!(SegmentRegister),
                "::",
                stringify!(type_)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SegmentRegister>())).present as *const _ as usize },
            15usize,
            concat!(
                "Offset of field: ",
                stringify!(SegmentRegister),
                "::",
                stringify!(present)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SegmentRegister>())).dpl as *const _ as usize },
            16usize,
            concat!(
                "Offset of field: ",
                stringify!(SegmentRegister),
                "::",
                stringify!(dpl)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SegmentRegister>())).db as *const _ as usize },
            17usize,
            concat!(
                "Offset of field: ",
                stringify!(SegmentRegister),
                "::",
                stringify!(db)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SegmentRegister>())).s as *const _ as usize },
            18usize,
            concat!(
                "Offset of field: ",
                stringify!(SegmentRegister),
                "::",
                stringify!(s)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SegmentRegister>())).l as *const _ as usize },
            19usize,
            concat!(
                "Offset of field: ",
                stringify!(SegmentRegister),
                "::",
                stringify!(l)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SegmentRegister>())).g as *const _ as usize },
            20usize,
            concat!(
                "Offset of field: ",
                stringify!(SegmentRegister),
                "::",
                stringify!(g)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SegmentRegister>())).avl as *const _ as usize },
            21usize,
            concat!(
                "Offset of field: ",
                stringify!(SegmentRegister),
                "::",
                stringify!(avl)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SegmentRegister>())).unusable as *const _ as usize },
            22usize,
            concat!(
                "Offset of field: ",
                stringify!(SegmentRegister),
                "::",
                stringify!(unusable)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<SegmentRegister>())).padding as *const _ as usize },
            23usize,
            concat!(
                "Offset of field: ",
                stringify!(SegmentRegister),
                "::",
                stringify!(padding)
            )
        );
    }

    #[test]
    fn vcpu_test_layout_descriptor_table() {
        assert_eq!(
            ::std::mem::size_of::<DescriptorTable>(),
            16usize,
            concat!("Size of: ", stringify!(DescriptorTable))
        );
        assert_eq!(
            ::std::mem::align_of::<DescriptorTable>(),
            8usize,
            concat!("Alignment of ", stringify!(DescriptorTable))
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<DescriptorTable>())).base as *const _ as usize },
            0usize,
            concat!(
                "Offset of field: ",
                stringify!(DescriptorTable),
                "::",
                stringify!(base)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<DescriptorTable>())).limit as *const _ as usize },
            8usize,
            concat!(
                "Offset of field: ",
                stringify!(DescriptorTable),
                "::",
                stringify!(limit)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<DescriptorTable>())).padding as *const _ as usize },
            10usize,
            concat!(
                "Offset of field: ",
                stringify!(DescriptorTable),
                "::",
                stringify!(padding)
            )
        );
    }

    #[test]
    fn vcpu_test_layout_fpu_state() {
        assert_eq!(
            ::std::mem::size_of::<FpuState>(),
            416usize,
            concat!("Size of: ", stringify!(FpuState))
        );
        assert_eq!(
            ::std::mem::align_of::<FpuState>(),
            8usize,
            concat!("Alignment of ", stringify!(FpuState))
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<FpuState>())).fpr as *const _ as usize },
            0usize,
            concat!(
                "Offset of field: ",
                stringify!(FpuState),
                "::",
                stringify!(fpr)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<FpuState>())).fcw as *const _ as usize },
            128usize,
            concat!(
                "Offset of field: ",
                stringify!(FpuState),
                "::",
                stringify!(fcw)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<FpuState>())).fsw as *const _ as usize },
            130usize,
            concat!(
                "Offset of field: ",
                stringify!(FpuState),
                "::",
                stringify!(fsw)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<FpuState>())).ftwx as *const _ as usize },
            132usize,
            concat!(
                "Offset of field: ",
                stringify!(FpuState),
                "::",
                stringify!(ftwx)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<FpuState>())).pad1 as *const _ as usize },
            133usize,
            concat!(
                "Offset of field: ",
                stringify!(FpuState),
                "::",
                stringify!(pad1)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<FpuState>())).last_opcode as *const _ as usize },
            134usize,
            concat!(
                "Offset of field: ",
                stringify!(FpuState),
                "::",
                stringify!(last_opcode)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<FpuState>())).last_ip as *const _ as usize },
            136usize,
            concat!(
                "Offset of field: ",
                stringify!(FpuState),
                "::",
                stringify!(last_ip)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<FpuState>())).last_dp as *const _ as usize },
            144usize,
            concat!(
                "Offset of field: ",
                stringify!(FpuState),
                "::",
                stringify!(last_dp)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<FpuState>())).xmm as *const _ as usize },
            152usize,
            concat!(
                "Offset of field: ",
                stringify!(FpuState),
                "::",
                stringify!(xmm)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<FpuState>())).mxcsr as *const _ as usize },
            408usize,
            concat!(
                "Offset of field: ",
                stringify!(FpuState),
                "::",
                stringify!(mxcsr)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<FpuState>())).pad2 as *const _ as usize },
            412usize,
            concat!(
                "Offset of field: ",
                stringify!(FpuState),
                "::",
                stringify!(pad2)
            )
        );
    }

    #[test]
    fn vcpu_test_layout_cpuid_entry2() {
        assert_eq!(
            ::std::mem::size_of::<CpuIdEntry2>(),
            40usize,
            concat!("Size of: ", stringify!(CpuIdEntry2))
        );
        assert_eq!(
            ::std::mem::align_of::<CpuIdEntry2>(),
            4usize,
            concat!("Alignment of ", stringify!(CpuIdEntry2))
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<CpuIdEntry2>())).function as *const _ as usize },
            0usize,
            concat!(
                "Offset of field: ",
                stringify!(CpuIdEntry2),
                "::",
                stringify!(function)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<CpuIdEntry2>())).index as *const _ as usize },
            4usize,
            concat!(
                "Offset of field: ",
                stringify!(CpuIdEntry2),
                "::",
                stringify!(index)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<CpuIdEntry2>())).flags as *const _ as usize },
            8usize,
            concat!(
                "Offset of field: ",
                stringify!(CpuIdEntry2),
                "::",
                stringify!(flags)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<CpuIdEntry2>())).eax as *const _ as usize },
            12usize,
            concat!(
                "Offset of field: ",
                stringify!(CpuIdEntry2),
                "::",
                stringify!(eax)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<CpuIdEntry2>())).ebx as *const _ as usize },
            16usize,
            concat!(
                "Offset of field: ",
                stringify!(CpuIdEntry2),
                "::",
                stringify!(ebx)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<CpuIdEntry2>())).ecx as *const _ as usize },
            20usize,
            concat!(
                "Offset of field: ",
                stringify!(CpuIdEntry2),
                "::",
                stringify!(ecx)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<CpuIdEntry2>())).edx as *const _ as usize },
            24usize,
            concat!(
                "Offset of field: ",
                stringify!(CpuIdEntry2),
                "::",
                stringify!(edx)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<CpuIdEntry2>())).padding as *const _ as usize },
            28usize,
            concat!(
                "Offset of field: ",
                stringify!(CpuIdEntry2),
                "::",
                stringify!(padding)
            )
        );
    }

    #[test]
    fn vcpu_test_layout_cpuid2() {
        assert_eq!(
            ::std::mem::size_of::<CpuId2>(),
            8usize,
            concat!("Size of: ", stringify!(CpuId2))
        );
        assert_eq!(
            ::std::mem::align_of::<CpuId2>(),
            4usize,
            concat!("Alignment of ", stringify!(CpuId2))
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<CpuId2>())).nent as *const _ as usize },
            0usize,
            concat!(
                "Offset of field: ",
                stringify!(CpuId2),
                "::",
                stringify!(nent)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<CpuId2>())).padding as *const _ as usize },
            4usize,
            concat!(
                "Offset of field: ",
                stringify!(CpuId2),
                "::",
                stringify!(padding)
            )
        );
        assert_eq!(
            unsafe { &(*(::std::ptr::null::<CpuId2>())).entries as *const _ as usize },
            8usize,
            concat!(
                "Offset of field: ",
                stringify!(CpuId2),
                "::",
                stringify!(entries)
            )
        );
    }

}
