// Copyright 2018-2019 CrowdStrike, Inc.
// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Portions Copyright 2018 Cloudbase Solutions Srl
// SPDX-License-Identifier: Apache-2.0 or MIT
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Trait to access the functionality of a virtual CPU (vCPU).

use std::{io, result};

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub use arm::VcpuInit;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub use x86_64::{
    StandardRegisters, SpecialRegisters, FpuState, MsrEntries, MsrEntry, 
    CpuId, LapicState
};

///
/// Reasons for vCPU exits for Windows (Hyper-V) platforms
///
#[derive(Debug)]
#[cfg(windows)]
pub enum VcpuExit {

    /// Corresponds to WHvRunVpExitReasonNone
    None,
    /// Corresponds to WHvRunVpExitReasonMemoryAccess
    MemoryAccess,
    /// Corresponds to WHvRunVpExitReasonX64IoPortAccess
    IoPortAccess,
    /// Corresponds to WHvRunVpExitReasonUnrecoverableException
    UnrecoverableException,
    /// Corresponds to WHvRunVpExitReasonInvalidVpRegisterValue
    InvalidVpRegisterValue,
    /// Corresponds to WHvRunVpExitReasonUnsupportedFeature
    UnsupportedFeature,
    /// Corresponds to WHvRunVpExitReasonX64InterruptWindow
    IrqWindowOpen,
    /// Corresponds to  WHvRunVpExitReasonX64Halt
    Hlt,
    /// Corresponds to WHvRunVpExitReasonX64ApicEoi
    IoapicEoi,
    /// Corresponds to WHvRunVpExitReasonX64MsrAccess
    MsrAccess,
    /// Corresponds to WHvRunVpExitReasonX64Cpuid
    Cpuid,
    /// Corresponds to WHvRunVpExitReasonException
    Exception,
    /// Corresponds to WHvRunVpExitReasonCanceled
    Canceled,
}

///
/// Reasons for vCPU exits for Unix-based (KVM) platforms
///
#[derive(Debug)]
#[cfg(unix)]
pub enum VcpuExit<'a> {
    /// Corresponds to KVM_EXIT_UNKNOWN.
    Unknown,
    /// Corresponds to KVM_EXIT_EXCEPTION.
    Exception,
    /// An out port instruction was run on the given port with the given data.
    IoOut(u16 /* port */, &'a [u8] /* data */),
    /// An in port instruction was run on the given port.
    ///
    /// The given slice should be filled in before [run()](struct.VcpuFd.html#method.run)
    /// is called again.
    IoIn(u16 /* port */, &'a mut [u8] /* data */),
    /// Corresponds to KVM_EXIT_HYPERCALL.
    Hypercall,
    /// Corresponds to KVM_EXIT_DEBUG.
    Debug,
    /// Corresponds to KVM_EXIT_HLT.
    Hlt,
    /// A read instruction was run against the given MMIO address.
    ///
    /// The given slice should be filled in before [run()](struct.VcpuFd.html#method.run)
    /// is called again.
    MmioRead(u64 /* address */, &'a mut [u8]),
    /// A write instruction was run against the given MMIO address with the given data.
    MmioWrite(u64 /* address */, &'a [u8]),
    /// Corresponds to KVM_EXIT_IRQ_WINDOW_OPEN.
    IrqWindowOpen,
    /// Corresponds to KVM_EXIT_SHUTDOWN.
    Shutdown,
    /// Corresponds to KVM_EXIT_FAIL_ENTRY.
    FailEntry,
    /// Corresponds to KVM_EXIT_INTR.
    Intr,
    /// Corresponds to KVM_EXIT_SET_TPR.
    SetTpr,
    /// Corresponds to KVM_EXIT_TPR_ACCESS.
    TprAccess,
    /// Corresponds to KVM_EXIT_S390_SIEIC.
    S390Sieic,
    /// Corresponds to KVM_EXIT_S390_RESET.
    S390Reset,
    /// Corresponds to KVM_EXIT_DCR.
    Dcr,
    /// Corresponds to KVM_EXIT_NMI.
    Nmi,
    /// Corresponds to KVM_EXIT_INTERNAL_ERROR.
    InternalError,
    /// Corresponds to KVM_EXIT_OSI.
    Osi,
    /// Corresponds to KVM_EXIT_PAPR_HCALL.
    PaprHcall,
    /// Corresponds to KVM_EXIT_S390_UCONTROL.
    S390Ucontrol,
    /// Corresponds to KVM_EXIT_WATCHDOG.
    Watchdog,
    /// Corresponds to KVM_EXIT_S390_TSCH.
    S390Tsch,
    /// Corresponds to KVM_EXIT_EPR.
    Epr,
    /// Corresponds to KVM_EXIT_SYSTEM_EVENT.
    SystemEvent,
    /// Corresponds to KVM_EXIT_S390_STSI.
    S390Stsi,
    /// Corresponds to KVM_EXIT_IOAPIC_EOI.
    IoapicEoi,
    /// Corresponds to KVM_EXIT_HYPERV.
    Hyperv,
}

/// A specialized `Result` type for VCPU operations
///
/// This typedef is generally used to avoid writing out io::Error directly and
/// is otherwise a direct mapping to Result.
pub type Result<T> = result::Result<T, io::Error>;

///
/// Trait to represent a virtual CPU
///
/// This crate provides a hypervisor-agnostic interface to common virtual CPU
/// functionality
///
pub trait Vcpu {
    /// Associated type representing the run context on a vCPU exit
    type RunContextType;

    /// Reads the standard registers from the virtual CPU
    ///
    /// StandardRegisters:
    /// - General Purpose Registers: RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP, R8 - R15
    /// - Instruction Pointer and Flags: RIP, RFLAGS
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    fn get_regs(&self) -> Result<StandardRegisters>;

    /// Writes the standard registers into the virtual CPU
    ///
    /// StandardRegisters:
    /// - General Purpose Registers: RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP, R8 - R15
    /// - Instruction Pointer and Flags: RIP, RFLAGS
    #[cfg(not(any(target_arch = "arm", target_arch = "aarch64")))]
    fn set_regs(&self, regs: &StandardRegisters) -> Result<()>;

    /// Reads the special registers from the virtual CPU
    ///
    /// SpecialRegisters:
    /// - Segment Registers: CS, DS, ES, FS, GS, SS
    /// - Task and Descriptor Table Registers: TR, LDT, GDT, IDT
    /// - Control Registers: CR0, CR2, CR3, CR4, CR8
    /// - Additional EFER, APIC base
    /// - Interrupt_bitmap: Bitmap of pending external interrupts (KVM only, may
    ///   be unused by vCPU implementations of other VMMs)
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_sregs(&self) -> Result<SpecialRegisters>;

    /// Writes the special registers into the virtual CPU
    ///
    /// SpecialRegisters:
    /// - Segment Registers: CS, DS, ES, FS, GS, SS
    /// - Task and Descriptor Table Registers: TR, LDT, GDT, IDT
    /// - Control Registers: CR0, CR2, CR3, CR4, CR8
    /// - Additional: EFER, APIC base
    /// - Interrupt_bitmap: Bitmap of pending external interrupts (KVM only, may
    ///   be unused by vCPU implementations of other VMMs)
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn set_sregs(&self, sregs: &SpecialRegisters) -> Result<()>;

    /// Reads the floating point state from the vCPU
    ///
    /// - Floating Point MMX Registers 0-7
    /// - Floating Point Control, Status, Tag Registers (FCW, FSW, FTW)
    /// - Floating point exception state (Last FIP, FOP, FCS, FDS, FDP)
    /// - XMM Registers 0-15
    /// - MXCSR Control and Status Register
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_fpu(&self) -> Result<FpuState>;

    /// Writes the floating point state to the vCPU
    ///
    /// - Floating Point MMX Registers 0-7
    /// - Floating Pointer Control, Status, Tag Registers (FCW, FSW, FTW)
    /// - Floating point exception state (Last FIP, FOP, FCS, FDS, FDP)
    /// - XMM Registers 0-15
    /// - MXCSR Control and Status Register
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn set_fpu(&self, fpu: &FpuState) -> Result<()>;

    /// Defines the vCPU responses to the CPUID instruction
    ///
    /// The information contained in these responses can be set to be consistent
    /// with hardware, kernel, userspace capabilities, and user requirements.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn set_cpuid2(&self, cpuid: &CpuId) -> Result<()>;

    /// Read the Local APIC state from the vCPU
    ///
    /// LAPIC state is comprised of the memory-mapped Local APIC registers.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_lapic(&self) -> Result<LapicState>;

    /// Write the Local APIC state to the vCPU
    ///
    /// LAPIC state is comprised of the memory-mapped Local APIC registers
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn set_lapic(&self, klapic: &LapicState) -> Result<()>;

    /// Read the Model-Specific Registers from the vCPU based on MSR indices
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn get_msrs(&self, msrs: &mut MsrEntries) -> Result<(i32)>;

    /// Write the Model-Specific Registers to the vCPU based on MSR indices
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn set_msrs(&self, msrs: &MsrEntries) -> Result<()>;

    /// Initialize a vCPU
    ///
    /// Specifies the CPU to present to the guest, and the optional features
    /// it should have
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn vcpu_init(&self, kvi: &VcpuInit) -> Result<()>;

    /// Set a single register in the virtual CPU
    #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
    fn set_one_reg(&self, reg_id: u64, data: u64) -> Result<()>;

    /// Run a virtual CPU until there is a VM exit
    ///
    /// The output will specify the type of VM exit
    fn run(&self) -> Result<VcpuExit>;

    /// Get the context from the last vCPU run.
    ///
    /// The context contains information related to the latest VM exit
    fn get_run_context(&self) -> Self::RunContextType;
}
