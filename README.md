# vmm-vcpu

A library to provide a hypervisor-agnostic abstraction on top of Virtual CPU (vCPU)
functionality.

## Platform Support

* Arch: x86, AMD64, ARM64
* Operating System: Unix/Linux/Windows

## Usage

The `vmm-vcpu` crate is not functional standalone, but should be used to implement
hypervisor-specific virtual CPU functionality. In order to create an 
implementation of the `vmm-vcpu` crate to be consumed by VMMs:

First, add the following to `Cargo.toml`:

```
vmm-vcpu = "0.1"
```

Next, add the following to the crate root:

```
extern crate vmm-vcpu
```

Then, implement each of the functions of the `Vcpu` trait. Any irrelevant/
unused functions can be completed with the `unimplemented!();` macro.

## Design

The `vmm-vcpu` crate itself is quite simple, requiring only exposing a public
`Vcpu` trait with the functions that comprise common vCPU functionality, as
well as exported wrappers on top of common data structures (including 
generically named structures wrapping data structures from `kvm_bindings` when 
architecturally, rather than hypervisor, specific.)

## License

This project is licensed under Apache License, Version 2.0, (LICENSE or http://www.apache.org/licenses/LICENSE-2.0)