# SharpRecycledGate

A C# Implementation of the RecycledGate Technique

## Overview

SharpRecycledGate implements a RecycledGate technique using C#. The core principle involves leveraging legitimate code structures (specifically a `RET` instruction gadget) found within loaded system modules (`ntdll.dll` by default) to perform the final control transfer to custom shellcode. This aims to make the execution flow appear more legitimate, potentially bypassing security controls that monitor for direct execution from newly allocated, non-module-backed memory.

## Concept

The key aspect of this RecycledGate is that the final instruction responsible for jumping into the shellcode is the legitimate RET instruction residing within `ntdll.dll`, rather than an instruction within the newly allocated memory block itself. This indirect execution path originating from a trusted module is the primary goal for evasion purposes.

## Execution flow

1. **Gadget Identification**: The target module (`ntdll.dll`) is loaded, and its PE structure is parsed. Executable sections (`.text` or sections with `IMAGE_SCN_MEM_EXECUTE` flag) are scanned byte-by-byte to locate the virtual address of a `RET` (0xC3) instruction. This found gadget will be used for the final jump.
2. **Shellcode Preparation**: The provided shellcode byte array has a NOP sled prepended. This adds a small buffer to potentially increase execution reliability if the entry point calculation has minor offsets.
3. **Memory Allocation**: `VirtualAlloc` is called to reserve and commit a region of memory with `PAGE_EXECUTE_READWRITE` permissions. This region will host both a small setup stub and the prepared shellcode.
4. **Stub Generation**: A small sequence of x64 machine code (the "setup stub") is generated. This stub performs two actions:
    * Pushes the calculated future address of the shellcode onto the stack.
    * Performs an absolute JMP to the address of the RET gadget found in Step 1.
5. **Placement**: 
    * The generated setup stub is copied to the beginning of the allocated memory region.
    * The NOP-padded shellcode is copied into the allocated memory region immediately following the setup stub.
6. **Execution Transfer**: `CreateThread`  is called, setting the new thread's starting address (`lpStartAddress`) to point to the beginning of the setup stub in the allocated memory.
7. **RecycledGate Execution**: 
    * The new thread begins executing the setup stub.
    * The stub pushes the shellcode address onto the stack.
    * The stub jumps to the RET gadget within ntdll.dll.
    * The RET instruction in ntdll.dll executes, popping the shellcode address (placed there by the stub) from the stack into the instruction pointer (RIP).
    * Execution control is transferred to the shellcode.

## Technical Notes
* Made in C# targeting .NET Framework 4.8
* Only for x64
* Leverages P/Invoke for Windows API calls (VirtualAlloc, CreateThread, GetModuleHandle, etc.).
* Requires memory allocated with execute permissions