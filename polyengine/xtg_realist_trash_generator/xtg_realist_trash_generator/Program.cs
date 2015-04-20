using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;


namespace xtg_realist_trash_generator
{

    class Program
    {

        [DllImport("Kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hLib, [MarshalAs(UnmanagedType.LPStr)] string szName);

        [DllImport("Kernel32.dll")]
        private static extern IntPtr LoadLibraryA([MarshalAs(UnmanagedType.LPStr)]string szLibName);

        [DllImport("Kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll")]
        private static extern int ZwSetInformationProcess(IntPtr hProcess, int processInformationClass, ref ulong processInformation, int processInformationLength);

        [DllImport("User32.dll")]
        private static extern int CallWindowProc(IntPtr lpPrevWndFunc, int hWnd, int Msg, int wParam, int lParam);

        [DllImport("Kernel32.dll")]
        private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("JunkGen.dll", EntryPoint = "GenJunk", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr GenJunk(
            [MarshalAs(UnmanagedType.I4)]int CodeSize,
            [MarshalAs(UnmanagedType.I4)]int CodeMask,
        [MarshalAs(UnmanagedType.I4)]int NeededRegisters,
              [MarshalAs(UnmanagedType.I4)]int BDATA,
              [MarshalAs(UnmanagedType.I4)]int DATA_ADDR,
              [MarshalAs(UnmanagedType.I4)]int DATA_SIZE);

        [DllImport("Poly.dll")]
        private static extern IntPtr GenerateDecryptor(IntPtr lpCode, Int32 CodeSize);

        private static Random Rand = new Random(Guid.NewGuid().GetHashCode());

        private const int XMASK_FUNCTION = 0x1;
        private const int XMASK_LOGIC = 0x4;

        private struct XTG_REGS
        {
            public static uint XTG_EAX = 0x01;
            public static uint XTG_ECX = 0x02;
            public static uint XTG_EDX = 0x04;
            public static uint XTG_EBX = 0x08;
            public static uint XTG_ESP = 0x10;
            public static uint XTG_EBP = 0x20;
            public static uint XTG_ESI = 0x40;
            public static uint XTG_EDI = 0x80;
        }

        //XTG_EAX				equ		00000001b									;01h
        //XTG_ECX				equ		00000010b									;02h
        //XTG_EDX				equ		00000100b									;04h
        //XTG_EBX				equ		00001000b									;08h
        //XTG_ESP				equ		00010000b									;10h
        //XTG_EBP				equ		00100000b									;20h
        //XTG_ESI				equ		01000000b									;40h
        //XTG_EDI				equ		10000000b									;80h 

        [StructLayout(LayoutKind.Explicit)]
        private struct JUNKRET
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.I4)]
            public Int32 EP_ADDR;

            [FieldOffset(4)]
            [MarshalAs(UnmanagedType.I4)]
            public Int32 CODE_SIZE;

            [FieldOffset(8)]
            [MarshalAs(UnmanagedType.I4)]
            public Int32 DATA_ADDR;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct APEX_POLYMORPH_STRUCT
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.I4)]
            public Int32 DecryptorAddress;

            [FieldOffset(4)]
            [MarshalAs(UnmanagedType.I4)]
            public Int32 DecryptorSize;

            [FieldOffset(8)]
            [MarshalAs(UnmanagedType.I4)]
            public Int32 DecryptorEntryPoint;
        }

        [Flags()]
        public enum AllocationType : uint
        {
            COMMIT = 0x1000,
            RESERVE = 0x2000,
            RESET = 0x80000,
            LARGE_PAGES = 0x20000000,
            PHYSICAL = 0x400000,
            TOP_DOWN = 0x100000,
            WRITE_WATCH = 0x200000
        }

        [Flags()]
        public enum MemoryProtection : uint
        {
            EXECUTE = 0x10,
            EXECUTE_READ = 0x20,
            EXECUTE_READWRITE = 0x40,
            EXECUTE_WRITECOPY = 0x80,
            NOACCESS = 0x01,
            READONLY = 0x02,
            READWRITE = 0x04,
            WRITECOPY = 0x08,
            GUARD_Modifierflag = 0x100,
            NOCACHE_Modifierflag = 0x200,
            WRITECOMBINE_Modifierflag = 0x400
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, IntPtr dwSize,
            AllocationType flAllocationType, MemoryProtection flProtect);

        private static byte[] MsgBox =  {
             0x31,0xd2,0xb2,0x30,0x64,0x8b,0x12,0x8b,0x52,0x0c,0x8b,0x52,0x1c,0x8b,0x42
           ,0x08,0x8b,0x72,0x20,0x8b,0x12,0x80,0x7e,0x0c,0x33,0x75,0xf2,0x89,0xc7,0x03
           ,0x78,0x3c,0x8b,0x57,0x78,0x01,0xc2,0x8b,0x7a,0x20,0x01,0xc7,0x31,0xed,0x8b
               ,0x34,0xaf,0x01,0xc6,0x45,0x81,0x3e,0x46,0x61,0x74,0x61,0x75,0xf2,0x81,0x7e
           ,0x08,0x45,0x78,0x69,0x74,0x75,0xe9,0x8b,0x7a,0x24,0x01,0xc7,0x66,0x8b,0x2c
           ,0x6f,0x8b,0x7a,0x1c,0x01,0xc7,0x8b,0x7c,0xaf,0xfc,0x01,0xc7,0x68,0x79,0x74
                   ,0x65,0x01,0x68,0x6b,0x65,0x6e,0x42,0x68,0x20,0x42,0x72,0x6f,0x89,0xe1,0xfe
           ,0x49,0x0b,0x31,0xc0,0x51,0x50,0xff,0xd7};

        private static byte[] int_3 = { 0xcc };

        static void Main(string[] args)
        {
            // byte[] code = { 0xcc, 0xcc, 0xcc, 0xcc };

            IntPtr ptr_JRet = GenJunk(0x1000, XMASK_FUNCTION, 0, 1, 0x00400000, 0x2000);
            JUNKRET jRet = (JUNKRET)Marshal.PtrToStructure(ptr_JRet, typeof(JUNKRET));

            byte[] cock = new byte[0x2000];
            Marshal.Copy((IntPtr)jRet.DATA_ADDR, cock, 0, 0x2000);

            File.WriteAllBytes(@"C:\Users\Admin\Desktop\Data.bin", cock);

            Debugger.Break();

            //GCHandle GC = GCHandle.Alloc(int_3, GCHandleType.Pinned);
            //IntPtr pCode = GC.AddrOfPinnedObject();

            //IntPtr ptr_Apex_Poly_Struct = GenerateDecryptor(pCode, 1);
            //APEX_POLYMORPH_STRUCT ApexPolyStruct = (APEX_POLYMORPH_STRUCT)Marshal.PtrToStructure(ptr_Apex_Poly_Struct, typeof(APEX_POLYMORPH_STRUCT));

            //// Copy decryptor into byte array
            //byte[] PolyDecryptor = new byte[ApexPolyStruct.DecryptorSize];
            //Marshal.Copy((IntPtr)ApexPolyStruct.DecryptorAddress, PolyDecryptor, 0, ApexPolyStruct.DecryptorSize);

            //// offset of the entrypoint in decryptor 
            //int Offset_EP = ApexPolyStruct.DecryptorEntryPoint - ApexPolyStruct.DecryptorAddress;

            ////CallWindowProc((IntPtr)ApexPolyStruct.DecryptorEntryPoint, 0, 0, 0,0);

            //File.WriteAllBytes(@"Z:\Crypt PE\ASM New\include\fuckshitup.bin", PolyDecryptor);

            Debugger.Break();
        }
    }
}
