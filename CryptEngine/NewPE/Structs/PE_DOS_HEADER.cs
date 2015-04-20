using System.Runtime.InteropServices;
using System.Text;
using System.Reflection;
using System;

namespace CryptEngine.NewPE.Structs
{
    [StructLayout(LayoutKind.Sequential)]
    public struct PE_DOS_HEADER
    {
        public const ushort e_magic = 0x5A4D;

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

        public ushort e_lsarlc;

        public ushort e_ovno;

        public unsafe fixed ushort e_res[4];

        public ushort e_oemid;

        public ushort e_oeminfo;

        public unsafe fixed ushort e_res2[10];

        public uint e_lfanew;

        public int Length { get { return Marshal.SizeOf(this); } }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();

            sb.AppendLine("DOS_HEADER:");
            sb.AppendLine(String.Format(".{0}:\t\tdw 0x{1}", "e_magic", e_magic.ToString("X8")));
            sb.AppendLine(String.Format(".{0}:\t\tdw {1}", "e_cblp", e_cblp));
            sb.AppendLine(String.Format(".{0}:\t\tdw {1}", "e_cp", e_cp));
            sb.AppendLine(String.Format(".{0}:\t\tdw {1}", "e_crlc", e_crlc));
            sb.AppendLine(String.Format(".{0}:\t\tdw {1}", "e_cparhdr", e_cparhdr));
            sb.AppendLine(String.Format(".{0}:\t\tdw {1}", "e_minalloc", e_minalloc));
            sb.AppendLine(String.Format(".{0}:\t\tdw {1}", "e_maxalloc", e_maxalloc));
            sb.AppendLine(String.Format(".{0}:\t\tdw {1}", "e_ss", e_ss));
            sb.AppendLine(String.Format(".{0}:\t\tdw {1}", "e_sp", e_sp));
            sb.AppendLine(String.Format(".{0}:\t\tdw {1}", "e_csum", e_csum));
            sb.AppendLine(String.Format(".{0}:\t\tdw {1}", "e_ip", e_ip));
            sb.AppendLine(String.Format(".{0}:\t\tdw {1}", "e_cs", e_cs));
            sb.AppendLine(String.Format(".{0}:\t\tdw {1}", "e_lsarlc", e_lsarlc));
            sb.AppendLine(String.Format(".{0}:\t\tdw {1}", "e_ovno", e_ovno));
            sb.AppendLine(String.Format(".{0}:\t\ttimes 4 dw 0", "e_res"));
            sb.AppendLine(String.Format(".{0}:\t\tdw {1}", "e_oemid", e_oemid));
            sb.AppendLine(String.Format(".{0}:\t\tdw {1}", "e_oeminfo", e_oeminfo));
            sb.AppendLine(String.Format(".{0}:\t\ttimes 10 dw 0", "e_res2"));
            sb.AppendLine(String.Format(".{0}:\t\tdd {1}", "e_lfanew", e_lfanew));

            return sb.ToString();
        }
    }
}
