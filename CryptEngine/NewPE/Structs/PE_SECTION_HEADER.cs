using System.Runtime.InteropServices;
using System.Text;

namespace CryptEngine.NewPE.Structs
{
    [StructLayout(LayoutKind.Sequential)]
    public struct PE_SECTION_HEADER
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public char[] Name;

        public uint VirtualSize;

        public uint VirtualAddress;

        public uint SizeOfRawData;

        public uint PointerToRawData;

        public uint PointerToRelocations;

        public uint PointerToLinenumbers;

        public ushort NumberOfRelocations;

        public ushort NumberOfLinenumbers;

        public uint Characteristics;

        public int Length { get { return Marshal.SizeOf(this); } }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();

            sb.AppendLine(string.Format("{0}_SECTION_HEADER:", new string(Name).TrimStart('.').ToUpper()));

            int len = 8 - Name.Length;
            sb.Append(string.Format("\t.Name:\t\tdb \"{0}\"", new string(Name)));
            for (int i = 0; i < len; i++)
                sb.Append(", 0");
            sb.AppendLine();

            sb.AppendLine(string.Format("\t.VirtualSize:\t\tdd 0x{0}", VirtualSize.ToString("X8")));
            sb.AppendLine(string.Format("\t.VirtualAddress:\t\tdd 0x{0}", VirtualAddress.ToString("X8")));
            sb.AppendLine(string.Format("\t.SizeOfRawData:\t\tdd 0x{0}", SizeOfRawData.ToString("X8")));
            sb.AppendLine(string.Format("\t.PointerToRawData:\t\tdd {0}", new string(Name).TrimStart('.').ToUpper())/* PointerToRawData.ToString("X8")) */);
            sb.AppendLine(string.Format("\t.PointerToRelocations:\t\tdd 0x{0}", PointerToRelocations.ToString("X8")));
            sb.AppendLine(string.Format("\t.PointerToLinenumbers:\t\tdd 0x{0}", PointerToLinenumbers.ToString("X8")));
            sb.AppendLine(string.Format("\t.NumberOfRelocations:\t\tdw 0x{0}", NumberOfRelocations.ToString("X8")));
            sb.AppendLine(string.Format("\t.NumberOfLinenumbers:\t\tdw 0x{0}", NumberOfLinenumbers.ToString("X8")));
            sb.AppendLine(string.Format("\t.Characteristics:\t\tdd 0x{0}", Characteristics.ToString("X8")));

            return sb.ToString();
        }
    }
}
