using System.Runtime.InteropServices;
using System.Text;

namespace CryptEngine.NewPE.Structs
{
    [StructLayout(LayoutKind.Sequential)]
    public struct PE_FILE_HEADER
    {
        public ushort Machine;

        public ushort NumberOfSections;

        public uint TimeDateStamp;

        public uint PointerToSymbolTable;

        public uint NumberOfSymbols;

        public ushort SizeOfOptionalHeader;

        public ushort Characteristics;

        public int Length { get { return Marshal.SizeOf(this); } }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();

            sb.AppendLine("FILE_HEADER:");
            sb.AppendLine(string.Format("\t.Machine:\t\tdw 0x{0}", Machine.ToString("X8")));
            sb.AppendLine(string.Format("\t.NumberOfSections:\t\tdw 0x{0}", NumberOfSections.ToString("X8")));
            sb.AppendLine(string.Format("\t.TimeDateStamp:\t\tdd 0x{0}", TimeDateStamp.ToString("X8")));
            sb.AppendLine(string.Format("\t.PointerToSymbolTable:\t\tdd 0x{0}", PointerToSymbolTable.ToString("X8")));
            sb.AppendLine(string.Format("\t.NumberOfSymbols:\t\tdd 0x{0}", NumberOfSymbols.ToString("X8")));
            sb.AppendLine(string.Format("\t.SizeOfOptionalHeader:\t\tdw 0x{0}", SizeOfOptionalHeader.ToString("X8")));
            sb.AppendLine(string.Format("\t.Characteristics:\t\tdw 0x{0}", Characteristics.ToString("X8")));

            return sb.ToString();
        }
    }
}
