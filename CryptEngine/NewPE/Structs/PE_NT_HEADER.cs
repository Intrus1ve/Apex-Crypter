using System.Runtime.InteropServices;
using System.Text;

namespace CryptEngine.NewPE.Structs
{
    [StructLayout(LayoutKind.Sequential)]
    public struct PE_NT_HEADER
    {
        [MarshalAs(UnmanagedType.I4)]
        public const int Signature = 0x4550;

        public PE_FILE_HEADER FileHeader;
        public PE_OPTIONAL_HEADER OptionalHeader;

        public int Length { get { return Marshal.SizeOf(Signature) + Marshal.SizeOf(FileHeader) + Marshal.SizeOf(OptionalHeader); } }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();

            sb.AppendLine("PE_HEADER:");
            sb.AppendLine(string.Format("\t.Signature:\t\tdd 0x{0}", Signature.ToString("X8")));
            sb.AppendLine();

            sb.AppendLine(FileHeader.ToString());

            sb.AppendLine(OptionalHeader.ToString());

            return sb.ToString();
        }
    }
}
