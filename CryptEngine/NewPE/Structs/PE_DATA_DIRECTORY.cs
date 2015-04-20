using System;
using System.Runtime.InteropServices;
using System.Text;

namespace CryptEngine.NewPE.Structs
{

    #region PE_DATA_DIRECTORY_ENTRY

    public enum PE_DATA_DIRECTORY_ENTRY
    {
        Export,
        Import,
        Resource,
        Exception,
        Security,
        Relocation,
        Debug,
        Architecture,
        GlobalPtr,
        TLS,
        Configuration,
        BoundImport,
        ImportAddressTable,
        DelayImport,
        CLR,
        Reserved
    }

    #endregion

    [StructLayout(LayoutKind.Sequential)]
    public struct PE_DATA_DIRECTORY
    {
        [MarshalAs(UnmanagedType.I4)]
        public uint VirtualAddress;

        [MarshalAs(UnmanagedType.I4)]
        public uint Size;

        public int Length { get { return Marshal.SizeOf(this); } }

        public string ToString(PE_DATA_DIRECTORY_ENTRY Entry)
        {
            StringBuilder sb = new StringBuilder();

            sb.AppendLine(string.Format("{0}_DIRECTORY:", Enum.GetName(typeof(PE_DATA_DIRECTORY_ENTRY), Entry).ToUpper()));
            sb.AppendLine(string.Format("\t.VirtualAddres:\t\tdd {0}", VirtualAddress));
            sb.AppendLine(string.Format("\t.Size:\t\tdd {0}", Size));

            return sb.ToString();
        }
    }
}
