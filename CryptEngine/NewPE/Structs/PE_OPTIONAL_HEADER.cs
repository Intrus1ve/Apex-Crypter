using System.Runtime.InteropServices;
using System.Text;

namespace CryptEngine.NewPE.Structs
{
    [StructLayout(LayoutKind.Sequential)]
    public struct PE_OPTIONAL_HEADER
    {
        [MarshalAs(UnmanagedType.I2)]
        public const short Magic = 0x10b;

        [MarshalAs(UnmanagedType.I1)]
        public byte MajorLinkerVersion;

        [MarshalAs(UnmanagedType.I1)]
        public byte MinorLinkerVersion;

        [MarshalAs(UnmanagedType.I4)]
        public uint SizeOfCode;

        [MarshalAs(UnmanagedType.I4)]
        public uint SizeOfInitializedData;

        [MarshalAs(UnmanagedType.I4)]
        public uint SizeOfUninitializedData;

        [MarshalAs(UnmanagedType.I4)]
        public uint AddressOfEntryPoint;

        [MarshalAs(UnmanagedType.I4)]
        public uint BaseOfCode;

        [MarshalAs(UnmanagedType.I4)]
        public uint BaseOfData;

        [MarshalAs(UnmanagedType.I4)]
        public uint ImageBase;

        [MarshalAs(UnmanagedType.I4)]
        public uint SectionAlignment;

        [MarshalAs(UnmanagedType.I4)]
        public uint FileAlignment;

        [MarshalAs(UnmanagedType.I2)]
        public short MajorOperatingSystemVersion;

        [MarshalAs(UnmanagedType.I2)]
        public short MinorOperatingSystemVersion;

        [MarshalAs(UnmanagedType.I2)]
        public short MajorImageVersion;

        [MarshalAs(UnmanagedType.I2)]
        public short MinorImageVersion;

        [MarshalAs(UnmanagedType.I2)]
        public short MajorSubsystemVersion;

        [MarshalAs(UnmanagedType.I2)]
        public short MinorSubsystemVersion;

        [MarshalAs(UnmanagedType.I4)]
        public uint Win32VersionValue;

        [MarshalAs(UnmanagedType.I4)]
        public uint SizeOfImage;

        [MarshalAs(UnmanagedType.I4)]
        public uint SizeOfHeaders;

        [MarshalAs(UnmanagedType.I4)]
        public uint CheckSum;

        [MarshalAs(UnmanagedType.I2)]
        public const short Subsystem = 2;

        [MarshalAs(UnmanagedType.I2)]
        public ushort DllCharacteristics;

        [MarshalAs(UnmanagedType.I4)]
        public const uint SizeOfStackReserve = 0x100000;

        [MarshalAs(UnmanagedType.I4)]
        public const uint SizeOfStackCommit = 0x1000;

        [MarshalAs(UnmanagedType.I4)]
        public const uint SizeOfHeapReserve = 0x100000;

        [MarshalAs(UnmanagedType.I4)]
        public const uint SizeOfHeapCommit = 0x1000;

        [MarshalAs(UnmanagedType.I4)]
        public uint LoaderFlags;

        [MarshalAs(UnmanagedType.I4)]
        public const uint NumberOfRvaAndSizes = 16;

        public PE_DATA_DIRECTORY ExportDirectory;

        public PE_DATA_DIRECTORY ImportDirectory;

        public PE_DATA_DIRECTORY ResourceDirectory;

        public PE_DATA_DIRECTORY ExceptionDirectory;

        public PE_DATA_DIRECTORY SecurityDirectory;

        public PE_DATA_DIRECTORY RelocationDirectory;

        public PE_DATA_DIRECTORY DebugDirectory;

        public PE_DATA_DIRECTORY ArchitectureDirectory;

        public PE_DATA_DIRECTORY GlobalPtrDirectory;

        public PE_DATA_DIRECTORY TLSDirectory;

        public PE_DATA_DIRECTORY ConfigurationDirectory;

        public PE_DATA_DIRECTORY BoundImportDirectory;

        public PE_DATA_DIRECTORY ImportAddressTableDirectory;

        public PE_DATA_DIRECTORY DelayImportDirectory;

        public PE_DATA_DIRECTORY CLRDirectory;

        public PE_DATA_DIRECTORY Reserved;

        public int Length { get { return Marshal.SizeOf(this); } }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();

            sb.AppendLine("OPTIONAL_HEADER:");
            sb.AppendLine(string.Format("\t.Magic:\t\tdw 0x{0}", Magic.ToString("X8")));
            sb.AppendLine(string.Format("\t.MajorLinkerVersion:\t\tdb 0x{0}", MajorLinkerVersion.ToString("X8")));
            sb.AppendLine(string.Format("\t.MinorLinkerVersion:\t\tdb 0x{0}", MinorLinkerVersion.ToString("X8")));
            sb.AppendLine(string.Format("\t.SizeOfCode:\t\tdd 0x{0}", SizeOfCode.ToString("X8")));
            sb.AppendLine(string.Format("\t.SizeOfInitializedData:\t\tdd 0x{0}", SizeOfInitializedData.ToString("X8")));
            sb.AppendLine(string.Format("\t.SizeOfUninitializedData:\t\tdd 0x{0}", SizeOfUninitializedData.ToString("X8")));
            sb.AppendLine(string.Format("\t.AddresssOfEntryPoint:\t\tdd 0x{0}", AddressOfEntryPoint.ToString("X8")));
            sb.AppendLine(string.Format("\t.BaseOfCode:\t\tdd 0x{0}", BaseOfCode.ToString("X8")));
            sb.AppendLine(string.Format("\t.BaseOfData:\t\tdd 0x{0}", BaseOfData.ToString("X8")));
            sb.AppendLine(string.Format("\t.ImageBase:\t\tdd 0x{0}", ImageBase.ToString("X8")));
            sb.AppendLine(string.Format("\t.SectionAlignment:\t\tdd 0x{0}", SectionAlignment.ToString("X8")));
            sb.AppendLine(string.Format("\t.FileAlignment:\t\tdd 0x{0}", FileAlignment.ToString("X8")));
            sb.AppendLine(string.Format("\t.MajorOperatingSystemVersion:\t\tdw 0x{0}", MajorOperatingSystemVersion.ToString("X8")));
            sb.AppendLine(string.Format("\t.MinorOperatingSystemVersion:\t\tdw 0x{0}", MinorOperatingSystemVersion.ToString("X8")));
            sb.AppendLine(string.Format("\t.MajorImageVersion:\t\tdw 0x{0}", MajorImageVersion.ToString("X8")));
            sb.AppendLine(string.Format("\t.MinorImageVersion:\t\tdw 0x{0}", MinorImageVersion.ToString("X8")));
            sb.AppendLine(string.Format("\t.MajorSubsystemVersion:\t\tdw 0x{0}", MajorSubsystemVersion.ToString("X8")));
            sb.AppendLine(string.Format("\t.MinorSubsystemVersion:\t\tdw 0x{0}", MinorSubsystemVersion.ToString("X8")));
            sb.AppendLine(string.Format("\t.Win32VersionValue:\t\tdd 0x{0}", Win32VersionValue.ToString("X8")));
            sb.AppendLine(string.Format("\t.SizeOfImage:\t\tdd 0x{0}", SizeOfImage.ToString("X8")));
            sb.AppendLine(string.Format("\t.SizeOfHeaders:\t\tdd 0x{0}", SizeOfHeaders.ToString("X8")));
            sb.AppendLine(string.Format("\t.CheckSum:\t\tdd 0x{0}", CheckSum.ToString("X8")));
            sb.AppendLine(string.Format("\t.Subsystem:\t\tdw 0x{0}", Subsystem.ToString("X8")));
            sb.AppendLine(string.Format("\t.DllCharacteristics:\t\tdw 0x{0}", DllCharacteristics.ToString("X8")));
            sb.AppendLine(string.Format("\t.SizeOfStackReserve:\t\tdd 0x{0}", SizeOfStackReserve.ToString("X8")));
            sb.AppendLine(string.Format("\t.SizeOfStackCommit:\t\tdd 0x{0}", SizeOfStackCommit.ToString("X8")));
            sb.AppendLine(string.Format("\t.SizeOfHeapReserve:\t\tdd 0x{0}", SizeOfHeapReserve.ToString("X8")));
            sb.AppendLine(string.Format("\t.SizeOfHeapCommit:\t\tdd 0x{0}", SizeOfHeapCommit.ToString("X8")));
            sb.AppendLine(string.Format("\t.LoaderFlags:\t\tdd 0x{0}", LoaderFlags.ToString("X8")));
            sb.AppendLine(string.Format("\t.NumberOfRvaAndSizes:\t\t dd 0x{0}", NumberOfRvaAndSizes.ToString("X8")));

            sb.AppendLine();
            sb.AppendLine("DATA_DIRECTORIES:");
            sb.AppendLine(string.Format("\t{0}", ExportDirectory.ToString(PE_DATA_DIRECTORY_ENTRY.Export)));
            sb.AppendLine(string.Format("\t{0}", ImportDirectory.ToString(PE_DATA_DIRECTORY_ENTRY.Import)));
            sb.AppendLine(string.Format("\t{0}", ResourceDirectory.ToString(PE_DATA_DIRECTORY_ENTRY.Resource)));
            sb.AppendLine(string.Format("\t{0}", ExceptionDirectory.ToString(PE_DATA_DIRECTORY_ENTRY.Exception)));
            sb.AppendLine(string.Format("\t{0}", SecurityDirectory.ToString(PE_DATA_DIRECTORY_ENTRY.Security)));
            sb.AppendLine(string.Format("\t{0}", RelocationDirectory.ToString(PE_DATA_DIRECTORY_ENTRY.Relocation)));
            sb.AppendLine(string.Format("\t{0}", DebugDirectory.ToString(PE_DATA_DIRECTORY_ENTRY.Debug)));
            sb.AppendLine(string.Format("\t{0}", ArchitectureDirectory.ToString(PE_DATA_DIRECTORY_ENTRY.Architecture)));
            sb.AppendLine(string.Format("\t{0}", Reserved.ToString(PE_DATA_DIRECTORY_ENTRY.GlobalPtr)));
            sb.AppendLine(string.Format("\t{0}", TLSDirectory.ToString(PE_DATA_DIRECTORY_ENTRY.TLS)));
            sb.AppendLine(string.Format("\t{0}", ConfigurationDirectory.ToString(PE_DATA_DIRECTORY_ENTRY.Configuration)));
            sb.AppendLine(string.Format("\t{0}", BoundImportDirectory.ToString(PE_DATA_DIRECTORY_ENTRY.BoundImport)));
            sb.AppendLine(string.Format("\t{0}", ImportAddressTableDirectory.ToString(PE_DATA_DIRECTORY_ENTRY.ImportAddressTable)));
            sb.AppendLine(string.Format("\t{0}", DelayImportDirectory.ToString(PE_DATA_DIRECTORY_ENTRY.DelayImport)));
            sb.AppendLine(string.Format("\t{0}", CLRDirectory.ToString(PE_DATA_DIRECTORY_ENTRY.CLR)));
            sb.AppendLine(string.Format("\t{0}", Reserved.ToString(PE_DATA_DIRECTORY_ENTRY.Reserved)));

            return sb.ToString();
        }
    }
}
