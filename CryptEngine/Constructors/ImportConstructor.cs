using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using CryptEngine.Extensions;

namespace CryptEngine.Constructors
{
    public class ImportConstructor
    {

        [DllImport("Kernel32.dll")]
        private static extern IntPtr LoadLibraryEx([MarshalAs(UnmanagedType.LPStr)]string szLibName, IntPtr hFile, [MarshalAs(UnmanagedType.I4)] int dwFlags);

        [DllImport("Kernel32.dll")]
        private static extern IntPtr LoadLibraryA([MarshalAs(UnmanagedType.LPStr)]string szLibName);

        [DllImport("Kernel32.dll")]
        private static extern IntPtr FreeLibrary(IntPtr hLib);

        [DllImport("Kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hLib, [MarshalAs(UnmanagedType.LPStr)]string szFuncName);

        #region Structs

        [StructLayout(LayoutKind.Sequential)]
        private struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;       // Magic number
            public UInt16 e_cblp;    // Bytes on last page of file
            public UInt16 e_cp;      // Pages in file
            public UInt16 e_crlc;    // Relocations
            public UInt16 e_cparhdr;     // Size of header in paragraphs
            public UInt16 e_minalloc;    // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
            public UInt16 e_ss;      // Initial (relative) SS value
            public UInt16 e_sp;      // Initial SP value
            public UInt16 e_csum;    // Checksum
            public UInt16 e_ip;      // Initial IP value
            public UInt16 e_cs;      // Initial (relative) CS value
            public UInt16 e_lfarlc;      // File address of relocation table
            public UInt16 e_ovno;    // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;    // Reserved words
            public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;     // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;    // Reserved words
            public Int32 e_lfanew;      // File address of new exe header

            private string _e_magic
            {
                get { return new string(e_magic); }
            }

            public bool isValid
            {
                get { return _e_magic == "MZ"; }
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS32
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public char[] Signature;

            [FieldOffset(4)]
            public IMAGE_FILE_HEADER FileHeader;

            [FieldOffset(24)]
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;

            private string _Signature
            {
                get { return new string(Signature); }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        public enum MachineType : ushort
        {
            Native = 0,
            I386 = 0x014c,
            Itanium = 0x0200,
            x64 = 0x8664
        }
        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }
        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14

        }
        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            [FieldOffset(24)]
            public uint BaseOfData;

            [FieldOffset(28)]
            public uint ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public uint SizeOfStackReserve;

            [FieldOffset(76)]
            public uint SizeOfStackCommit;

            [FieldOffset(80)]
            public uint SizeOfHeapReserve;

            [FieldOffset(84)]
            public uint SizeOfHeapCommit;

            [FieldOffset(88)]
            public uint LoaderFlags;

            [FieldOffset(92)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(96)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(104)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_EXPORT_DIRECTORY
        {
            public UInt32 Characteristics;
            public UInt32 TimeDateStamp;
            public UInt16 MajorVersion;
            public UInt16 MinorVersion;
            public UInt32 Name;
            public UInt32 Base;
            public UInt32 NumberOfFunctions;
            public UInt32 NumberOfNames;
            public UInt32 AddressOfFunctions;     // RVA from base of image
            public UInt32 AddressOfNames;     // RVA from base of image
            public UInt32 AddressOfNameOrdinals;  // RVA from base of image
        }

        #endregion

        private struct ImportDLL
        {
            public IntPtr LoadedAddress;
            public string ModuleName;
            public string ModulePath;
            public IDictionary<string, IntPtr> Functions;
        }

        IList<ImportDLL> XP_DLLS;
        // IList<ImportDLL> WIN8_DLLS;

        private static Dictionary<string, List<string>> ImportTable;

        private static Random Rand = new Random(Guid.NewGuid().GetHashCode());

        private static string ImportDirectory;

        public ImportConstructor(string _ImportDirectory)
        {
            ImportTable = new Dictionary<string, List<string>>();

            XP_DLLS = new List<ImportDLL>();
            // WIN8_DLLS = new List<ImportDLL>();

            ImportDirectory = _ImportDirectory;

        }

        public unsafe int RandomizeImportTable()
        {
            string[] xp_dll_paths = Directory.GetFiles(ImportDirectory).Where(file => Path.GetExtension(file) == ".dll").ToArray();

            for (int i = 0; i < xp_dll_paths.Length; i++)
            {
                ImportDLL xp_dll = new ImportDLL();
                // ImportDLL win8_dll = new ImportDLL();

                // xp
                xp_dll.ModulePath = xp_dll_paths[i];
                xp_dll.ModuleName = Path.GetFileNameWithoutExtension(xp_dll.ModulePath).ToUpper();
                xp_dll.LoadedAddress = LoadLibraryEx(xp_dll.ModulePath, IntPtr.Zero, 0x1);
                xp_dll.Functions = new Dictionary<string, IntPtr>();
                XP_DLLS.Add(xp_dll);

                // win8
                //win8_dll.ModuleName = xp_dll.ModuleName;
                //win8_dll.ModulePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86), win8_dll.ModuleName);
                //win8_dll.LoadedAddress = LoadLibraryEx(win8_dll.ModulePath, IntPtr.Zero, 0x00000001);
                //win8_dll.Functions = new Dictionary<string, IntPtr>();
                //WIN8_DLLS.Add(win8_dll);
            }

            // walk exports to find functions to use
            foreach (ImportDLL IDLL in XP_DLLS)
            {
                IMAGE_DOS_HEADER pIDH = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(IDLL.LoadedAddress, typeof(IMAGE_DOS_HEADER));
                IMAGE_NT_HEADERS32 pINH = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure((IntPtr)(IDLL.LoadedAddress + pIDH.e_lfanew), typeof(IMAGE_NT_HEADERS32));
                IMAGE_DATA_DIRECTORY ExportDirectory = pINH.OptionalHeader.ExportTable;
                IMAGE_EXPORT_DIRECTORY pIED = (IMAGE_EXPORT_DIRECTORY)Marshal.PtrToStructure(((IntPtr)IDLL.LoadedAddress + (int)ExportDirectory.VirtualAddress), typeof(IMAGE_EXPORT_DIRECTORY));

                int NumberOfNamedFunctions = (int)pIED.NumberOfNames;

                uint* lpAddressOfNames = (uint*)(IDLL.LoadedAddress + (int)pIED.AddressOfNames);
                uint* lpAddressOfFunctions = (uint*)(IDLL.LoadedAddress + (int)pIED.AddressOfFunctions);
                uint* lpAddressOfNameOrdinals = (uint*)(IDLL.LoadedAddress + (int)pIED.AddressOfNameOrdinals);

                for (int i = 0; i < NumberOfNamedFunctions; i++)
                {
                    uint lpFuncNameRVA = lpAddressOfNames[i];
                    char* szFuncName = (char*)(IDLL.LoadedAddress + (int)lpFuncNameRVA);
                    string FuncName = Marshal.PtrToStringAnsi((IntPtr)szFuncName);

                    IDLL.Functions.Add(FuncName, GetProcAddress(IDLL.LoadedAddress, FuncName));
                }
            }

            // generate random amount of modules of which to select the functions from
            int ModuleCount = Rand.Next(2, 4);

            List<ImportDLL> AllModules = new List<ImportDLL>();
            List<ImportDLL> SelectedModules = new List<ImportDLL>();

            foreach (ImportDLL IDLL in XP_DLLS)
                AllModules.Add(IDLL);

            // Base modules
            //SelectedModules.Add(XP_DLLS.Where(DLL => DLL.ModuleName == "KERNEL32").First());
            //SelectedModules.Add(XP_DLLS.Where(DLL => DLL.ModuleName == "USER32").First());
            //SelectedModules.Add(XP_DLLS.Where(DLL => DLL.ModuleName == "GDI32").First());
            //SelectedModules.Add(XP_DLLS.Where(DLL => DLL.ModuleName == "OLEAUT32").First());
            //SelectedModules.Add(XP_DLLS.Where(DLL => DLL.ModuleName == "MSVCRT").First());
            // Randomize modules
            SelectedModules.AddRange(AllModules.OrderBy(x => Rand.Next()).Take(ModuleCount).ToList());

            // Remove any overlapping modules
            SelectedModules = SelectedModules.Distinct().ToList();
            SelectedModules = SelectedModules.OrderBy(x => Rand.Next()).ToList();

            // ensure compatability of each imported module function
            foreach (ImportDLL IDLL in SelectedModules)
            {
                int NumberOfFunctions = Rand.Next(60, 90); // IDLL.Functions.Count; // Rand.Next(IDLL.Functions.Count / 16, IDLL.Functions.Count / 12);

                //if (NumberOfFunctions < 50)
                //    NumberOfFunctions = Rand.Next(IDLL.Functions.Count / 4, IDLL.Functions.Count / 2);
                //else if (NumberOfFunctions > 50 && NumberOfFunctions < 100)
                //    NumberOfFunctions = Rand.Next(IDLL.Functions.Count / 8, IDLL.Functions.Count / 4);
                //else if (NumberOfFunctions > 100 && NumberOfFunctions < 200)
                //    NumberOfFunctions = Rand.Next(IDLL.Functions.Count / 12, IDLL.Functions.Count / 4);
                //else if (NumberOfFunctions > 200 && NumberOfFunctions < 400)
                //    NumberOfFunctions = Rand.Next(IDLL.Functions.Count / 16, IDLL.Functions.Count / 8);
                //else if (NumberOfFunctions > 400)
                //    NumberOfFunctions = Rand.Next(IDLL.Functions.Count / 8, IDLL.Functions.Count / 4);

                //if (NumberOfFunctions == 0)
                //    NumberOfFunctions += 1;

                var SelectedFunctions = IDLL.Functions.OrderBy(x => Rand.Next()).Take(NumberOfFunctions);
                List<string> CheckedFunctions = new List<string>();

                foreach (var Function in SelectedFunctions)
                {
                    IntPtr hCorrespondingLib = LoadLibraryA(IDLL.ModuleName);
                    IntPtr pFuncCheck = GetProcAddress(hCorrespondingLib, Function.Key);

                    if (null != pFuncCheck && pFuncCheck != IntPtr.Zero && !IsBlacklisted(Function.Key))
                        CheckedFunctions.Add(Function.Key);
                    else
                        Console.WriteLine("bad function {0}", Function.Key);

                    FreeLibrary(hCorrespondingLib);
                }

                ImportTable.Add(IDLL.ModuleName, CheckedFunctions);
            }

            return SelectedModules.Count;
        }

        public unsafe void FreeModules()
        {
            foreach (ImportDLL IDLL in XP_DLLS)
                FreeLibrary(IDLL.LoadedAddress);
        }

        public static bool IsBlacklisted(string pszFunction)
        {
            string[] cock = Path.Combine(ImportDirectory, "blacklist.xml").ReadLines();
            pszFunction = pszFunction.TrimEnd('A', 'W');

            for (int i = 0; i < cock.Length; i++)
            {
                if (cock[i].Contains(pszFunction) && cock[i].Contains("bl=\"1\""))
                    return true;
            }
            return false;
        }

        public void ConstructSectionSource(string SavePath)
        {
            string Template = Properties.Resources.Template;

            string ModuleTemplate = Properties.Resources.IMPORT_MODULE_TEMPLATE;
            string InfoTemplate = Properties.Resources.IMPORT_INFO_TEMPLATE;

            string mod_ModuleTemplate = ModuleTemplate;
            string mod_InfoTemplate = InfoTemplate;

            string func_def = String.Concat(".str#FUNC#: db 0, 0, ", '"', "#FUNC#", '"', ", 0");
            string func_name_def = "dd .str#FUNC#";
            string func_adr_def = "dd .#FUNC#";
            string func_adr_def_two = ".#FUNC#:     dd 0";

            foreach (string Module in ImportTable.Keys)
            {
                string libName = Module;

                mod_ModuleTemplate = ModuleTemplate;
                mod_InfoTemplate = InfoTemplate;

                mod_ModuleTemplate = mod_ModuleTemplate.Replace("#MODULENAME#", libName);
                mod_InfoTemplate = mod_InfoTemplate.Replace("#MODULENAME#", libName);

                foreach (string function in ImportTable[Module])
                {
                    int index_func_def = mod_InfoTemplate.IndexOf(func_def);
                    mod_InfoTemplate = mod_InfoTemplate.Insert(index_func_def, String.Concat("\t\t", func_def.Replace("#FUNC#", function)));
                    mod_InfoTemplate = mod_InfoTemplate.Insert(index_func_def, "\n");

                    int index_func_name_list = mod_InfoTemplate.IndexOf(func_name_def);
                    mod_InfoTemplate = mod_InfoTemplate.Insert(index_func_name_list, String.Concat("\t\t\t", func_name_def.Replace("#FUNC#", function)));
                    mod_InfoTemplate = mod_InfoTemplate.Insert(index_func_name_list, "\n");

                    int index_func_adr = mod_InfoTemplate.IndexOf(func_adr_def);
                    mod_InfoTemplate = mod_InfoTemplate.Insert(index_func_adr, String.Concat("\t\t\t", func_adr_def.Replace("#FUNC#", function)));
                    mod_InfoTemplate = mod_InfoTemplate.Insert(index_func_adr, "\n");

                    int index_func_two = mod_InfoTemplate.IndexOf(func_adr_def_two);
                    mod_InfoTemplate = mod_InfoTemplate.Insert(index_func_two, String.Concat("\t\t\t", func_adr_def_two.Replace("#FUNC#", function)));
                    mod_InfoTemplate = mod_InfoTemplate.Insert(index_func_two, "\n");
                }

                Template = Template.Insert(Template.IndexOf("#IMPORT_MODULE#"), mod_ModuleTemplate);
                Template = Template.Insert(Template.IndexOf("#IMPORT_MODULE#"), Environment.NewLine);
                Template = Template.Insert(Template.IndexOf("#IMPORT_INFO#"), mod_InfoTemplate);
                Template = Template.Insert(Template.IndexOf("#IMPORT_INFO#"), Environment.NewLine);
            }

            Template = Template.Replace(func_def, String.Empty);
            Template = Template.Replace(func_name_def, String.Empty);
            Template = Template.Replace(func_adr_def, String.Empty);
            Template = Template.Replace(func_adr_def_two, String.Empty);

            Template = Template.Replace("#IMPORT_MODULE#", String.Empty);
            Template = Template.Replace("#IMPORT_INFO#", String.Empty);

            Template = Template.TrimEnd();

            if (File.Exists(SavePath))
                File.Delete(SavePath);

            File.WriteAllText(SavePath, Template);

        }
    }
}
