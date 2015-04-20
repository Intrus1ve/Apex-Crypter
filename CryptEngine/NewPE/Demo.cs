using System;
using System.Collections.Generic;

using CryptEngine.Constructors;

using CryptEngine.NewPE;
using CryptEngine.NewPE.Structs;
using System.IO;

namespace CryptEngine.NewPE
{
    class Demo
    {
        void DemoRun()
        {
            //string RootDir = "X:\\Crypt PE\\ASM New";

            //NewPE PE = new NewPE();

            ////PE.PeDirectory = PEDirectory.SetRootPath(RootDir);

            //PE.ConstructDosHeader();
            //PE.WriteDosHeader();
            //PE.WriteRichSignature();

            //string TlsCallbackInc = Path.Combine(PE.PeDirectory.IncludeDirectory, "tls_callback.inc");

            //JunkCodeConstructor junkConstructor = new JunkCodeConstructor();
            //junkConstructor.WriteLogicalFunctionsToTextSection(PE.PeDirectory.TextSectionPath, 1);
            //junkConstructor.WriteLogicalTrashToTLSCallback(TlsCallbackInc, 1);

            //ImportConstructor impConstructor = new ImportConstructor(PE.PeDirectory.ImportsDirectory);
            //impConstructor.RandomizeImportTable();
            //impConstructor.FreeModules();

            //PEFactory.CompileIDataSection(PE);
            //PEFactory.CompileDataSection(PE);
            //PEFactory.CompileRunPESection(PE);
            //PEFactory.CompileTLSSection(PE);

        }
    }
}
