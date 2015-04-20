using CryptEngine.Constructors;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CryptEngine.Structures
{
    public struct OutterStub
    {
        public ImportConstructor ImportCtor;
        public JunkCodeConstructor JunkCtor;
        public DataConstructor DataCtor;
        public TimeDateStampConstructor TDSCtor;

        public string SaveFileName;
        public string CloneFilePath;
        public string IconFilePath;

        public int JunkCodeMultiplier;
    }
}
