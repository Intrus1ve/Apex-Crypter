using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CryptEngine.Structures
{
    public struct InnerStub
    {  
        public byte[] Payload;
        public byte[] XorPayload;
        public byte[] EncodePayload;
        public byte[] PayloadKey;

        public byte[] RunPE;
        public byte[] XorRunPE;
        public byte[] RunPEKey; 
        public string RunPEPath;

        public bool UseUPX;
        public bool DelayExecution;
        public bool PolymorphicDecryptor;
    }
}
