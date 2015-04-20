using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CryptEngine.Cryptography
{
    public class Keys
    {
        private static RNGCryptoServiceProvider RNG = new RNGCryptoServiceProvider();

        public static void PopulateBuffer(byte[] Key)
        {
            RNG.GetNonZeroBytes(Key);
        }
    }
}
