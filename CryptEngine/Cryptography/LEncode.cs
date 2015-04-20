using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;

namespace CryptEngine.Cryptography
{
    public class LEncode
    {
        [DllImport("CENative.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool LowEntropyEncode(string InFile, string OutFile);

        public static byte[] Encode(byte[] Data)
        {
            string File_1 = Path.GetTempFileName();
            string File_2 = Path.GetTempFileName();

            File.WriteAllBytes(File_1, Data);

            bool ret = LowEntropyEncode(File_1, File_2);

            if (File.Exists(File_2) && ret)
            {
                File.Delete(File_1);
                byte[] bb = File.ReadAllBytes(File_2);
                File.Delete(File_2);
                return bb;
            }
            else
            {
                File.Delete(File_1);
                File.Delete(File_2);
                return null;
            }
        }
    }
}
