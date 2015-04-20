using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.IO;

namespace CryptEngine.Misc
{
    public static class RichSignature
    {
        [DllImport("CENative.dll")]
        private static extern IntPtr GenRich(IntPtr pMem);

        [DllImport("CENative.dll")]
        private static extern bool ChangeRich(IntPtr pMem);

        //public static bool ChangeRichSig(string file)
        //{
        //    byte[] pFile = File.ReadAllBytes(file);
            
        //    GCHandle gc = GCHandle.Alloc(file,GCHandleType.Pinned);
        //    IntPtr ptrFile = gc.AddrOfPinnedObject();

        //    if(ChangeRich(ptrFile))
        //    {

        //    }
        //}

        public static byte[] GenerateRichSignature(string file)
        {
            byte[] pFile = File.ReadAllBytes(file);

            GCHandle gc = GCHandle.Alloc(pFile, GCHandleType.Pinned);
            IntPtr ptrFile = gc.AddrOfPinnedObject();

            IntPtr rich_sig = GenRich(ptrFile);

            List<byte> sig = new List<byte>();

            for (int i = 0; i < 250; i++)
            {
                // end mask = 0x68636952
                byte[] tmp = new byte[4];
              
                Marshal.Copy(rich_sig, tmp, 0, 1);

                if (tmp[0] == 0x68)
                {
                    Marshal.Copy(rich_sig, tmp, 1, 1); // copy next byte
                    if (tmp[1] == 0x63)
                    {
                        Marshal.Copy(rich_sig, tmp, 2, 1); // next byte
                        if (tmp[2] == 0x69)
                        {
                            Marshal.Copy(rich_sig, tmp, 3, 1); // last byte
                            sig.AddRange(tmp);
                        }
                    }
                }
                else
                {
                    sig.Add(tmp[0]);
                }
            }

            gc.Free();
            return sig.ToArray();
        }

    }
}
