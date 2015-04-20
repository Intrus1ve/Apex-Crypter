using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CryptEngine.Cryptography
{
    public class Xor
    {
        public static void EncodeDecodeData(byte[] Src, byte[] Key)
        {
            for (int i = 0; i < Src.Length; i++)
                    Src[i] ^= Key[i % Key.Length];
            //RC4(ref Src, Key);
        }

        private static void RC4(ref Byte[] bytes, Byte[] key)
        {
            Byte[] s = new Byte[256];
            Byte[] k = new Byte[256];
            Byte temp;
            int i, j;

            for (i = 0; i < 256; i++)
            {
                s[i] = (Byte)i;
                k[i] = key[i % key.GetLength(0)];
            }

            j = 0;
            for (i = 0; i < 256; i++)
            {
                j = (j + s[i] + k[i]) % 256;
                temp = s[i];
                s[i] = s[j];
                s[j] = temp;
            }

            i = j = 0;
            for (int x = 0; x < bytes.GetLength(0); x++)
            {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;
                temp = s[i];
                s[i] = s[j];
                s[j] = temp;
                int t = (s[i] + s[j]) % 256;
                bytes[x] ^= s[t];
            }
        }

        public static void EncodeDecodeData(byte[] Src, byte[] Dst, byte[] Key)
        {
            for (int i = 0; i < Src.Length; i++)
                Dst[i] = (byte)(Src[i] ^ Key[i % Key.Length]);
        }
    }
}
