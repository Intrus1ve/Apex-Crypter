using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace CryptEngine.Extensions
{
    public static class ArrayExtensions
    {
        public static string ToASMBuffer(this byte[] bArray)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("db  ");

            for (int i = 0; i < bArray.Length; i++)
            {
                if (i % 16 == 0 && i != 0)
                {
                    sb.Append("db  ");
                    sb.Append(String.Concat("0x", bArray[i].ToString("X2"), ", "));
                }
                else if ((i + 1) % 16 == 0)
                {
                    sb.Append(String.Concat("0x", bArray[i].ToString("X2")));
                    sb.AppendLine();
                }
                else
                {
                    if (i == bArray.Length - 1)
                        sb.Append(String.Concat("0x", bArray[i].ToString("X2")));
                    else
                        sb.Append(String.Concat("0x", bArray[i].ToString("X2"), ", "));
                }
            }

            return sb.ToString();
        }

        public static void WriteFileBytes(this byte[] bArray, string sPath)
        {
            File.WriteAllBytes(sPath, bArray);
        }
    }
}
