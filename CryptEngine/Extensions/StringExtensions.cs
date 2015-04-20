using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace CryptEngine.Extensions
{

    public enum StringEncoding
    {
        ASCII,
        UNICODE
    }

    public static class StringExtensions
    {
        public static byte[] ReadBytes(this string strPath)
        {
            if (File.Exists(strPath))
                return File.ReadAllBytes(strPath);
            else return null;
        }
        public static string ReadText(this string strPath)
        {
            if (File.Exists(strPath))
                return File.ReadAllText(strPath);
            else return null;
        }

        public static string[] ReadLines(this string strPath)
        {
            if (File.Exists(strPath))
                return File.ReadAllLines(strPath);
            else return null;
        }
        public static void WriteFile(this string strPath, byte[] Bytes)
        {
            File.WriteAllBytes(strPath, Bytes);
        }
        public static void WriteText(this string strPath, string Text, StringEncoding _Encoding)
        {
            if (_Encoding == StringEncoding.ASCII)
                File.WriteAllText(strPath, Text, Encoding.ASCII);
            if (_Encoding == StringEncoding.UNICODE)
                File.WriteAllText(strPath, Text, Encoding.Unicode);
        }
        public static void WriteLines(this string strPath, string[] Lines)
        {
            File.WriteAllLines(strPath, Lines);
        }

    }
}
