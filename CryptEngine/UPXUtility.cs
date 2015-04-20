using CryptEngine.Extensions;
using System.Diagnostics;
using System.IO;

namespace CryptEngine
{
    public class UPXUtility
    {
        public static void UPXCompress(ref byte[] Buffer, string OptDir)
        {
            byte[] OrigBuffer = Buffer;

            string OrigBufferPath = Path.Combine(OptDir, Path.GetRandomFileName());
            Buffer.WriteFileBytes(OrigBufferPath);

            string UPXPath = Path.Combine(OptDir, "upx.exe");

            ProcessStartInfo PSI = new ProcessStartInfo();
            PSI.Arguments = OrigBufferPath;
            PSI.CreateNoWindow = true;
            PSI.FileName = UPXPath;
            PSI.WindowStyle = ProcessWindowStyle.Hidden;

            Process.Start(PSI).WaitForExit();

            byte[] XPressBuffer = File.ReadAllBytes(OrigBufferPath);

            if (XPressBuffer.Length < OrigBuffer.Length)
                Buffer = XPressBuffer;
            else
                Buffer = OrigBuffer;
        }
    }
}
