using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace CryptEngine.Misc
{
    public static class CertSpoofer
    {
        private static string SelectRandomCert(string Dir)
        {
            string[] certs = Directory.GetFiles(Dir).Where(x => Path.GetExtension(x).Contains("cert")).ToArray();
            Random R = new Random(Guid.NewGuid().GetHashCode());
            int index = R.Next(0, certs.Length);
            return certs[index];
        }

        public static bool SpoofCert(string InputFile, string CertDirectory)
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            // <--- Init ProcStartInfo --->
            psi.Arguments = String.Format("-file \"{0}\" -addds \"{1}\" -out \"{0}\"", InputFile, SelectRandomCert(CertDirectory));
            psi.FileName = Path.Combine(CertDirectory, "fakeds.exe");
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;

            using (Process proc = Process.Start(psi))
            {
                using (StreamReader sReader = proc.StandardOutput)
                {
                    string result = sReader.ReadToEnd();
                    if (result.Contains("OK"))
                        return true;
                    else return false;
                }
            }
        }
    }
}
