using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics;

using CryptEngine.Extensions;
using xNewPE = CryptEngine.NewPE.NewPE;
using System.IO;
using System.Globalization;

///
//
// HOLY FUCK THIS SHIT IS NOT 10% DONE LMFAO IT WONT EXECUTE 
//
///

namespace CryptEngine.Constructors
{
    public class WinAPIConstructor
    {
        private xNewPE PE;
        private Random Rand;

        public WinAPIConstructor(xNewPE _PE)
        {
            PE = _PE;
            Rand = new Random(Guid.NewGuid().GetHashCode());
        }

        public void InitializeIATList()
        {
            //nasm -f bin idata.asm -o idata.o -l idata.lst

            ProcessStartInfo psi = new ProcessStartInfo();
            psi.Arguments = String.Format("-i \"{0}/\" -f bin \"{1}\" -o \"{2}\" -l \"{3}\"",
                                               PE.PeDirectory.RootDirectoryPath,
                                               PE.PeDirectory.IDataSectionPath,
                                               PE.PeDirectory.IDataObjectPath,
                                               PE.PeDirectory.IATListPath);

            psi.FileName = PE.PeDirectory.CompilerPath;
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;

            using (Process Proc = Process.Start(psi))
            {
                using (StreamReader sReader = Proc.StandardOutput)
                {
                    string res = sReader.ReadToEnd();
                    Console.WriteLine(res);
                }
            }
        }

        public void CreateImportDefinitions()
        {
            string retString = "%include \"include/global_constants.inc\"\r\n%include \"include/section_addresses.inc\"";

            string[] addrLists = System.Text.RegularExpressions.Regex.Split(PE.PeDirectory.IATListPath.ReadText(), ".FUNCTION_ADDRESSES:");

            for (int i = 1; i < addrLists.Length; i++)
            {
                string[] functions_split = System.Text.RegularExpressions.Regex.Split(addrLists[i], @"^\s*([0-9]|[1-9][0-9]|[1-9][0-9][0-9]|[1-9][0-9][0-9][0-9]|[1-9][0-9][0-9][0-9][0-9])\s*$", System.Text.RegularExpressions.RegexOptions.Multiline);
                if (functions_split.Length > 2)
                {
                    string[] functions = functions_split[2].Split('\n');
                    for (int u = 1; u < functions.Length - 1; u++)
                    {
                        string function_pointer_addr = System.Text.RegularExpressions.Regex.Match(functions[u], @"([0-9A-F]{8})").Value;
                        string function_name = System.Text.RegularExpressions.Regex.Match(functions[u], @"\.[a-zA-Z0-9]*").Value.TrimStart('.');
                        retString += "\r\n" + function_name + " EQU " + "IMAGE_BASE + IDATA_SECTION_ADDRESS + 0x" + (Int32.Parse(function_pointer_addr,NumberStyles.HexNumber) - 0xb2).ToString();
                    }

                }
                retString += "\r\n";
            }

            PE.PeDirectory.IATDefPath.WriteText(retString, StringEncoding.ASCII);
        }

        const string S_PUSH = "push {0}";
        const string S_CALL = "call [{0}]";

        public void FillWinAPITrash(string filepath)
        {

            string[] lines = filepath.ReadLines();

            for (int x = 0; x < lines.Length; x++)
            {
                if (lines[x].Contains(";[WIN_API_TRASH]"))
                {
                    int num_arg = Rand.Next(1, 16);

                    StringBuilder sb = new StringBuilder();
                  
                    for (int i = 0; i < num_arg; i++)
                        sb.AppendLine(string.Format(S_PUSH, Rand.Next()));
                    
                    sb.AppendLine(string.Format(S_CALL, get_rand_func()));

                    lines[x] = sb.ToString();
                }
            }

            Path.Combine(PE.PeDirectory.IncludeDirectory, "tls_callback.inc").WriteLines(lines);
        }

        private string get_rand_func()
        {
            var lines = PE.PeDirectory.IATDefPath.ReadLines().ToList<string>();
            lines = lines.Where(line => !line.StartsWith("%")).ToList<string>();
            lines = lines.Where(line => !string.IsNullOrEmpty(line)).ToList<string>();
            int index = Rand.Next(0, lines.Count);
            return lines[index].Substring(0, lines[index].IndexOf(" "));
        }

    }
}
