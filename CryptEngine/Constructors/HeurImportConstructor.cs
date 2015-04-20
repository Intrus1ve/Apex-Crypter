using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CryptEngine.NewPE;
using System.IO;
using CryptEngine.Extensions;
using System.Runtime.InteropServices;

namespace CryptEngine.Constructors
{
    public static class HeurImportConstructor
    {
        public struct ImportedDLL
        {
            /// <summary>
            /// Name of the imported module (kernel32.dll, gdi32.dll, etc...)
            /// </summary>
            public string DLL_NAME;

            /// <summary>
            /// Total number of unique imported functions found in the EXEs scanned
            /// </summary>
            public int DLL_IMPORTED_FUNCTION_COUNT;

            /// <summary>
            /// Percentage that the module is found in exe scanned
            /// </summary>
            public double DLL_PR_FOUND_IN_EXE;

            /// <summary>
            /// Percentage of total functions in a pe that has this module make up of
            /// </summary>
            public double DLL_PR_TOTAL_FUNC_IN_EXE;

            /// <summary>
            /// Abstraction of imported functions present 
            /// </summary>
            public List<ImportedFUNC> DLL_IMPORTED_FUNCTIONS;
        }

        public struct ImportedFUNC
        {
            /// <summary>
            /// Name of imported function
            /// </summary>
            public string FUNC_NAME;

            /// <summary>
            /// Percentage of this imported function when parent module is imported
            /// </summary>
            public double FUNC_PR_FOR_CURRENT_MODULE;

            /// <summary>
            /// Percentage of this imported function in relation to all exe scanned
            /// </summary>
            public double FUNC_PR_ALL_EXE;
        }

        public static List<ImportedDLL> ParseImportTableLog()
        {
            string[] lines_log = (Properties.Resources._01).Split(Environment.NewLine.ToCharArray(), StringSplitOptions.RemoveEmptyEntries);

            List<ImportedDLL> import_info = new List<ImportedDLL>();

            int module_count = 1;
            int total_func_count = 1;

            for (int i = 0; i < lines_log.Length; i++)
            {
                if (lines_log[i] == Convert.ToString(module_count) &&
                        (lines_log[i + 1].Contains(".dll") || lines_log[i + 1].Contains(".drv") || lines_log[i + 1].Contains(".exe")))
                {
                    ImportedDLL imp_dll = new ImportedDLL();
                    imp_dll.DLL_IMPORTED_FUNCTIONS = new List<ImportedFUNC>();

                    imp_dll.DLL_NAME = lines_log[++i];
                    ++i;
                    imp_dll.DLL_IMPORTED_FUNCTION_COUNT = Int32.Parse(lines_log[++i]);
                    ++i;
                    imp_dll.DLL_PR_FOUND_IN_EXE = Double.Parse(lines_log[++i].TrimEnd('%'));
                    imp_dll.DLL_PR_TOTAL_FUNC_IN_EXE = Double.Parse(lines_log[++i].TrimEnd('%'));
                    ++i;
                    module_count++;

                    int func_count = 1;

                __continue_fill:
                    {
                        for (int x = i; x < (i + (6 * imp_dll.DLL_IMPORTED_FUNCTION_COUNT)); x++)
                        {
                            if (lines_log[x] == string.Concat(func_count, " | ", total_func_count))
                            {
                                ImportedFUNC imp_func = new ImportedFUNC();
                                imp_func.FUNC_NAME = lines_log[++x];
                                ++x;
                                imp_func.FUNC_PR_FOR_CURRENT_MODULE = Double.Parse(lines_log[++x].TrimEnd('%'));
                                imp_func.FUNC_PR_ALL_EXE = Double.Parse(lines_log[++x].TrimEnd('%'));
                                ++x;
                                imp_dll.DLL_IMPORTED_FUNCTIONS.Add(imp_func);
                                func_count++;
                                total_func_count++;

                                goto __continue_fill;
                            }
                        }
                    }

                    import_info.Add(imp_dll);
                }
            }

            // check for ordinals
            //List<ImportedDLL> non_ordinal_import_info = new List<ImportedDLL>();

            // okay
            // i need to remove all instances of 
            // import_info -> DLLS -> Imported Functions -> Where Imported Function.Name.StartsWith("0x")

            foreach (ImportedDLL DLL in import_info)
            {
                ImportedFUNC[] items = DLL.DLL_IMPORTED_FUNCTIONS.Where(a => a.FUNC_NAME.StartsWith("0x")).ToArray<ImportedFUNC>();
                foreach (ImportedFUNC i in items) DLL.DLL_IMPORTED_FUNCTIONS.Remove(i);
            }

            import_info = import_info.Where(X => !X.DLL_NAME.Contains("oleaut32.dll")).ToList<ImportedDLL>();
            import_info = import_info.Where(X => !X.DLL_NAME.Contains("atl.dll")).ToList<ImportedDLL>();
            import_info = import_info.Where(X => !X.DLL_NAME.Contains("msvcrt.dll")).ToList<ImportedDLL>();

            return import_info;
        }

        public static void CreateHeurImportTable(List<ImportedDLL> input)
        {
            Random R = new Random(Guid.NewGuid().GetHashCode());
            Dictionary<string, List<string>> ret = new Dictionary<string, List<string>>();

            // Has 4 <-> 8 imported DLLs
            int count_imported_modules = R.Next(2, 4);

            // Total number of imported functions
            int count_imported_functions = R.Next(10, 30);

            // Select n dlls above x percentile threshold
            double x = 0.25;
            var imported_modules = input.Where(DLL => DLL.DLL_PR_FOUND_IN_EXE >= x).OrderBy(XX => R.Next()).Take(count_imported_modules).ToArray();

            foreach (var lib in imported_modules)
            {
                List<string> funcs = new List<string>();

                int func_count = (int)((count_imported_functions * lib.DLL_PR_TOTAL_FUNC_IN_EXE) / 100) + R.Next(5, 12);

                // func threshold
                double y = 0.8;

                var __funcs = lib.DLL_IMPORTED_FUNCTIONS.Where(FUNC => FUNC.FUNC_PR_FOR_CURRENT_MODULE >= y).OrderBy(RR => R.Next()).Take(func_count).ToArray();
                foreach (var func_item in __funcs)
                {
                    if (CheckWorkingFunction(lib.DLL_NAME, func_item.FUNC_NAME))
                        funcs.Add(func_item.FUNC_NAME);
                }

                if (funcs.Count > 0)
                    ret.Add(lib.DLL_NAME, funcs);
            }

            ImportTable = ret;
        }

        [DllImport("Kernel32.dll")]
        private static extern IntPtr LoadLibraryA([MarshalAs(UnmanagedType.LPStr)]string szLibName);

        [DllImport("Kernel32.dll")]
        private static extern IntPtr FreeLibrary(IntPtr hLib);

        [DllImport("Kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hLib, [MarshalAs(UnmanagedType.LPStr)]string szFuncName);

        private static bool CheckWorkingFunction(string Mod, string Func)
        {
            IntPtr hLib = LoadLibraryA(Mod);

            IntPtr hFunc = GetProcAddress(hLib, Func);

            if (hFunc == IntPtr.Zero)
            {
                FreeLibrary(hLib);
                return false;
            }

            FreeLibrary(hLib);
            return true;
        }

        private static Dictionary<string, List<string>> ImportTable;

        public static void ConstructSectionSource(string SavePath)
        {
            string Template = Properties.Resources.Template;

            string ModuleTemplate = Properties.Resources.IMPORT_MODULE_TEMPLATE;
            string InfoTemplate = Properties.Resources.IMPORT_INFO_TEMPLATE;

            string mod_ModuleTemplate = ModuleTemplate;
            string mod_InfoTemplate = InfoTemplate;

            string func_def = String.Concat(".str#FUNC#: db 0, 0, ", '"', "#FUNC#", '"', ", 0");
            string func_name_def = "dd .str#FUNC#";
            string func_adr_def = "dd .#FUNC#";
            string func_adr_def_two = ".#FUNC#:     dd 0";

            foreach (string Module in ImportTable.Keys)
            {
                string libName = Module;
                string libWOSuffix = libName.Substring(0, libName.Length - 4).ToUpper();
                string libSuffix = libName.Substring(libName.Length - 4, 4);
                libName = String.Concat(libWOSuffix, libSuffix);

                mod_ModuleTemplate = ModuleTemplate;
                mod_InfoTemplate = InfoTemplate;

                mod_ModuleTemplate = mod_ModuleTemplate.Replace("#MODULENAME#", libName);
                mod_InfoTemplate = mod_InfoTemplate.Replace("#MODULENAME#", libName);

                foreach (string function in ImportTable[Module])
                {
                    int index_func_def = mod_InfoTemplate.IndexOf(func_def);
                    mod_InfoTemplate = mod_InfoTemplate.Insert(index_func_def, String.Concat("\t\t", func_def.Replace("#FUNC#", function)));
                    mod_InfoTemplate = mod_InfoTemplate.Insert(index_func_def, "\n");

                    int index_func_name_list = mod_InfoTemplate.IndexOf(func_name_def);
                    mod_InfoTemplate = mod_InfoTemplate.Insert(index_func_name_list, String.Concat("\t\t\t", func_name_def.Replace("#FUNC#", function)));
                    mod_InfoTemplate = mod_InfoTemplate.Insert(index_func_name_list, "\n");

                    int index_func_adr = mod_InfoTemplate.IndexOf(func_adr_def);
                    mod_InfoTemplate = mod_InfoTemplate.Insert(index_func_adr, String.Concat("\t\t\t", func_adr_def.Replace("#FUNC#", function)));
                    mod_InfoTemplate = mod_InfoTemplate.Insert(index_func_adr, "\n");

                    int index_func_two = mod_InfoTemplate.IndexOf(func_adr_def_two);
                    mod_InfoTemplate = mod_InfoTemplate.Insert(index_func_two, String.Concat("\t\t\t", func_adr_def_two.Replace("#FUNC#", function)));
                    mod_InfoTemplate = mod_InfoTemplate.Insert(index_func_two, "\n");
                }

                Template = Template.Insert(Template.IndexOf("#IMPORT_MODULE#"), mod_ModuleTemplate);
                Template = Template.Insert(Template.IndexOf("#IMPORT_MODULE#"), Environment.NewLine);
                Template = Template.Insert(Template.IndexOf("#IMPORT_INFO#"), mod_InfoTemplate);
                Template = Template.Insert(Template.IndexOf("#IMPORT_INFO#"), Environment.NewLine);
            }

            Template = Template.Replace(func_def, String.Empty);
            Template = Template.Replace(func_name_def, String.Empty);
            Template = Template.Replace(func_adr_def, String.Empty);
            Template = Template.Replace(func_adr_def_two, String.Empty);

            Template = Template.Replace("#IMPORT_MODULE#", String.Empty);
            Template = Template.Replace("#IMPORT_INFO#", String.Empty);

            Template = Template.TrimEnd();

            if (File.Exists(SavePath))
                File.Delete(SavePath);

            File.WriteAllText(SavePath, Template);

        }
    }
}
