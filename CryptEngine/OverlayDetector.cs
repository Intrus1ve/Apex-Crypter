using CryptEngine.Extensions;
using System;
using System.IO;

namespace CryptEngine
{
    public class PEOverlay
    {

        public bool HasOverlay { get; private set; }

        public byte[] OverlayData { get; private set; }

        public PEOverlay(string FilePath)
        {
            byte[] pFileBytes = FilePath.ReadBytes();
            if (null != pFileBytes)
                SetOverlayData(pFileBytes);
        }

        public void AppendOverlayDataToFile(string DestFile)
        {
            byte[] pDestBuffer = DestFile.ReadBytes();
            byte[] pFinalBuffer = new byte[pDestBuffer.Length + OverlayData.Length];

            Buffer.BlockCopy(pDestBuffer, 0, pFinalBuffer, 0, pDestBuffer.Length);
            Buffer.BlockCopy(OverlayData, 0, pFinalBuffer, pDestBuffer.Length, OverlayData.Length);

            if (File.Exists(DestFile))
                File.Delete(DestFile);

            DestFile.WriteFile(pFinalBuffer);
        }

        private void SetOverlayData(byte[] fileBuffer)
        {
            int fAddr = BitConverter.ToInt32(fileBuffer, 60); // e_lfanew
            short nSectCount = BitConverter.ToInt16(fileBuffer, fAddr + 6); // NumberOfSections
            int sectAddr = (40 * (nSectCount - 1)) + fAddr + 248; // SectionAddress (Last)
            int sectRawAddr = BitConverter.ToInt32(fileBuffer, sectAddr + 20); // RawAddress
            int sectRawSize = BitConverter.ToInt32(fileBuffer, sectAddr + 16); // RawSize
            int eofLen = fileBuffer.Length - (sectRawAddr + sectRawSize); // length of overlay

            if (eofLen > 0)
            {   /* has overlay */
                byte[] pOverlayData = new byte[eofLen];
                Buffer.BlockCopy(fileBuffer, sectRawAddr + sectRawSize, pOverlayData, 0, eofLen);
                HasOverlay = true;
                OverlayData = pOverlayData;
            }
            else
            {   /* does not have overlay */
                HasOverlay = false;
                OverlayData = null;
            }
        }
    }
}
