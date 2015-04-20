using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using CryptEngine.Extensions;

namespace CryptEngine.Constructors
{
    public class TimeDateStampConstructor
    {

        private static Random Rand = new Random(Guid.NewGuid().GetHashCode());

        private long GenTDS()
        {
            return Rand.Next(0x40000000, 0x52D95C3A);
        }

        public void ConstructUniqueTimeDateStamp(string FilePath)
        {
            string tFile = FilePath.ReadText();
            tFile = tFile.Replace("[TIME_DATE_STAMP]", "0x" + GenTDS().ToString("X8"));
            FilePath.WriteText(tFile, StringEncoding.UNICODE);
        }
    }
}
