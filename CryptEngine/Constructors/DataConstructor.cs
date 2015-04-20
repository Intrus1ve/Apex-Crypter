using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using CryptEngine.Extensions;

namespace CryptEngine.Constructors
{
    public class DataConstructor
    {

        private static Random Rand = new Random(Guid.NewGuid().GetHashCode());

        public void ConstructHeuristicSection(string FilePath)
        {
            int XLen = Rand.Next(0x2000, 0x4000);

            int str_data_len = (XLen / 16);
            int byte_data_len = (XLen / 2);

            string str_data = GenString(str_data_len - 32, str_data_len + 32);
            byte[] byte_data = new byte[Rand.Next(0x3000, 0x5000)]; // GenHeurByte(byte_data_len - 32, byte_data_len + 32);

            byte[] final_data = WeaveData(str_data, byte_data);
            string frmt = final_data.ToASMBuffer();

            string t_file = FilePath.ReadText();
            t_file = t_file.Replace(";[DATA]", frmt);

            FilePath.WriteText(t_file, StringEncoding.ASCII);
        }

        public void DilluteSectionEntropy(string FilePath)
        {
            int fill_size = (int)(FilePath.ReadBytes().Length * ((double)Rand.Next(60, 80) / 10));

            byte[] fill_dil = new byte[fill_size];

            //chunk:
            //-----> block
            //-----> block
            //-----> block
            //chunk2:
            //------> block
            //------> block

            int num_chunks = Rand.Next(16, 32);
            int num_blocks = num_chunks * num_chunks;
            int size_block = fill_size / num_blocks;
            num_blocks /= size_block;

            List<byte[]> blocks = new List<byte[]>();

            for (int i = 0; i < num_blocks; i++)
                blocks.Add(gen_block_data(size_block));

            string str_t_sect = FilePath.ReadText();


            int index_of = str_t_sect.IndexOf(";[DATA]");

            for (int x = 0; x < num_chunks; x++)
            {
                foreach (var block in blocks)
                {
                    str_t_sect = str_t_sect.Insert(index_of, block.ToASMBuffer());
                    str_t_sect = str_t_sect.Insert(index_of, Environment.NewLine);
                }
            }


            FilePath.WriteText(str_t_sect, StringEncoding.ASCII);
        }

        private byte[] gen_block_data(int block_size)
        {
            int b_data = Rand.Next(0, 1);

            if (b_data == 1)
            { //bytes
                int d_range = Rand.Next(10, 20);
                byte b_median = (byte)Rand.Next(25, 200);
                byte[] b_ret = new byte[block_size];
                for (int i = 0; i < block_size; i++)
                    b_ret[i] = (byte)Rand.Next(b_median - d_range, b_median + d_range);
                return b_ret;
            }
            else
            { //str
                StringBuilder sb = new StringBuilder();
                char c = (char)Rand.Next(50, 150);
                int c_range = Rand.Next(10, 20);
                for (int i = 0; i < block_size; i++)
                    sb.Append((char)Rand.Next((int)(c - c_range), (int)(c + c_range)));
                byte[] b_ret = new byte[sb.ToString().Length * sizeof(char)];
                Buffer.BlockCopy(sb.ToString().ToCharArray(), 0, b_ret, 0, b_ret.Length);
                return b_ret;
            }
        }

        public byte[] GenData(int min, int max)
        {
            int XLen = Rand.Next(min, max);

            int str_data_len = (XLen / 16);
            int byte_data_len = (XLen / 2);

            string str_data = GenString(str_data_len - 32, str_data_len + 32);
            byte[] byte_data = GenHeurByte(byte_data_len - 32, byte_data_len + 32);

            byte[] final_data = WeaveData(str_data, byte_data);
            return final_data;
        }

        public void NullEntropy(string FilePath)
        {
            string t_file = FilePath.ReadText();
            t_file = t_file.Replace(";[DATA]", new byte[Rand.Next(0x1000, 0x3000)].ToASMBuffer());
            FilePath.WriteText(t_file, StringEncoding.ASCII);
        }

        private byte[] WeaveData(string str_data, byte[] b_data)
        {
            byte[] s_data = new ASCIIEncoding().GetBytes(str_data);

            int xx_len = s_data.Length + b_data.Length;
            byte[] xx = new byte[xx_len];

            Buffer.BlockCopy(s_data, 0, xx, 0, s_data.Length);
            Buffer.BlockCopy(b_data, 0, xx, s_data.Length, b_data.Length);

            var list_byte = new List<byte>(xx);

            return list_byte.OrderBy(x => Rand.Next()).ToArray();
        }

        private string GenString(int Min, int Max)
        {
            StringBuilder sb = new StringBuilder();
            int len = Rand.Next(Min, Max);
            char c = (char)Rand.Next(50, 150);
            for (int i = 0; i < len; i++)
            {
                sb.Append((char)Rand.Next((int)(c - 20), (int)(c + 20)));
            }
            return sb.ToString();
        }

        private byte[] GenHeurByte(int Min, int Max)
        {
            int len = (int)Math.Round((double)Rand.Next(Min, Max) / 4) * 4;

            List<byte> heur_bytes = new List<byte>();
            heur_bytes.Add(0x00);
            heur_bytes.Add(0xFF);

            int num_rand_heur_bytes = Rand.Next(2, 6);
            for (int i = 0; i < num_rand_heur_bytes; i++)
                heur_bytes.Add((byte)Rand.Next(50, 200));

            heur_bytes = heur_bytes.Distinct().ToList();

            int x = heur_bytes.Count;
            byte[] ret = new byte[len];
            int path = Rand.Next(1, 5);

            byte heur = heur_bytes[Rand.Next(0, x)];

            for (int jj = 0; jj < ret.Length; jj += 4)
            {
                switch (path)
                {
                    case 1:
                        {
                            // heur_byte, 0x00, 0x00, heur_byte
                            byte[] chunk = new byte[4];
                            chunk[0] = 0x00;
                            chunk[1] = 0x00;
                            chunk[2] = 0x00;
                            chunk[3] = heur;
                            Buffer.BlockCopy(chunk, 0, ret, jj, 4);
                        }
                        break;
                    case 2:
                        { // heur_byte, 0xFF, 0xFF, heur_byte
                            byte[] chunk = new byte[4];
                            chunk[0] = 0x00;
                            chunk[1] = 0x00;
                            chunk[2] = 0x00;
                            chunk[3] = heur;
                            Buffer.BlockCopy(chunk, 0, ret, jj, 4);
                        }
                        break;
                    case 3:
                        { // heur_byte, heur_byte, 0x00, 0x00
                            byte[] chunk = new byte[4];
                            chunk[0] = 0x00;
                            chunk[1] = heur;
                            chunk[2] = 0x00;
                            chunk[3] = 0x00;
                            Buffer.BlockCopy(chunk, 0, ret, jj, 4);
                        }
                        break;
                    case 4:
                        { // heur_byte, 0xFF, heur_byte, 0xFF
                            byte[] chunk = new byte[4];
                            chunk[0] = heur;
                            chunk[1] = 0x00;
                            chunk[2] = 0x00;
                            chunk[3] = 0x00;
                            Buffer.BlockCopy(chunk, 0, ret, jj, 4);
                        }
                        break;
                    case 5:
                        { // 0xFF, heur_byte, heur_byte, 0x00
                            byte[] chunk = new byte[4];
                            chunk[0] = 0x00;
                            chunk[1] = 0x00;
                            chunk[2] = heur;
                            chunk[3] = 0x00;
                        }
                        break;
                }
            }

            return ret;
        }

    }
}
