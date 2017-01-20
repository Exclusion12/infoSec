﻿using System;
using System.IO;
using System.Text;

namespace Enc
{
    class Program
    {

        static void Main(string[] args)
        {
            try
            {
                byte[] pass = Encoding.Default.GetBytes("Aa123456");
                
                byte[] file = File.ReadAllBytes("./BindShell.dll");
                byte[] encFile = RC4.Encrypt(pass, file);
                File.WriteAllBytes("./BindShell.dat", encFile);

               
            }
            catch (Exception) { 

            }
        }
    }

    public class RC4
    {

        public static byte[] Encrypt(byte[] pwd, byte[] data)
        {
            int a, i, j, k, tmp;
            int[] key, box;
            byte[] cipher;

            key = new int[256];
            box = new int[256];
            cipher = new byte[data.Length];

            for (i = 0; i < 256; i++)
            {
                key[i] = pwd[i % pwd.Length];
                box[i] = i;
            }
            for (j = i = 0; i < 256; i++)
            {
                j = (j + box[i] + key[i]) % 256;
                tmp = box[i];
                box[i] = box[j];
                box[j] = tmp;
            }
            for (a = j = i = 0; i < data.Length; i++)
            {
                a++;
                a %= 256;
                j += box[a];
                j %= 256;
                tmp = box[a];
                box[a] = box[j];
                box[j] = tmp;
                k = box[((box[a] + box[j]) % 256)];
                cipher[i] = (byte)(data[i] ^ k);
            }
            return cipher;
        }

        public static byte[] Decrypt(byte[] pwd, byte[] data)
        {
            return Encrypt(pwd, data);
        }

    }
}
