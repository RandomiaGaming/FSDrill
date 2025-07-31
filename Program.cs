using System;
using System.Collections.Generic;
using System.Data.SqlTypes;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace FSDrill
{
    public static class Program
    {
        public static void Main(string[] args)
        {
            byte[] password = FromASCII("hi");
            byte[] salt = FromBase64("foYIzS4xKRCJZdWkXcG3ww==");
            byte[] saltyPassword = Salt(password, salt);
            byte[] key = Hash(saltyPassword, 100000);
            byte[] input = FromBase64("+ZgYGkGjej43H8HSXTGp5Q==");
            byte[] output = Decrypt(input, key);
            byte[] outputHash = Hash(output);
            byte[] expectedOutputHash = FromBase64("IpUCxYwOrxmWUSLXSzp3m/ZrhcTym1PSdjKxVs9PLqumBW6R8SxIlfpCc08kkX3dJNz0x5Qme29dmkUF+wX2gA==");

            if(outputHash.Length != expectedOutputHash.Length)
            {
                throw new Exception("CRY");
            }
            for (int i = 0; i < output.Length; i++)
            {
                if (outputHash[i] != expectedOutputHash[i])
                {
                    throw new Exception("SOB");
                }
            }

            Console.ReadLine();
        }

        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            if(key.Length > (256 / 8))
            {
                byte[] truncatedKey = new byte[256 / 8];
                Array.Copy(key, 0, truncatedKey, 0, truncatedKey.Length);
                key = truncatedKey;
            }

            AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider();
            aesCryptoServiceProvider.Key = key;
            aesCryptoServiceProvider.Mode = CipherMode.CBC;
            aesCryptoServiceProvider.Padding = PaddingMode.Zeros;
            aesCryptoServiceProvider.BlockSize = 16 * 8;

            byte[] iv = new byte[16];
            Array.Copy(data, iv, 16);
            aesCryptoServiceProvider.IV = iv;

            ICryptoTransform cryptoTransform = aesCryptoServiceProvider.CreateDecryptor(aesCryptoServiceProvider.Key, aesCryptoServiceProvider.IV);
            MemoryStream memoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write);

            cryptoStream.Write(data, 0, data.Length);
            cryptoStream.FlushFinalBlock();

            byte[] output = memoryStream.ToArray();

            cryptoStream.Dispose();
            memoryStream.Dispose();
            cryptoTransform.Dispose();
            aesCryptoServiceProvider.Dispose();

            return output;
        }
        public static byte[] FromBase64(string input)
        {
            return Convert.FromBase64String(input);
        }
        public static byte[] FromASCII(string input)
        {
            return Encoding.ASCII.GetBytes(input);
        }
        public static byte[] Salt(byte[] input, byte[] salt)
        {
            byte[] output = new byte[input.Length + salt.Length];
            Array.Copy(input, 0, output, 0, input.Length);
            Array.Copy(salt, 0, output, input.Length, salt.Length);
            return output;
        }
        public static byte[] Hash(byte[] input, int spinCount = 1)
        {
            SHA512Managed sha512 = new SHA512Managed();
            for (int i = 0; i < spinCount; i++)
            {
                input = sha512.ComputeHash(input);
            }
            sha512.Dispose();
            return input;
        }
        // Searches the contents of files for an ascii string. Prints results
        public static void SearchAscii(string folderPath, string targetText)
        {
            byte[] targetBytes = Encoding.ASCII.GetBytes(targetText);
            foreach (string filePath in Directory.GetFiles(folderPath, "*", SearchOption.AllDirectories))
            {
                byte[] fileBytes = File.ReadAllBytes(filePath);
                if (ContainsBytes(fileBytes, targetBytes))
                {
                    Console.WriteLine($"Found {targetText} in {filePath}");
                }
            }
        }
        // Returns true if source contains searchTarget else false.
        private static bool ContainsBytes(byte[] source, byte[] searchTarget)
        {
            int loopMax = (source.Length - searchTarget.Length) + 1;
            for (int i = 0; i < loopMax; i++)
            {
                bool found = true;
                for (int j = 0; j < searchTarget.Length; j++)
                {
                    if (source[i + j] != searchTarget[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                {
                    return true;
                }
            }
            return false;
        }
        // Prints all the files in a folder biggest first.
        public static void PrintBigFiles(string folderPath)
        {
            List<Tuple<string, long>> db = new List<Tuple<string, long>>();
            foreach (string filePath in Directory.GetFiles(folderPath, "*", SearchOption.AllDirectories))
            {
                db.Add(new Tuple<string, long>(filePath, new FileInfo(filePath).Length));
            }
            db.Sort((x, y) => x.Item2.CompareTo(y.Item2));
            for (int i = 0; i < db.Count; i++)
            {
                Console.WriteLine($"{db[i].Item2} byte file {db[i].Item1}");
            }
        }
    }
    public sealed class XML
    {
        public string version = "1.0"; // The version of XML this file uses.
        public string encoding = "UTF-8"; // The encoding used to create this XML file.
        public bool standalone = true; // Yes or no depending on if this XML file is standalone.
        public Encryption encryption;
        public sealed class Encryption
        {
            // Dead links to XML schemas that don't exist anymore.
            public string xmlns = "http://schemas.microsoft.com/office/2006/encryption";
            public string xmlns_p = "http://schemas.microsoft.com/office/2006/keyEncryptor/password";
            public string xmlns_c = "http://schemas.microsoft.com/office/2006/keyEncryptor/certificate";
            public KeyData keyData;
            public sealed class KeyData
            {
                public int saltSize = 16; // The size of the salt in bytes.
                public int blockSize = 16; // The size of one block in bytes.
                public int keyBits = 256; // The size of the key in bits.
                public int hashSize = 64; // The size of the hash in bytes.
                public string cipherAlgorithm = "AES"; // The cypher algorithem used.
                public string cipherChaining = "ChainingModeCBC"; // The cypher chaining mode used.
                public string hashAlgorithm = "SHA512"; // The hashing algorithem used.
                public string saltValue = "ZuPdXsCe3kHAedJx9CtgAg=="; // A base64 string containing the salt value.
            }
            public KeyEncryptor keyEncryptor;
            public sealed class KeyEncryptor
            {
                public string uri = "http://schemas.microsoft.com/office/2006/keyEncryptor/password"; // A dead link to an XML schema that doesn't exist anymore.
                public pEncryptedKey pencryptedKey;
                public sealed class pEncryptedKey
                {
                    public int spinCount = 100000; // The number of hash itterations used.
                    public int saltSize = 16; // The size of the salt in bytes.
                    public int blockSize = 16; // The size of one block in bytes.
                    public int keyBits = 256; // The size of the key in bits.
                    public int hashSize = 64; // The size of the hash in bytes.
                    public string cipherAlgorithm = "AES"; // The cypher algorithem used.
                    public string cipherChaining = "ChainingModeCBC"; // The cypher chaining mode used.
                    public string hashAlgorithm = "SHA512"; // The hashing algorithem used.
                    public string saltValue = "foYIzS4xKRCJZdWkXcG3ww=="; // A base64 string containing the salt value.
                    public string encryptedVerifierHashInput = "+ZgYGkGjej43H8HSXTGp5Q=="; // The input to the password verification hash in base64.
                    public string encryptedVerifierHashValue = "IpUCxYwOrxmWUSLXSzp3m/ZrhcTym1PSdjKxVs9PLqumBW6R8SxIlfpCc08kkX3dJNz0x5Qme29dmkUF+wX2gA=="; // The output from the password verification hash in base64.
                    public string encryptedKeyValue = "ifmEVj2H69woonwW1wp/P1a4z01yN6ykqUcLL836Iaw="; // The encrypted key in base64. (encrypted with the password)
                }
            }
        }
    }
}
