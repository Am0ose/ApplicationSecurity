using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;

namespace ApplicationSecurity.Services
{
    public class EncryptionHelper
    {
        private static readonly byte[] Key;

        static EncryptionHelper()
        {
            var config = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .Build();

            string keyString = config["EncryptionSettings:AESKey"];
            if (string.IsNullOrEmpty(keyString) || keyString.Length != 32)
            {
                throw new InvalidOperationException("Invalid AES Key. It must be exactly 32 characters long.");
            }

            Key = Encoding.UTF8.GetBytes(keyString);
        }

        public static string Encrypt(string plainText)
        {
            using Aes aes = Aes.Create();
            aes.Key = Key;
            aes.GenerateIV();

            using MemoryStream memoryStream = new();
            using CryptoStream cryptoStream = new(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
            using (StreamWriter writer = new(cryptoStream))
            {
                writer.Write(plainText);
            }

            byte[] encryptedBytes = memoryStream.ToArray();
            byte[] combined = new byte[aes.IV.Length + encryptedBytes.Length];
            Buffer.BlockCopy(aes.IV, 0, combined, 0, aes.IV.Length);
            Buffer.BlockCopy(encryptedBytes, 0, combined, aes.IV.Length, encryptedBytes.Length);

            return Convert.ToBase64String(combined);
        }

        public static string Decrypt(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText))
                return string.Empty;

            byte[] combined = Convert.FromBase64String(cipherText);

            using Aes aes = Aes.Create();
            aes.Key = Key;
            byte[] iv = new byte[aes.IV.Length];
            byte[] encryptedBytes = new byte[combined.Length - iv.Length];

            Buffer.BlockCopy(combined, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(combined, iv.Length, encryptedBytes, 0, encryptedBytes.Length);

            aes.IV = iv;

            using MemoryStream memoryStream = new(encryptedBytes);
            using CryptoStream cryptoStream = new(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Read);
            using StreamReader reader = new(cryptoStream);

            return reader.ReadToEnd();
        }
    }
}
