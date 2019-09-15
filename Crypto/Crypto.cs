using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptoUtilities
{
    public class Crypto
    {
        const int IV_BYTE_LENGTH = 128 / 8;
        const int SALT_BYTE_LENGTH = 256 / 8;
        const int KEY_LENGTH = 256;
        const int KEY_BYTE_LENGTH = KEY_LENGTH / 8;
        private static byte[] CombineArrays(byte[] a1, byte[] a2)
        {
            byte[] rv = new byte[a1.Length + a2.Length];
            Buffer.BlockCopy(a1, 0, rv, 0, a1.Length);
            Buffer.BlockCopy(a2, 0, rv, a1.Length, a2.Length);
            return rv;
        }
		public static string EncryptStringAES(string text, string keyString)
		{
            // TODO: This should probably take advantage of the ASP.NET Core IDataProtector service, but that would not be stateless
            //       since the keys are generated and stored on the server so every docker container would have a different key.
            //       To solve this we'd need to add Microsoft.AspNetCore.DataProtection.Redis (or similar)


            if (keyString.Length < KEY_BYTE_LENGTH)
            {
                keyString = keyString.PadRight(KEY_BYTE_LENGTH, '0');
            }


            var key = new Rfc2898DeriveBytes(keyString, SALT_BYTE_LENGTH);

            using (var aesAlg = Aes.Create())
            {

                byte[] rawPlaintext = Encoding.Unicode.GetBytes(text);

                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.KeySize = KEY_LENGTH;
                aesAlg.Key = key.GetBytes(KEY_BYTE_LENGTH);
                aesAlg.IV = key.GetBytes(IV_BYTE_LENGTH);

                byte[] cipherText = null;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aesAlg.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(rawPlaintext, 0, rawPlaintext.Length);
                    }

                    cipherText = ms.ToArray();

                    var result = new byte[cipherText.Length + key.Salt.Length + aesAlg.IV.Length];
                    cipherText.CopyTo(result, 0);
                    key.Salt.CopyTo(result, cipherText.Length);
                    aesAlg.IV.CopyTo(result, key.Salt.Length + cipherText.Length);
                    return Convert.ToBase64String(result);
                }
            }
        }

		public static string DecryptStringAES(string cipherText, string keyString)
        {
            if (keyString.Length < KEY_BYTE_LENGTH)
            {
                keyString = keyString.PadRight(KEY_BYTE_LENGTH, '0');
            }
            var fullCipher = Convert.FromBase64String(cipherText);

			var iv = new byte[IV_BYTE_LENGTH];
            var salt = new byte[SALT_BYTE_LENGTH];
			var cipher = new byte[fullCipher.Length - iv.Length - salt.Length];
            
            Buffer.BlockCopy(fullCipher, 0, cipher, 0, cipher.Length);
			Buffer.BlockCopy(fullCipher, cipher.Length, salt, 0, salt.Length);
			Buffer.BlockCopy(fullCipher, cipher.Length + salt.Length, iv, 0, iv.Length);


            var key = new Rfc2898DeriveBytes(keyString, salt);

			using (var aesAlg = Aes.Create())
            {
                aesAlg.Padding = PaddingMode.PKCS7;
                aesAlg.KeySize = KEY_LENGTH;
                aesAlg.Key = key.GetBytes(KEY_BYTE_LENGTH);
                aesAlg.IV = iv;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aesAlg.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipher, 0, cipher.Length);
                    }

                    return Encoding.Unicode.GetString(ms.ToArray());
                }
            }
		}

        private const int PERMUTATION_COUNT = 10000;

        public static byte[] GenerateSaltValue()
        {
            byte[] salt;
            RandomNumberGenerator.Create().GetBytes(salt = new byte[16]);
            return salt;
        }

        public static string HashPassword(string password, byte[] salt)
        {
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, PERMUTATION_COUNT);
            byte[] hash = pbkdf2.GetBytes(20);

            byte[] hashBytes = new byte[36];
            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);

            return Convert.ToBase64String(hashBytes);
        }

        public static bool VerifyHashedPassword(string password, string storedHash)
        {
            /* Extract the bytes */
            byte[] hashBytes = Convert.FromBase64String(storedHash);
            /* Get the salt */
            byte[] salt = new byte[16];
            Array.Copy(hashBytes, 0, salt, 0, 16);
            /* Compute the hash on the password the user entered */
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt, PERMUTATION_COUNT);
            byte[] hash = pbkdf2.GetBytes(20);
            /* Compare the results */
            for (int i = 0; i < 20; i++)
                if (hashBytes[i + 16] != hash[i])
                    return false;
            return true;
        }

        public static string GenerateRandomString(int length)
        {
            const string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
            StringBuilder res = new StringBuilder();
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] uintBuffer = new byte[sizeof(uint)];

                while (length-- > 0)
                {
                    rng.GetBytes(uintBuffer);
                    uint num = BitConverter.ToUInt32(uintBuffer, 0);
                    res.Append(valid[(int)(num % (uint)valid.Length)]);
                }
            }

            return res.ToString();
        }

    }
}

