using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;

namespace CryptoUtilities.Tests
{
    [TestClass]
    public class CryptoTests
    {
        private string sharedSecret;

        public CryptoTests()
        {
            sharedSecret = "a_secret";
        }

        [TestMethod]
        public void HashPassword_Should_Always_Get_Same_Hash()
        {
            var salt = Crypto.GenerateSaltValue();
            var password1 = Crypto.HashPassword("P@55word", salt);
            var password2 = Crypto.HashPassword("P@55word", salt);

            Assert.AreEqual(password1, password2);
        }

        [TestMethod]
        public void HashPassword_Should_Get_A_Different_Hash_Per_Salt()
        {
            var salt1 = Crypto.GenerateSaltValue();
            var salt2 = Crypto.GenerateSaltValue();
            var password1 = Crypto.HashPassword("P@55word", salt1);
            var password2 = Crypto.HashPassword("P@55word", salt2);

            Assert.AreNotEqual(password1, password2);
        }

        [TestMethod]
        public void VerifyPassword_Should_return_true_if_correct()
        {
            var salt = Crypto.GenerateSaltValue();
            var hash = Crypto.HashPassword("P@55word", salt);

            var result = Crypto.VerifyHashedPassword("P@55word", hash);

            Assert.IsTrue(result);
        }

        [TestMethod]
        public void VerifyPassword_Should_return_false_if_incorrect()
        {
            var salt = Crypto.GenerateSaltValue();
            var hash = Crypto.HashPassword("P@55word", salt);

            var result = Crypto.VerifyHashedPassword("P@55Word", hash);
            var result2 = Crypto.VerifyHashedPassword("", hash);
            var result3 = Crypto.VerifyHashedPassword(hash, hash);

            Assert.IsFalse(result);
            Assert.IsFalse(result2);
            Assert.IsFalse(result3);
        }

        [TestMethod]
        public void Encrypting_should_generate_random_salts()
        {
            var message = "This is a secret message";

            var encrypted1 = Crypto.EncryptStringAES(message, sharedSecret);
            var encrypted2 = Crypto.EncryptStringAES(message, sharedSecret);

            Assert.AreNotEqual(encrypted1, encrypted2);
        }

        [TestMethod]
        public void Encrypting_should_decrypt_correctly()
        {
            var message = "This is a secret message";

            var encrypted = Crypto.EncryptStringAES(message, sharedSecret);
            var decrypted = Crypto.DecryptStringAES(encrypted, sharedSecret);

            Assert.AreEqual(message, decrypted);
        }


        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void Encrypting_should_not_decrypt_with_incorrect_secret()
        {
            var message = "This is a secret message";
            var incorrectSecret = "not_the_secret";

            var encrypted = Crypto.EncryptStringAES(message, sharedSecret);
            var decrypted = Crypto.DecryptStringAES(encrypted, incorrectSecret);
        }


    }
}
