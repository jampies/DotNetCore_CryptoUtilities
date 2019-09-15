# CryptoUtilities

A few useful cryptography related functions.

Nuget package available here: https://www.nuget.org/packages/CryptoUtilities/

## Available functions

* `static string EncryptStringAES(string text, string keyString)`
* `static string DecryptStringAES(string cipherText, string keyString)`
* `static byte[] GenerateSaltValue()`
* `static string HashPassword(string password, byte[] salt)`
* `static bool VerifyHashedPassword(string password, string storedHash)`
* `static string GenerateRandomString(int length)`

## License

* MIT
