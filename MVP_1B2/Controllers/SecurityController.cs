using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MVP_1B2.Services;
using System.Security.Cryptography;
using System.Text;

namespace MVP_1B2.Controllers
{
    [Authorize(Roles = "Administrator,Manager")]
    public class SecurityController : Controller
    {
        private readonly CustomStreamCipherService _streamCipher;

        public SecurityController(
            CustomStreamCipherService streamCipher)
        {
            _streamCipher = streamCipher;
        }

        public IActionResult TestCipher()
        {
            byte[] plaintext =
                Encoding.UTF8.GetBytes(
                    "Hello, this is my custom stream cipher!");

            byte[] nonce =
                RandomNumberGenerator.GetBytes(12);

            byte[] encrypted =
                _streamCipher.Transform(
                    plaintext,
                    nonce);

            byte[] decrypted =
                _streamCipher.Transform(
                    encrypted,
                    nonce);

            string result =
                Encoding.UTF8.GetString(
                    decrypted);

            Console.WriteLine("===== CUSTOM STREAM CIPHER TEST =====");
            Console.WriteLine($"Original:  {Encoding.UTF8.GetString(plaintext)}");
            Console.WriteLine($"Decrypted: {result}");
            Console.WriteLine($"Success:   {result == Encoding.UTF8.GetString(plaintext)}");
            Console.WriteLine("======================================");

            return Content(result);
        }
        public async Task<IActionResult> TestFileCipher()
        {
            string inputPath =
                Path.Combine(
                    Directory.GetCurrentDirectory(),
                    "TestFiles",
                    "COMP-8171-Database Systems Security Assignment I _ClaireKo.pdf");

            string encryptedPath =
                Path.Combine(
                    Directory.GetCurrentDirectory(),
                    "TestFiles",
                    "COMP-8171-Database Systems Security Assignment I _ClaireKo.mvp");

            string decryptedPath =
                Path.Combine(
                    Directory.GetCurrentDirectory(),
                    "TestFiles",
                    "COMP-8171-Database Systems Security Assignment I _ClaireKo_decrypted.pdf");

            await _streamCipher.EncryptFileAsync(
                inputPath,
                encryptedPath);

            await _streamCipher.DecryptFileAsync(
                encryptedPath,
                decryptedPath);


            try
            {
                await _streamCipher.DecryptFileAsync(
                 encryptedPath,
                 decryptedPath);

                return Content(
                $"Encryption and decryption completed.\n\n" +
                $"Original: {inputPath}\n" +
                $"Encrypted: {encryptedPath}\n" +
                $"Decrypted: {decryptedPath}");
            }
            catch (CryptographicException ex)
            {
                return Content(
                    "CAUGHT: " + ex.Message);
            }


        }
    }

}