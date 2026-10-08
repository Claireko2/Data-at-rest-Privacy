using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace MVP_1B2.Services
{
    public sealed class AesGcmEncryptionService
    {
        private const int KeySize = 32;   // 256 bits
        private const int NonceSize = 12; // 96 bits
        private const int TagSize = 16;   // 128 bits

        private readonly byte[] _key;

        public AesGcmEncryptionService(IConfiguration configuration)
        {
            var keyBase64 = configuration["Encryption:AesKey"];

            if (string.IsNullOrWhiteSpace(keyBase64))
            {
                throw new InvalidOperationException(
                    "Encryption:AesKey is not configured.");
            }

            try
            {
                _key = Convert.FromBase64String(keyBase64);
            }
            catch (FormatException)
            {
                throw new InvalidOperationException(
                    "Encryption:AesKey is not a valid Base64 value.");
            }

            if (_key.Length != KeySize)
            {
                throw new InvalidOperationException(
                    "Encryption:AesKey must contain exactly 32 bytes.");
            }
        }

        public string EncryptString(string plaintext)
        {
            if (plaintext == null)
            {
                throw new ArgumentNullException(nameof(plaintext));
            }

            var plaintextBytes =
                Encoding.UTF8.GetBytes(plaintext);

            var encryptedBytes =
                EncryptBytes(plaintextBytes);

            return Convert.ToBase64String(encryptedBytes);
        }

        public string DecryptString(string ciphertext)
        {
            if (ciphertext == null)
            {
                throw new ArgumentNullException(nameof(ciphertext));
            }

            var encryptedBytes =
                Convert.FromBase64String(ciphertext);

            var plaintextBytes =
                DecryptBytes(encryptedBytes);

            return Encoding.UTF8.GetString(plaintextBytes);
        }

        public byte[] EncryptBytes(byte[] plaintext)
        {
            if (plaintext == null)
            {
                throw new ArgumentNullException(nameof(plaintext));
            }

            // Generate a new random nonce for every encryption.
            byte[] nonce =
                RandomNumberGenerator.GetBytes(NonceSize);

            byte[] ciphertext =
                new byte[plaintext.Length];

            byte[] tag =
                new byte[TagSize];

            using var aes =
                new AesGcm(_key, TagSize);

            aes.Encrypt(
                nonce,
                plaintext,
                ciphertext,
                tag);

            // Store:
            // [ nonce ][ authentication tag ][ ciphertext ]

            byte[] result =
                new byte[
                    NonceSize +
                    TagSize +
                    ciphertext.Length];

            Buffer.BlockCopy(
                nonce,
                0,
                result,
                0,
                NonceSize);

            Buffer.BlockCopy(
                tag,
                0,
                result,
                NonceSize,
                TagSize);

            Buffer.BlockCopy(
                ciphertext,
                0,
                result,
                NonceSize + TagSize,
                ciphertext.Length);

            return result;
        }

        public byte[] DecryptBytes(byte[] encryptedData)
        {
            if (encryptedData == null)
            {
                throw new ArgumentNullException(nameof(encryptedData));
            }

            if (encryptedData.Length < NonceSize + TagSize)
            {
                throw new CryptographicException(
                    "Encrypted data is too short.");
            }

            byte[] nonce =
                encryptedData[
                    0..NonceSize];

            byte[] tag =
                encryptedData[
                    NonceSize..(NonceSize + TagSize)];

            byte[] ciphertext =
                encryptedData[
                    (NonceSize + TagSize)..];

            byte[] plaintext =
                new byte[ciphertext.Length];

            using var aes =
                new AesGcm(_key, TagSize);

            aes.Decrypt(
                nonce,
                ciphertext,
                tag,
                plaintext);

            return plaintext;
        }

        public bool IsEncrypted(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            try
            {
                byte[] data = Convert.FromBase64String(value);

                return data.Length >= NonceSize + TagSize;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        public decimal DecryptDecimal(string value)
        {
            var plaintext = IsEncrypted(value)
                ? DecryptString(value)
                : value;

            return decimal.Parse(
                plaintext,
                CultureInfo.InvariantCulture);
        }

        public DateTime DecryptDateTime(string value)
        {
            var plaintext = IsEncrypted(value)
                ? DecryptString(value)
                : value;

            return DateTime.Parse(
                plaintext,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind);
        }
    }
}
