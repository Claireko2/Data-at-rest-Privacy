
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using MVP_1B2.Models;

namespace MVP_1B2.Services
{
    public sealed class LicenseVerificationService
    {
        private readonly RSA _publicKey;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
        };

        public LicenseVerificationService(
            IConfiguration configuration)
        {
            var publicKeyPath =
                configuration["License:PublicKeyPath"];

            if (string.IsNullOrWhiteSpace(publicKeyPath))
            {
                throw new InvalidOperationException(
                    "License:PublicKeyPath is not configured.");
            }

            if (!File.Exists(publicKeyPath))
            {
                throw new FileNotFoundException(
                    "License public key was not found.",
                    publicKeyPath);
            }

            _publicKey = RSA.Create();

            _publicKey.ImportFromPem(
                File.ReadAllText(publicKeyPath));
        }

        public LicenseDocument LoadLicense(
            string licensePath)
        {
            if (!File.Exists(licensePath))
            {
                throw new FileNotFoundException(
                    "License file was not found.",
                    licensePath);
            }

            string json =
                File.ReadAllText(licensePath);

            var document =
                JsonSerializer.Deserialize<LicenseDocument>(
                    json,
                    JsonOptions);

            if (document == null)
            {
                throw new InvalidOperationException(
                    "License file could not be parsed.");
            }

            return document;
        }

        public bool VerifySignature(
            LicenseDocument document)
        {
            string payloadJson =
                JsonSerializer.Serialize(
                    document.License,
                    JsonOptions);

            byte[] payloadBytes =
                Encoding.UTF8.GetBytes(
                    payloadJson);

            byte[] signatureBytes =
                Convert.FromBase64String(
                    document.Signature);

            return _publicKey.VerifyData(
                payloadBytes,
                signatureBytes,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
        }

        public bool IsWithinValidityPeriod(
            MVP_1B2.Models.LicensePayload license)
        {
            var now =
                DateTimeOffset.UtcNow;

            return now >= license.ValidFromUtc
                && now <= license.ValidUntilUtc;
        }

        public bool ValidateLicense(
            LicenseDocument document)
        {
            if (!VerifySignature(document))
            {
                return false;
            }

            if (!IsWithinValidityPeriod(
                    document.License))
            {
                return false;
            }

            return true;
        }
    }
}

