using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using MVP_1B2.Models;

namespace MVP_1B2.Services
{
    [Obfuscation(
        Exclude = false,
        Feature = "all",
        ApplyToMembers = true,
        StripAfterObfuscation = true)]
    public sealed class LicenseService : ILicenseService
    {
        private readonly IHostEnvironment _environment;
        private readonly LicenseOptions _options;
        private readonly ILogger<LicenseService> _logger;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
        };

        public LicenseService(
            IHostEnvironment environment,
            IOptions<LicenseOptions> options,
            ILogger<LicenseService> logger)
        {
            _environment = environment;
            _options = options.Value;
            _logger = logger;
        }

        public LicenseValidationResult Validate()
        {
            try
            {
                var licensePath =
                    ResolvePath(_options.LicenseFilePath);

                var publicKeyPath =
                    ResolvePath(_options.PublicKeyPath);

                if (!File.Exists(licensePath))
                {
                    return LicenseValidationResult.Invalid(
                        "No license file was found.");
                }

                if (!File.Exists(publicKeyPath))
                {
                    return LicenseValidationResult.Invalid(
                        "The license verification key is missing.");
                }

                var licenseJson =
                    File.ReadAllText(licensePath);

                using var document =
                    JsonDocument.Parse(licenseJson);

                if (!document.RootElement.TryGetProperty(
                        "license",
                        out var licenseElement))
                {
                    return LicenseValidationResult.Invalid(
                        "The license file is malformed.");
                }

                if (!document.RootElement.TryGetProperty(
                        "signature",
                        out var signatureElement))
                {
                    return LicenseValidationResult.Invalid(
                        "The license signature is missing.");
                }

                var signatureText =
                    signatureElement.GetString();

                if (string.IsNullOrWhiteSpace(signatureText))
                {
                    return LicenseValidationResult.Invalid(
                        "The license signature is empty.");
                }

                byte[] signatureBytes;

                try
                {
                    signatureBytes =
                        Convert.FromBase64String(signatureText);
                }
                catch
                {
                    return LicenseValidationResult.Invalid(
                        "The license signature is invalid.");
                }

                var signedLicenseJson =
                    licenseElement.GetRawText();

                var data =
                    Encoding.UTF8.GetBytes(
                        signedLicenseJson);

                var publicKey =
                    File.ReadAllText(publicKeyPath);

                using var rsa = RSA.Create();

                rsa.ImportFromPem(publicKey);

                var signatureValid =
                    rsa.VerifyData(
                        data,
                        signatureBytes,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);

                if (!signatureValid)
                {
                    return LicenseValidationResult.Invalid(
                        "The license signature is invalid or the license has been modified.");
                }

                var license =
                    licenseElement.Deserialize<LicensePayload>(
                        JsonOptions);

                if (license == null)
                {
                    return LicenseValidationResult.Invalid(
                        "The license payload could not be read.");
                }

                if (string.IsNullOrWhiteSpace(
                        license.LicenseId))
                {
                    return LicenseValidationResult.Invalid(
                        "The license ID is missing.");
                }

                if (string.IsNullOrWhiteSpace(
                        license.CustomerId))
                {
                    return LicenseValidationResult.Invalid(
                        "The customer ID is missing.");
                }

                if (license.ValidUntilUtc
                    < license.ValidFromUtc)
                {
                    return LicenseValidationResult.Invalid(
                        "The license validity period is invalid.");
                }

                if (DateTimeOffset.UtcNow
                    < license.ValidFromUtc)
                {
                    return LicenseValidationResult.Invalid(
                        "The license is not active yet.");
                }

                if (DateTimeOffset.UtcNow
                    > license.ValidUntilUtc)
                {
                    return LicenseValidationResult.Invalid(
                        "The license has expired.");
                }

                return LicenseValidationResult.Valid(license);
            }
            catch (CryptographicException ex)
            {
                _logger.LogError(
                    ex,
                    "License cryptographic validation failed.");

                return LicenseValidationResult.Invalid(
                    "The license could not be verified.");
            }
            catch (JsonException ex)
            {
                _logger.LogError(
                    ex,
                    "License JSON validation failed.");

                return LicenseValidationResult.Invalid(
                    "The license file is invalid.");
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Unexpected license validation error.");

                return LicenseValidationResult.Invalid(
                    "The license could not be validated.");
            }
        }

        private string ResolvePath(string path)
        {
            if (Path.IsPathRooted(path))
            {
                return path;
            }

            return Path.Combine(
                _environment.ContentRootPath,
                path);
        }
    }
}
