using MVP_1B2.Models;
namespace MVP_1B2.Services

{
    public sealed class LicenseValidationResult
    {
        public bool IsValid { get; init; }

        public string Message { get; init; } = string.Empty;

        public LicensePayload? License { get; init; }

        public static LicenseValidationResult Valid(
            LicensePayload license)
        {
            return new LicenseValidationResult
            {
                IsValid = true,
                Message = "The license is valid.",
                License = license
            };
        }

        public static LicenseValidationResult Invalid(
            string message)
        {
            return new LicenseValidationResult
            {
                IsValid = false,
                Message = message
            };
        }
    }
}
