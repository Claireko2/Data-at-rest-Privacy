using System.Text.Json.Serialization;

namespace MVP_1B2.Models
{
    public class LicensePayload
    {
        public string LicenseId { get; set; } = string.Empty;
        public string CustomerId { get; set; } = string.Empty;
        public string LicenseType { get; set; } = string.Empty;
        public DateTimeOffset IssuedAtUtc { get; set; }
        public DateTimeOffset ValidFromUtc { get; set; }
        public DateTimeOffset ValidUntilUtc { get; set; }
    }

    public class LicenseDocument
    {
        public LicensePayload License { get; set; } = new LicensePayload();

        public string Signature { get; set; } = string.Empty;
    }
}