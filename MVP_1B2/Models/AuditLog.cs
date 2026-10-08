namespace MVP_1B2.Models
{
    public class AuditLog
    {
        public int Id { get; set; }

        public string UserId { get; set; } = string.Empty;

        public string Action { get; set; } = string.Empty;

        public string EntityType { get; set; } = string.Empty;

        public string EntityId { get; set; } = string.Empty;

        public DateTime TimestampUtc { get; set; }

        public string Details { get; set; } = string.Empty;

        public string Signature { get; set; } = string.Empty;
    }
}