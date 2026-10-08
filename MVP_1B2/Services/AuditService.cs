using MVP_1B2.Models;

namespace MVP_1B2.Services
{
    public sealed class AuditService
    {
        private readonly ClientContext _context;
        private readonly NonRepudiationService _nonRepudiation;

        public AuditService(
            ClientContext context,
            NonRepudiationService nonRepudiation)
        {
            _context = context;
            _nonRepudiation = nonRepudiation;
        }

        public async Task LogAsync(
    string userId,
    string action,
    string entityType,
    string entityId,
    string details)
        {
            var timestamp = DateTime.UtcNow;

            var canonicalData =
                $"{userId}|{action}|{entityType}|{entityId}|{timestamp:O}|{details}";

            var signature =
                _nonRepudiation.Sign(canonicalData);

            // TEST: verify immediately, before saving to database
            var testResult =
                _nonRepudiation.Verify(canonicalData, signature);

            Console.WriteLine("===== SIGNATURE TEST =====");
            Console.WriteLine($"Verification before database save: {testResult}");
            Console.WriteLine($"Canonical data: {canonicalData}");
            Console.WriteLine($"Signature: {signature}");
            Console.WriteLine("==========================");

            var auditLog = new AuditLog
            {
                UserId = userId,
                Action = action,
                EntityType = entityType,
                EntityId = entityId,
                TimestampUtc = timestamp,
                Details = details,
                Signature = signature
            };

            _context.AuditLogs.Add(auditLog);

            await _context.SaveChangesAsync();
        }
        public bool Verify(AuditLog auditLog)
        {
            var timestampUtc = DateTime.SpecifyKind(
                auditLog.TimestampUtc,
                DateTimeKind.Utc);

            var canonicalData =
                $"{auditLog.UserId}|{auditLog.Action}|{auditLog.EntityType}|{auditLog.EntityId}|{timestampUtc:O}|{auditLog.Details}";

            Console.WriteLine("VERIFY DATA:");
            Console.WriteLine(canonicalData);

            Console.WriteLine("SIGNATURE:");
            Console.WriteLine(auditLog.Signature);

            return _nonRepudiation.Verify(
                canonicalData,
                auditLog.Signature);
        }
    }
}