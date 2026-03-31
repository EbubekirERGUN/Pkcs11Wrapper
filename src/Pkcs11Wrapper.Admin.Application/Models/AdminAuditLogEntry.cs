namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record AdminAuditLogEntry(
    Guid Id,
    DateTimeOffset TimestampUtc,
    string Actor,
    string Category,
    string Action,
    string Target,
    string Outcome,
    string Details);
