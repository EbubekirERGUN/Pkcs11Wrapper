namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record AdminAuditLogEntry(
    Guid Id,
    DateTimeOffset TimestampUtc,
    string Actor,
    string[] ActorRoles,
    string AuthenticationType,
    string Category,
    string Action,
    string Target,
    string Outcome,
    string Details,
    long Sequence,
    string? PreviousHash,
    string EntryHash,
    string? RemoteIp,
    string? SessionId,
    string? UserAgent,
    string MachineName);
