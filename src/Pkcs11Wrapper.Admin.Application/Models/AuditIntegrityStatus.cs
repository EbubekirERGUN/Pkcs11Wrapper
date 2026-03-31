namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record AuditIntegrityStatus(
    bool IsValid,
    int CheckedEntries,
    string? LastSequence,
    string Summary,
    string? FailureReason);
