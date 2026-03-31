using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Services;

public sealed class AuditLogService(IAuditLogStore store, IAdminActorContext actorContext)
{
    public Task<IReadOnlyList<AdminAuditLogEntry>> GetRecentAsync(int take = 200, CancellationToken cancellationToken = default)
        => store.ReadRecentAsync(take, cancellationToken);

    public Task<AuditIntegrityStatus> VerifyIntegrityAsync(CancellationToken cancellationToken = default)
        => store.VerifyIntegrityAsync(cancellationToken);

    public Task WriteAsync(string category, string action, string target, string outcome, string details, string? actor = null, CancellationToken cancellationToken = default)
    {
        AdminActorInfo current = actorContext.GetCurrent();
        return store.AppendAsync(
            new AdminAuditLogEntry(
                Guid.NewGuid(),
                DateTimeOffset.UtcNow,
                actor ?? current.Name,
                current.Roles,
                current.AuthenticationType,
                category,
                action,
                target,
                outcome,
                details,
                0,
                null,
                string.Empty,
                current.RemoteIp,
                current.SessionId,
                current.UserAgent,
                Environment.MachineName),
            cancellationToken);
    }
}
