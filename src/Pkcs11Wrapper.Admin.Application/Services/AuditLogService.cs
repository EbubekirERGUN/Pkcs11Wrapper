using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Services;

public sealed class AuditLogService(IAuditLogStore store, IAdminActorContext actorContext)
{
    private readonly SemaphoreSlim _integrityGate = new(1, 1);
    private AuditIntegrityStatus? _cachedIntegrity;

    public Task<IReadOnlyList<AdminAuditLogEntry>> GetRecentAsync(int take = 200, CancellationToken cancellationToken = default)
        => store.ReadRecentAsync(take, cancellationToken);

    public async Task<AuditIntegrityStatus> VerifyIntegrityAsync(bool forceVerification = false, CancellationToken cancellationToken = default)
    {
        if (!forceVerification && _cachedIntegrity is not null)
        {
            return _cachedIntegrity;
        }

        await _integrityGate.WaitAsync(cancellationToken);
        try
        {
            if (!forceVerification && _cachedIntegrity is not null)
            {
                return _cachedIntegrity;
            }

            _cachedIntegrity = await store.VerifyIntegrityAsync(cancellationToken);
            return _cachedIntegrity;
        }
        finally
        {
            _integrityGate.Release();
        }
    }

    public async Task WriteAsync(string category, string action, string target, string outcome, string details, string? actor = null, CancellationToken cancellationToken = default)
    {
        AdminActorInfo current = actorContext.GetCurrent();
        await store.AppendAsync(
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
