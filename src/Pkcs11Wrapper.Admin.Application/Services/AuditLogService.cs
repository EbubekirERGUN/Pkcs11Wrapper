using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Services;

public sealed class AuditLogService(IAuditLogStore store)
{
    public Task<IReadOnlyList<AdminAuditLogEntry>> GetRecentAsync(int take = 200, CancellationToken cancellationToken = default)
        => store.ReadRecentAsync(take, cancellationToken);

    public Task WriteAsync(string category, string action, string target, string outcome, string details, string actor = "local-admin", CancellationToken cancellationToken = default)
        => store.AppendAsync(
            new AdminAuditLogEntry(Guid.NewGuid(), DateTimeOffset.UtcNow, actor, category, action, target, outcome, details),
            cancellationToken);
}
