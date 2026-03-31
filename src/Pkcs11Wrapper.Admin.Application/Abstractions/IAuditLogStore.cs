using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Abstractions;

public interface IAuditLogStore
{
    Task AppendAsync(AdminAuditLogEntry entry, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AdminAuditLogEntry>> ReadRecentAsync(int take, CancellationToken cancellationToken = default);

    Task<AuditIntegrityStatus> VerifyIntegrityAsync(CancellationToken cancellationToken = default);
}
