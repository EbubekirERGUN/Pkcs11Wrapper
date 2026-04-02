using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Abstractions;

public interface IPkcs11TelemetryStore
{
    Task AppendAsync(AdminPkcs11TelemetryEntry entry, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AdminPkcs11TelemetryEntry>> ReadRecentAsync(int take, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AdminPkcs11TelemetryEntry>> ReadAllAsync(CancellationToken cancellationToken = default);

    Task<AdminPkcs11TelemetryStorageStatus> GetStorageStatusAsync(CancellationToken cancellationToken = default);
}
