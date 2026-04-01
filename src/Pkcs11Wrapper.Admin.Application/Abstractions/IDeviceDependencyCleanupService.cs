using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Abstractions;

public interface IDeviceDependencyCleanupService
{
    Task<DeviceDependencyCleanupSummary> CleanupForDevicesAsync(IReadOnlyCollection<Guid> deviceIds, CancellationToken cancellationToken = default);

    Task<DeviceDependencyCleanupSummary> CleanupForMissingDevicesAsync(IReadOnlyCollection<Guid> retainedDeviceIds, CancellationToken cancellationToken = default);
}
