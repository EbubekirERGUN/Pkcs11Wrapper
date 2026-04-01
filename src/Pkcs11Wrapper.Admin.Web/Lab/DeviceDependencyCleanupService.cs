using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Infrastructure;

namespace Pkcs11Wrapper.Admin.Web.Lab;

public sealed class DeviceDependencyCleanupService(
    ProtectedPinStore protectedPinStore,
    Pkcs11LabTemplateStore templateStore) : IDeviceDependencyCleanupService
{
    public async Task<DeviceDependencyCleanupSummary> CleanupForDevicesAsync(IReadOnlyCollection<Guid> deviceIds, CancellationToken cancellationToken = default)
    {
        int removedPins = 0;
        int removedTemplates = 0;

        foreach (Guid deviceId in deviceIds.Distinct())
        {
            removedPins += await protectedPinStore.DeleteForDeviceAsync(deviceId, cancellationToken);
            removedTemplates += await templateStore.DeleteForDeviceAsync(deviceId, cancellationToken);
        }

        return new DeviceDependencyCleanupSummary(0, removedPins, removedTemplates);
    }

    public async Task<DeviceDependencyCleanupSummary> CleanupForMissingDevicesAsync(IReadOnlyCollection<Guid> retainedDeviceIds, CancellationToken cancellationToken = default)
    {
        int removedPins = await protectedPinStore.DeleteMissingDevicesAsync(retainedDeviceIds, cancellationToken);
        int removedTemplates = await templateStore.DeleteMissingDevicesAsync(retainedDeviceIds, cancellationToken);
        return new DeviceDependencyCleanupSummary(0, removedPins, removedTemplates);
    }
}
