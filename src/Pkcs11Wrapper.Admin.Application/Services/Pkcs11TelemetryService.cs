using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Native;

namespace Pkcs11Wrapper.Admin.Application.Services;

public sealed class Pkcs11TelemetryService(IPkcs11TelemetryStore store)
{
    public Task<IReadOnlyList<AdminPkcs11TelemetryEntry>> GetRecentAsync(int take = 500, CancellationToken cancellationToken = default)
        => store.ReadRecentAsync(take, cancellationToken);

    public IPkcs11OperationTelemetryListener CreateListener(HsmDeviceProfile device)
        => new AdminPkcs11TelemetryListener(store, device);

    private sealed class AdminPkcs11TelemetryListener(IPkcs11TelemetryStore store, HsmDeviceProfile device) : IPkcs11OperationTelemetryListener
    {
        public void OnOperationCompleted(in Pkcs11OperationTelemetryEvent operationEvent)
        {
            AdminPkcs11TelemetryEntry entry = new(
                Guid.NewGuid(),
                DateTimeOffset.UtcNow,
                device.Id,
                device.Name,
                operationEvent.OperationName,
                operationEvent.NativeOperationName,
                operationEvent.Status.ToString(),
                operationEvent.Duration.TotalMilliseconds,
                operationEvent.ReturnValue?.ToString(),
                operationEvent.SlotId.HasValue ? (ulong)operationEvent.SlotId.Value : null,
                operationEvent.SessionHandle.HasValue ? (ulong)operationEvent.SessionHandle.Value : null,
                operationEvent.MechanismType.HasValue ? (ulong)operationEvent.MechanismType.Value : null,
                operationEvent.Exception?.GetType().Name,
                [.. operationEvent.Fields.Select(field => new AdminPkcs11TelemetryField(field.Name, field.Classification.ToString(), field.Value))]);

            try
            {
                store.AppendAsync(entry).GetAwaiter().GetResult();
            }
            catch
            {
            }
        }
    }
}
