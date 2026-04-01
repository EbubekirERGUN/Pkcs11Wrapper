using Microsoft.AspNetCore.DataProtection;

namespace Pkcs11Wrapper.Admin.Infrastructure;

public sealed class ProtectedPinStore(AdminStorageOptions options, IDataProtectionProvider dataProtectionProvider)
{
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private readonly IDataProtector _protector = dataProtectionProvider.CreateProtector("Pkcs11Wrapper.Admin.ProtectedPinStore.v1");

    public async Task<string?> TryGetAsync(Guid deviceId, nuint slotId, string purpose, CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            ProtectedPinRecord? record = (await ReadAllCoreAsync(cancellationToken)).FirstOrDefault(x => x.DeviceId == deviceId && x.SlotId == slotId && string.Equals(x.Purpose, purpose, StringComparison.Ordinal));
            return record is null ? null : _protector.Unprotect(record.Ciphertext);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task SaveAsync(Guid deviceId, nuint slotId, string purpose, string pin, CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            List<ProtectedPinRecord> records = await ReadAllCoreAsync(cancellationToken);
            records.RemoveAll(x => x.DeviceId == deviceId && x.SlotId == slotId && string.Equals(x.Purpose, purpose, StringComparison.Ordinal));
            records.Add(new ProtectedPinRecord(deviceId, slotId, purpose, _protector.Protect(pin), DateTimeOffset.UtcNow, Mask(pin)));
            await WriteAllCoreAsync(records, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task DeleteAsync(Guid deviceId, nuint slotId, string purpose, CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            List<ProtectedPinRecord> records = await ReadAllCoreAsync(cancellationToken);
            records.RemoveAll(x => x.DeviceId == deviceId && x.SlotId == slotId && string.Equals(x.Purpose, purpose, StringComparison.Ordinal));
            await WriteAllCoreAsync(records, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<int> DeleteForDeviceAsync(Guid deviceId, CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            List<ProtectedPinRecord> records = await ReadAllCoreAsync(cancellationToken);
            int removed = records.RemoveAll(x => x.DeviceId == deviceId);
            if (removed > 0)
            {
                await WriteAllCoreAsync(records, cancellationToken);
            }

            return removed;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<int> DeleteMissingDevicesAsync(IReadOnlyCollection<Guid> retainedDeviceIds, CancellationToken cancellationToken = default)
    {
        HashSet<Guid> retained = [.. retainedDeviceIds];

        await _mutex.WaitAsync(cancellationToken);
        try
        {
            List<ProtectedPinRecord> records = await ReadAllCoreAsync(cancellationToken);
            int removed = records.RemoveAll(x => x.DeviceId != Guid.Empty && !retained.Contains(x.DeviceId));
            if (removed > 0)
            {
                await WriteAllCoreAsync(records, cancellationToken);
            }

            return removed;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<ProtectedPinRecord>> GetMetadataAsync(CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            return await ReadAllCoreAsync(cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<List<ProtectedPinRecord>> ReadAllCoreAsync(CancellationToken cancellationToken)
        => await CrashSafeFileStore.ReadJsonAsync(GetPath(), AdminJsonContext.Default.ListProtectedPinRecord, cancellationToken) ?? [];

    private Task WriteAllCoreAsync(List<ProtectedPinRecord> records, CancellationToken cancellationToken)
        => CrashSafeFileStore.WriteJsonAsync(GetPath(), records, AdminJsonContext.Default.ListProtectedPinRecord, cancellationToken);

    private string GetPath() => Path.Combine(options.DataRoot, "protected-pins.json");

    private static string Mask(string pin)
        => pin.Length <= 2 ? new string('*', pin.Length) : $"{pin[0]}{new string('*', Math.Max(1, pin.Length - 2))}{pin[^1]}";
}
