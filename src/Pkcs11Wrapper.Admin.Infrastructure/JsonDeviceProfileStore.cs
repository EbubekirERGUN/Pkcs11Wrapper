using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Infrastructure;

public sealed class JsonDeviceProfileStore(AdminStorageOptions options) : IDeviceProfileStore
{
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public async Task<IReadOnlyList<HsmDeviceProfile>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            string path = GetPath();
            return await CrashSafeFileStore.ReadJsonAsync(path, AdminJsonContext.Default.ListHsmDeviceProfile, cancellationToken) ?? [];
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task SaveAllAsync(IReadOnlyList<HsmDeviceProfile> devices, CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await CrashSafeFileStore.WriteJsonAsync(GetPath(), devices.ToList(), AdminJsonContext.Default.ListHsmDeviceProfile, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    private string GetPath() => Path.Combine(options.DataRoot, options.DeviceProfilesFileName);
}
