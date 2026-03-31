using System.Text.Json;
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
            if (!File.Exists(path))
            {
                return [];
            }

            await using FileStream stream = File.OpenRead(path);
            return await JsonSerializer.DeserializeAsync(stream, AdminJsonContext.Default.ListHsmDeviceProfile, cancellationToken) ?? [];
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
            string path = GetPath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await using FileStream stream = File.Create(path);
            await JsonSerializer.SerializeAsync(stream, devices.ToList(), AdminJsonContext.Default.ListHsmDeviceProfile, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    private string GetPath() => Path.Combine(options.DataRoot, options.DeviceProfilesFileName);
}
