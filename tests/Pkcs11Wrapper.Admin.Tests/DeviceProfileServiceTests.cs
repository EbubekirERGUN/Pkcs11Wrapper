using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class DeviceProfileServiceTests
{
    [Fact]
    public async Task UpsertAsyncCreatesAndUpdatesDevice()
    {
        InMemoryDeviceProfileStore store = new();
        DeviceProfileService service = new(store);

        HsmDeviceProfile created = await service.UpsertAsync(null, new HsmDeviceProfileInput
        {
            Name = "Local HSM",
            ModulePath = "/usr/lib/libpkcs11.so",
            DefaultTokenLabel = "token-a",
            Notes = "notes",
            IsEnabled = true
        });

        Assert.Equal("Local HSM", created.Name);
        Assert.Single(await service.GetAllAsync());

        HsmDeviceProfile updated = await service.UpsertAsync(created.Id, new HsmDeviceProfileInput
        {
            Name = "Updated HSM",
            ModulePath = "C:/pkcs11.dll",
            DefaultTokenLabel = "token-b",
            Notes = "updated",
            IsEnabled = false
        });

        Assert.Equal(created.Id, updated.Id);
        Assert.Equal("Updated HSM", updated.Name);
        Assert.Equal("C:/pkcs11.dll", updated.ModulePath);
        Assert.False(updated.IsEnabled);
    }

    [Fact]
    public async Task UpsertAsyncRejectsMissingNameOrModulePath()
    {
        InMemoryDeviceProfileStore store = new();
        DeviceProfileService service = new(store);

        await Assert.ThrowsAsync<ArgumentException>(() => service.UpsertAsync(null, new HsmDeviceProfileInput { Name = "", ModulePath = "/tmp/pkcs11.so" }));
        await Assert.ThrowsAsync<ArgumentException>(() => service.UpsertAsync(null, new HsmDeviceProfileInput { Name = "HSM", ModulePath = "" }));
    }

    [Fact]
    public async Task UpsertAsyncRejectsDuplicateNamesCaseInsensitive()
    {
        InMemoryDeviceProfileStore store = new();
        DeviceProfileService service = new(store);
        await service.UpsertAsync(null, new HsmDeviceProfileInput { Name = "Primary", ModulePath = "/tmp/a.so", IsEnabled = true });

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() => service.UpsertAsync(null, new HsmDeviceProfileInput { Name = "primary", ModulePath = "/tmp/b.so", IsEnabled = true }));
        Assert.Contains("already assigned", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DeleteAsyncRejectsUnknownDevice()
    {
        InMemoryDeviceProfileStore store = new();
        DeviceProfileService service = new(store);

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() => service.DeleteAsync(Guid.NewGuid()));
        Assert.Contains("was not found", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class InMemoryDeviceProfileStore : IDeviceProfileStore
    {
        private List<HsmDeviceProfile> _devices = [];

        public Task<IReadOnlyList<HsmDeviceProfile>> GetAllAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<HsmDeviceProfile>>(_devices.ToArray());

        public Task SaveAllAsync(IReadOnlyList<HsmDeviceProfile> devices, CancellationToken cancellationToken = default)
        {
            _devices = [.. devices];
            return Task.CompletedTask;
        }
    }
}
