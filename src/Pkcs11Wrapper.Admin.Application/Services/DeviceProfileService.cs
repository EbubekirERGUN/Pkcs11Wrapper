using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Services;

public sealed class DeviceProfileService(IDeviceProfileStore store)
{
    public async Task<IReadOnlyList<HsmDeviceProfile>> GetAllAsync(CancellationToken cancellationToken = default)
        => (await store.GetAllAsync(cancellationToken)).OrderBy(x => x.Name, StringComparer.OrdinalIgnoreCase).ToArray();

    public async Task<HsmDeviceProfile?> GetAsync(Guid id, CancellationToken cancellationToken = default)
        => (await store.GetAllAsync(cancellationToken)).FirstOrDefault(x => x.Id == id);

    public async Task<HsmDeviceProfile> UpsertAsync(Guid? id, HsmDeviceProfileInput input, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        Validate(input);

        List<HsmDeviceProfile> devices = [.. await store.GetAllAsync(cancellationToken)];
        DateTimeOffset now = DateTimeOffset.UtcNow;

        if (id is Guid existingId)
        {
            int index = devices.FindIndex(x => x.Id == existingId);
            if (index < 0)
            {
                throw new InvalidOperationException($"Device profile '{existingId}' was not found.");
            }

            HsmDeviceProfile current = devices[index];
            HsmDeviceProfile updated = current with
            {
                Name = input.Name.Trim(),
                ModulePath = input.ModulePath.Trim(),
                DefaultTokenLabel = Normalize(input.DefaultTokenLabel),
                Notes = Normalize(input.Notes),
                IsEnabled = input.IsEnabled,
                UpdatedUtc = now
            };

            devices[index] = updated;
            await store.SaveAllAsync(devices, cancellationToken);
            return updated;
        }

        HsmDeviceProfile created = new(
            Guid.NewGuid(),
            input.Name.Trim(),
            input.ModulePath.Trim(),
            Normalize(input.DefaultTokenLabel),
            Normalize(input.Notes),
            input.IsEnabled,
            now,
            now);

        devices.Add(created);
        await store.SaveAllAsync(devices, cancellationToken);
        return created;
    }

    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        List<HsmDeviceProfile> devices = [.. await store.GetAllAsync(cancellationToken)];
        devices.RemoveAll(x => x.Id == id);
        await store.SaveAllAsync(devices, cancellationToken);
    }

    private static void Validate(HsmDeviceProfileInput input)
    {
        if (string.IsNullOrWhiteSpace(input.Name))
        {
            throw new ArgumentException("Device name is required.", nameof(input));
        }

        if (string.IsNullOrWhiteSpace(input.ModulePath))
        {
            throw new ArgumentException("PKCS#11 module path is required.", nameof(input));
        }
    }

    private static string? Normalize(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
