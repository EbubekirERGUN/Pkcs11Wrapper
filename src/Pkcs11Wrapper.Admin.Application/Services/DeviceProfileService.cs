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

    public async Task<AdminConfigurationImportResult> ImportAsync(IReadOnlyList<HsmDeviceProfile> importedProfiles, AdminConfigurationImportMode mode, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(importedProfiles);

        DateTimeOffset now = DateTimeOffset.UtcNow;
        List<HsmDeviceProfile> imported = importedProfiles.Select(profile => NormalizeImported(profile, now)).ToList();
        ValidateImportedProfiles(imported);

        List<HsmDeviceProfile> existing = [.. await store.GetAllAsync(cancellationToken)];
        int added = 0;
        int updated = 0;
        int removed = 0;

        switch (mode)
        {
            case AdminConfigurationImportMode.Merge:
                foreach (HsmDeviceProfile importedProfile in imported)
                {
                    int existingIndex = existing.FindIndex(x => x.Id == importedProfile.Id);
                    if (existingIndex >= 0)
                    {
                        existing[existingIndex] = importedProfile;
                        updated++;
                        continue;
                    }

                    HsmDeviceProfile? conflictingName = existing.FirstOrDefault(x => string.Equals(x.Name, importedProfile.Name, StringComparison.OrdinalIgnoreCase));
                    if (conflictingName is not null)
                    {
                        throw new InvalidOperationException($"Import would create a conflicting device name '{importedProfile.Name}'. Rename the device or use Replace All.");
                    }

                    existing.Add(importedProfile);
                    added++;
                }

                await store.SaveAllAsync(existing, cancellationToken);
                return new(
                    mode,
                    imported.Count,
                    added,
                    updated,
                    0,
                    $"Merged {imported.Count} device profile(s): {added} added, {updated} updated.",
                    []);

            case AdminConfigurationImportMode.ReplaceAll:
                removed = existing.Count;
                await store.SaveAllAsync(imported, cancellationToken);
                return new(
                    mode,
                    imported.Count,
                    imported.Count,
                    0,
                    removed,
                    $"Replaced device configuration with {imported.Count} imported profile(s); removed {removed} existing profile(s).",
                    []);

            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unsupported configuration import mode.");
        }
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

    private static HsmDeviceProfile NormalizeImported(HsmDeviceProfile profile, DateTimeOffset now)
    {
        string name = string.IsNullOrWhiteSpace(profile.Name)
            ? throw new ArgumentException("Imported device name is required.", nameof(profile))
            : profile.Name.Trim();
        string modulePath = string.IsNullOrWhiteSpace(profile.ModulePath)
            ? throw new ArgumentException($"Imported module path is required for device '{name}'.", nameof(profile))
            : profile.ModulePath.Trim();

        Guid id = profile.Id == Guid.Empty ? Guid.NewGuid() : profile.Id;
        DateTimeOffset createdUtc = profile.CreatedUtc == default ? now : profile.CreatedUtc;
        DateTimeOffset updatedUtc = profile.UpdatedUtc == default ? createdUtc : profile.UpdatedUtc;
        if (updatedUtc < createdUtc)
        {
            updatedUtc = createdUtc;
        }

        return profile with
        {
            Id = id,
            Name = name,
            ModulePath = modulePath,
            DefaultTokenLabel = Normalize(profile.DefaultTokenLabel),
            Notes = Normalize(profile.Notes),
            CreatedUtc = createdUtc,
            UpdatedUtc = updatedUtc
        };
    }

    private static void ValidateImportedProfiles(IReadOnlyList<HsmDeviceProfile> profiles)
    {
        HashSet<Guid> ids = [];
        HashSet<string> names = new(StringComparer.OrdinalIgnoreCase);

        foreach (HsmDeviceProfile profile in profiles)
        {
            if (!ids.Add(profile.Id))
            {
                throw new InvalidOperationException($"Imported configuration contains duplicate device id '{profile.Id}'.");
            }

            if (!names.Add(profile.Name))
            {
                throw new InvalidOperationException($"Imported configuration contains duplicate device name '{profile.Name}'.");
            }
        }
    }

    private static string? Normalize(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
