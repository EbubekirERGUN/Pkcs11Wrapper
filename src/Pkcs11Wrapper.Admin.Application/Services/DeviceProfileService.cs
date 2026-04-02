using System.Text;
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

        List<HsmDeviceProfile> devices = [.. await store.GetAllAsync(cancellationToken)];
        string normalizedName = ValidateName(input.Name);
        string normalizedModulePath = ValidateModulePath(input.ModulePath);
        string? normalizedTokenLabel = Normalize(input.DefaultTokenLabel);
        string? normalizedNotes = Normalize(input.Notes);
        HsmDeviceVendorMetadata? normalizedVendor = NormalizeVendorMetadata(input.VendorId, input.VendorName, input.VendorProfileId, input.VendorProfileName);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        EnsureUniqueName(devices, normalizedName, id);

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
                Name = normalizedName,
                ModulePath = normalizedModulePath,
                DefaultTokenLabel = normalizedTokenLabel,
                Notes = normalizedNotes,
                IsEnabled = input.IsEnabled,
                UpdatedUtc = now,
                Vendor = normalizedVendor
            };

            devices[index] = updated;
            await store.SaveAllAsync(devices, cancellationToken);
            return updated;
        }

        HsmDeviceProfile created = new(
            Guid.NewGuid(),
            normalizedName,
            normalizedModulePath,
            normalizedTokenLabel,
            normalizedNotes,
            input.IsEnabled,
            now,
            now,
            normalizedVendor);

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
        int removed = devices.RemoveAll(x => x.Id == id);
        if (removed == 0)
        {
            throw new InvalidOperationException($"Device profile '{id}' was not found.");
        }

        await store.SaveAllAsync(devices, cancellationToken);
    }

    private static string ValidateName(string? value)
    {
        string name = value?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Device name is required.", nameof(value));
        }

        if (name.Length > 128)
        {
            throw new ArgumentException("Device name must be 128 characters or fewer.", nameof(value));
        }

        return name;
    }

    private static string ValidateModulePath(string? value)
    {
        string modulePath = value?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(modulePath))
        {
            throw new ArgumentException("PKCS#11 module path is required.", nameof(value));
        }

        if (modulePath.Length > 4096)
        {
            throw new ArgumentException("PKCS#11 module path is unexpectedly long.", nameof(value));
        }

        return modulePath;
    }

    private static void EnsureUniqueName(IEnumerable<HsmDeviceProfile> devices, string name, Guid? currentId)
    {
        HsmDeviceProfile? conflict = devices.FirstOrDefault(device =>
            string.Equals(device.Name, name, StringComparison.OrdinalIgnoreCase)
            && (!currentId.HasValue || device.Id != currentId.Value));

        if (conflict is not null)
        {
            throw new InvalidOperationException($"Device name '{name}' is already assigned to '{conflict.Id}'.");
        }
    }

    private static HsmDeviceProfile NormalizeImported(HsmDeviceProfile profile, DateTimeOffset now)
    {
        string name = ValidateName(profile.Name);
        string modulePath = ValidateModulePath(profile.ModulePath);

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
            UpdatedUtc = updatedUtc,
            Vendor = NormalizeVendorMetadata(profile.Vendor)
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

    private static HsmDeviceVendorMetadata? NormalizeVendorMetadata(HsmDeviceVendorMetadata? vendor)
        => vendor is null ? null : NormalizeVendorMetadata(vendor.VendorId, vendor.VendorName, vendor.ProfileId, vendor.ProfileName);

    private static HsmDeviceVendorMetadata? NormalizeVendorMetadata(string? vendorId, string? vendorName, string? profileId, string? profileName)
    {
        string? normalizedVendorId = NormalizeIdentifier(vendorId);
        string? normalizedVendorName = Normalize(vendorName);
        string? normalizedProfileId = NormalizeIdentifier(profileId);
        string? normalizedProfileName = Normalize(profileName);

        if (normalizedVendorId is null && normalizedVendorName is null && normalizedProfileId is null && normalizedProfileName is null)
        {
            return null;
        }

        normalizedVendorId ??= NormalizeIdentifier(normalizedVendorName)
            ?? throw new ArgumentException("Vendor metadata requires a vendor id or vendor name.", nameof(vendorId));
        normalizedVendorName ??= normalizedVendorId;
        normalizedProfileId ??= NormalizeIdentifier(normalizedProfileName);
        normalizedProfileName ??= normalizedProfileId;

        ValidateOptionalLength(normalizedVendorId, 64, "Vendor id");
        ValidateOptionalLength(normalizedVendorName, 128, "Vendor name");
        ValidateOptionalLength(normalizedProfileId, 64, "Vendor profile id");
        ValidateOptionalLength(normalizedProfileName, 128, "Vendor profile name");

        return new(normalizedVendorId, normalizedVendorName, normalizedProfileId, normalizedProfileName);
    }

    private static string? NormalizeIdentifier(string? value)
    {
        string? normalized = Normalize(value);
        if (normalized is null)
        {
            return null;
        }

        StringBuilder builder = new(normalized.Length);
        bool pendingSeparator = false;
        foreach (char character in normalized)
        {
            if (char.IsLetterOrDigit(character))
            {
                if (pendingSeparator && builder.Length > 0)
                {
                    builder.Append('-');
                }

                builder.Append(char.ToLowerInvariant(character));
                pendingSeparator = false;
            }
            else
            {
                pendingSeparator = builder.Length > 0;
            }
        }

        return builder.Length == 0 ? null : builder.ToString();
    }

    private static void ValidateOptionalLength(string? value, int maxLength, string description)
    {
        if (value is not null && value.Length > maxLength)
        {
            throw new ArgumentException($"{description} must be {maxLength} characters or fewer.", description);
        }
    }

    private static string? Normalize(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
