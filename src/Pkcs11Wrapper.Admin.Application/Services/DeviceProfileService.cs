using System.Text;
using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Services;

public sealed class DeviceProfileService(IDeviceProfileStore store)
{
    private sealed record ImportCandidate(int Index, HsmDeviceProfile SourceProfile, HsmDeviceProfile? NormalizedProfile, string? ValidationError)
    {
        public bool IsValid => NormalizedProfile is not null && ValidationError is null;
    }

    private sealed record ImportEvaluation(
        IReadOnlyList<HsmDeviceProfile> ExistingProfiles,
        IReadOnlyList<HsmDeviceProfile> ReadyProfiles,
        AdminConfigurationImportAnalysis Analysis);

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

    public async Task<AdminConfigurationImportAnalysis> AnalyzeImportAsync(IReadOnlyList<HsmDeviceProfile> importedProfiles, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(importedProfiles);

        List<HsmDeviceProfile> existing = [.. await store.GetAllAsync(cancellationToken)];
        return EvaluateImport(existing, importedProfiles).Analysis;
    }

    public async Task<AdminConfigurationImportResult> ImportAsync(IReadOnlyList<HsmDeviceProfile> importedProfiles, AdminConfigurationImportMode mode, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(importedProfiles);

        List<HsmDeviceProfile> existing = [.. await store.GetAllAsync(cancellationToken)];
        ImportEvaluation evaluation = EvaluateImport(existing, importedProfiles);
        AdminConfigurationImportImpact impact = mode switch
        {
            AdminConfigurationImportMode.Merge => evaluation.Analysis.MergeImpact,
            AdminConfigurationImportMode.ReplaceAll => evaluation.Analysis.ReplaceAllImpact,
            _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unsupported configuration import mode.")
        };

        if (!impact.CanImport)
        {
            throw new InvalidOperationException(impact.Blockers.FirstOrDefault() ?? "Configuration import is blocked by preflight validation.");
        }

        switch (mode)
        {
            case AdminConfigurationImportMode.Merge:
            {
                List<HsmDeviceProfile> merged = [.. existing];
                foreach (HsmDeviceProfile importedProfile in evaluation.ReadyProfiles)
                {
                    int existingIndex = merged.FindIndex(x => x.Id == importedProfile.Id);
                    if (existingIndex >= 0)
                    {
                        merged[existingIndex] = importedProfile;
                        continue;
                    }

                    merged.Add(importedProfile);
                }

                await store.SaveAllAsync(merged, cancellationToken);
                return new(
                    mode,
                    importedProfiles.Count,
                    impact.AddedDeviceProfileCount,
                    impact.UpdatedDeviceProfileCount,
                    0,
                    $"Merged {importedProfiles.Count} device profile(s): {impact.AddedDeviceProfileCount} added, {impact.UpdatedDeviceProfileCount} updated.",
                    []);
            }

            case AdminConfigurationImportMode.ReplaceAll:
                await store.SaveAllAsync(evaluation.ReadyProfiles, cancellationToken);
                return new(
                    mode,
                    importedProfiles.Count,
                    impact.AddedDeviceProfileCount,
                    0,
                    impact.RemovedDeviceProfileCount,
                    $"Replaced device configuration with {importedProfiles.Count} imported profile(s); removed {impact.RemovedDeviceProfileCount} existing profile(s).",
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

    private static ImportEvaluation EvaluateImport(IReadOnlyList<HsmDeviceProfile> existingProfiles, IReadOnlyList<HsmDeviceProfile> importedProfiles)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        List<ImportCandidate> candidates = [];
        List<AdminConfigurationImportIssue> issues = [];
        List<string> commonBlockers = [];

        for (int index = 0; index < importedProfiles.Count; index++)
        {
            HsmDeviceProfile sourceProfile = importedProfiles[index];
            try
            {
                HsmDeviceProfile normalized = NormalizeImported(sourceProfile, now);
                candidates.Add(new(index, sourceProfile, normalized, null));
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
            {
                string profileName = GetDisplayName(sourceProfile.Name);
                string? profileId = TryFormatProfileId(sourceProfile.Id);
                candidates.Add(new(index, sourceProfile, null, ex.Message));
                commonBlockers.Add(ex.Message);
                issues.Add(new("All modes", "Error", profileName, profileId, $"Profile #{index + 1}: {ex.Message}"));
            }
        }

        List<ImportCandidate> validCandidates = candidates.Where(candidate => candidate.IsValid).ToList();
        HashSet<int> duplicateIndexes = [];

        foreach (IGrouping<Guid, ImportCandidate> group in validCandidates.GroupBy(candidate => candidate.NormalizedProfile!.Id).Where(group => group.Count() > 1))
        {
            string message = $"Imported configuration contains duplicate device id '{group.Key}'.";
            commonBlockers.Add(message);
            foreach (ImportCandidate candidate in group)
            {
                duplicateIndexes.Add(candidate.Index);
            }

            string profileNames = string.Join(", ", group.Select(candidate => candidate.NormalizedProfile!.Name).Distinct(StringComparer.OrdinalIgnoreCase));
            issues.Add(new("All modes", "Error", profileNames, group.Key.ToString(), message));
        }

        foreach (IGrouping<string, ImportCandidate> group in validCandidates.GroupBy(candidate => candidate.NormalizedProfile!.Name, StringComparer.OrdinalIgnoreCase).Where(group => group.Count() > 1))
        {
            string message = $"Imported configuration contains duplicate device name '{group.Key}'.";
            commonBlockers.Add(message);
            foreach (ImportCandidate candidate in group)
            {
                duplicateIndexes.Add(candidate.Index);
            }

            string profileIds = string.Join(", ", group.Select(candidate => candidate.NormalizedProfile!.Id.ToString()).Distinct(StringComparer.OrdinalIgnoreCase));
            issues.Add(new("All modes", "Error", group.Key, profileIds, message));
        }

        List<HsmDeviceProfile> readyProfiles = validCandidates
            .Where(candidate => !duplicateIndexes.Contains(candidate.Index))
            .Select(candidate => candidate.NormalizedProfile!)
            .ToList();

        Dictionary<Guid, HsmDeviceProfile> existingById = existingProfiles.ToDictionary(profile => profile.Id);
        Dictionary<string, HsmDeviceProfile> existingByName = existingProfiles.ToDictionary(profile => profile.Name, StringComparer.OrdinalIgnoreCase);

        List<HsmDeviceProfile> mergeAddedProfiles = [];
        List<HsmDeviceProfile> mergeUpdatedProfiles = [];
        List<string> mergeBlockers = [.. commonBlockers];
        List<HsmDeviceProfile> mergeConflictProfiles = [];

        foreach (HsmDeviceProfile profile in readyProfiles)
        {
            if (existingById.ContainsKey(profile.Id))
            {
                mergeUpdatedProfiles.Add(profile);
                continue;
            }

            if (existingByName.TryGetValue(profile.Name, out HsmDeviceProfile? conflictingName) && conflictingName.Id != profile.Id)
            {
                string message = $"Import would create a conflicting device name '{profile.Name}'. Rename the device or use Replace All.";
                mergeBlockers.Add(message);
                mergeConflictProfiles.Add(profile);
                issues.Add(new("Merge only", "Error", profile.Name, profile.Id.ToString(), message));
                continue;
            }

            mergeAddedProfiles.Add(profile);
        }

        List<string> replaceBlockers = [.. commonBlockers];

        AdminConfigurationImportImpact mergeImpact = new(
            AdminConfigurationImportMode.Merge,
            mergeBlockers.Count == 0,
            existingProfiles.Count + mergeAddedProfiles.Count,
            mergeAddedProfiles.Count,
            mergeUpdatedProfiles.Count,
            0,
            duplicateIndexes.Count + mergeConflictProfiles.Count,
            candidates.Count(candidate => !candidate.IsValid),
            [.. mergeAddedProfiles.Select(profile => profile.Name).OrderBy(name => name, StringComparer.OrdinalIgnoreCase)],
            [.. mergeUpdatedProfiles.Select(profile => profile.Name).OrderBy(name => name, StringComparer.OrdinalIgnoreCase)],
            [],
            mergeBlockers,
            BuildSummary(AdminConfigurationImportMode.Merge, mergeAddedProfiles.Count, mergeUpdatedProfiles.Count, 0, duplicateIndexes.Count + mergeConflictProfiles.Count, candidates.Count(candidate => !candidate.IsValid), existingProfiles.Count + mergeAddedProfiles.Count, mergeBlockers.Count == 0));

        AdminConfigurationImportImpact replaceAllImpact = new(
            AdminConfigurationImportMode.ReplaceAll,
            replaceBlockers.Count == 0,
            readyProfiles.Count,
            readyProfiles.Count,
            0,
            existingProfiles.Count,
            duplicateIndexes.Count,
            candidates.Count(candidate => !candidate.IsValid),
            [.. readyProfiles.Select(profile => profile.Name).OrderBy(name => name, StringComparer.OrdinalIgnoreCase)],
            [],
            [.. existingProfiles.Select(profile => profile.Name).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(name => name, StringComparer.OrdinalIgnoreCase)],
            replaceBlockers,
            BuildSummary(AdminConfigurationImportMode.ReplaceAll, readyProfiles.Count, 0, existingProfiles.Count, duplicateIndexes.Count, candidates.Count(candidate => !candidate.IsValid), readyProfiles.Count, replaceBlockers.Count == 0));

        AdminConfigurationImportAnalysis analysis = new(
            existingProfiles.Count,
            importedProfiles.Count,
            readyProfiles.Count,
            duplicateIndexes.Count,
            candidates.Count(candidate => !candidate.IsValid),
            mergeImpact,
            replaceAllImpact,
            issues);

        return new(existingProfiles, readyProfiles, analysis);
    }

    private static string BuildSummary(
        AdminConfigurationImportMode mode,
        int added,
        int updated,
        int removed,
        int duplicateCount,
        int invalidCount,
        int finalCount,
        bool canImport)
    {
        string action = mode == AdminConfigurationImportMode.Merge
            ? $"Would add {added} and update {updated} device profile(s)."
            : $"Would apply {added} imported device profile(s) and remove {removed} current profile(s).";

        string finalState = $" Final device count: {finalCount}.";
        if (canImport)
        {
            return action + finalState;
        }

        return action + finalState + $" Blocked by {duplicateCount} duplicate/conflicting and {invalidCount} invalid profile(s).";
    }

    private static string GetDisplayName(string? value)
        => string.IsNullOrWhiteSpace(value) ? "<unnamed>" : value.Trim();

    private static string? TryFormatProfileId(Guid id)
        => id == Guid.Empty ? null : id.ToString();

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
