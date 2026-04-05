using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Runtime;

public sealed class CryptoApiConfiguredRouteRegistry : ICryptoApiRouteRegistry
{
    private readonly IReadOnlyDictionary<string, ConfiguredRouteGroup> _routeGroups;
    private readonly HashSet<string> _enabledBackendNames;

    public CryptoApiConfiguredRouteRegistry(IOptions<CryptoApiRuntimeOptions> runtimeOptions)
    {
        ArgumentNullException.ThrowIfNull(runtimeOptions);

        CryptoApiRuntimeOptions options = runtimeOptions.Value;
        _enabledBackendNames = options.Backends
            .Where(static backend => backend.Enabled)
            .Select(backend => NormalizeMachineName(backend.Name, nameof(backend.Name)))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        _routeGroups = options.RouteGroups
            .Select(BuildRouteGroup)
            .ToDictionary(group => group.Name, StringComparer.OrdinalIgnoreCase);
    }

    public CryptoApiRoutePlanResolutionResult Resolve(CryptoApiKeyAliasRecord alias)
    {
        ArgumentNullException.ThrowIfNull(alias);

        if (!string.IsNullOrWhiteSpace(alias.RouteGroupName))
        {
            if (!_routeGroups.TryGetValue(alias.RouteGroupName.Trim(), out ConfiguredRouteGroup? group))
            {
                return CryptoApiRoutePlanResolutionResult.Failure(
                    $"Route group '{alias.RouteGroupName}' is not configured on this Crypto API host.");
            }

            IReadOnlyList<CryptoApiRouteCandidate> candidates = group.Candidates
                .Where(candidate => _enabledBackendNames.Count == 0 || _enabledBackendNames.Contains(candidate.DeviceRoute ?? string.Empty))
                .Select(candidate => new CryptoApiRouteCandidate(candidate.DeviceRoute, candidate.SlotId, candidate.Priority))
                .ToArray();

            if (candidates.Count == 0)
            {
                return CryptoApiRoutePlanResolutionResult.Failure(
                    $"Route group '{group.Name}' does not have any locally enabled backend candidates.");
            }

            return CryptoApiRoutePlanResolutionResult.Success(
                new CryptoApiRoutePlan(
                    RouteGroupName: group.Name,
                    SelectionMode: group.SelectionMode,
                    Candidates: candidates,
                    ObjectLabel: alias.ObjectLabel,
                    ObjectIdHex: alias.ObjectIdHex));
        }

        if (alias.SlotId is null)
        {
            return CryptoApiRoutePlanResolutionResult.Failure(
                $"Key alias '{alias.AliasName}' does not define a slot id or route group.");
        }

        return CryptoApiRoutePlanResolutionResult.Success(
            new CryptoApiRoutePlan(
                RouteGroupName: null,
                SelectionMode: "legacy-single-route",
                Candidates:
                [
                    new CryptoApiRouteCandidate(
                        DeviceRoute: alias.DeviceRoute,
                        SlotId: alias.SlotId.Value,
                        Priority: 0)
                ],
                ObjectLabel: alias.ObjectLabel,
                ObjectIdHex: alias.ObjectIdHex));
    }

    private static ConfiguredRouteGroup BuildRouteGroup(CryptoApiRuntimeRouteGroupOptions group)
    {
        string groupName = NormalizeMachineName(group.Name, nameof(group.Name));
        string selectionMode = NormalizeSelectionMode(group.SelectionMode);
        ConfiguredRouteCandidate[] candidates = group.Backends
            .Where(static backend => backend.Enabled)
            .Select(backend => new ConfiguredRouteCandidate(
                DeviceRoute: NormalizeMachineName(backend.BackendName, nameof(backend.BackendName)),
                SlotId: backend.SlotId,
                Priority: backend.Priority))
            .OrderBy(candidate => candidate.Priority)
            .ThenBy(candidate => candidate.DeviceRoute, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new ConfiguredRouteGroup(groupName, selectionMode, candidates);
    }

    internal static IReadOnlyList<string> Validate(CryptoApiRuntimeOptions options)
    {
        List<string> errors = [];
        ArgumentNullException.ThrowIfNull(options);

        HashSet<string> backendNames = new(StringComparer.OrdinalIgnoreCase);
        foreach (CryptoApiRuntimeBackendOptions backend in options.Backends)
        {
            string name;
            try
            {
                name = NormalizeMachineName(backend.Name, nameof(backend.Name));
            }
            catch (ArgumentException ex)
            {
                errors.Add($"CryptoApiRuntime:Backends contains an invalid backend name: {ex.Message}");
                continue;
            }

            if (!backendNames.Add(name))
            {
                errors.Add($"CryptoApiRuntime:Backends contains duplicate backend '{name}'.");
            }
        }

        HashSet<string> routeGroupNames = new(StringComparer.OrdinalIgnoreCase);
        foreach (CryptoApiRuntimeRouteGroupOptions group in options.RouteGroups)
        {
            string groupName;
            try
            {
                groupName = NormalizeMachineName(group.Name, nameof(group.Name));
            }
            catch (ArgumentException ex)
            {
                errors.Add($"CryptoApiRuntime:RouteGroups contains an invalid group name: {ex.Message}");
                continue;
            }

            if (!routeGroupNames.Add(groupName))
            {
                errors.Add($"CryptoApiRuntime:RouteGroups contains duplicate group '{groupName}'.");
            }

            string selectionMode;
            try
            {
                selectionMode = NormalizeSelectionMode(group.SelectionMode);
            }
            catch (ArgumentException ex)
            {
                errors.Add($"CryptoApiRuntime:RouteGroups:{groupName}: {ex.Message}");
                continue;
            }

            if (!string.Equals(selectionMode, "priority", StringComparison.Ordinal))
            {
                errors.Add($"CryptoApiRuntime:RouteGroups:{groupName} uses unsupported selection mode '{selectionMode}'.");
            }

            if (group.Backends.Count == 0 || !group.Backends.Any(static backend => backend.Enabled))
            {
                errors.Add($"CryptoApiRuntime:RouteGroups:{groupName} must declare at least one enabled backend candidate.");
                continue;
            }

            HashSet<string> backendCandidates = new(StringComparer.OrdinalIgnoreCase);
            foreach (CryptoApiRuntimeRouteBackendOptions backend in group.Backends.Where(static candidate => candidate.Enabled))
            {
                string backendName;
                try
                {
                    backendName = NormalizeMachineName(backend.BackendName, nameof(backend.BackendName));
                }
                catch (ArgumentException ex)
                {
                    errors.Add($"CryptoApiRuntime:RouteGroups:{groupName} contains an invalid backend reference: {ex.Message}");
                    continue;
                }

                string dedupeKey = $"{backendName}:{backend.SlotId}:{backend.Priority}";
                if (!backendCandidates.Add(dedupeKey))
                {
                    errors.Add($"CryptoApiRuntime:RouteGroups:{groupName} repeats backend '{backendName}' slot '{backend.SlotId}' priority '{backend.Priority}'.");
                }

                if (backendNames.Count > 0 && !backendNames.Contains(backendName))
                {
                    errors.Add($"CryptoApiRuntime:RouteGroups:{groupName} references undefined backend '{backendName}'.");
                }
            }
        }

        return errors;
    }

    internal static string NormalizeMachineName(string? value, string parameterName)
    {
        string normalized = string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException("Value is required.", parameterName)
            : value.Trim();

        foreach (char c in normalized)
        {
            if (!(char.IsLetterOrDigit(c) || c is '-' or '_' or '.'))
            {
                throw new ArgumentException("Only letters, digits, dash, underscore, and dot are allowed.", parameterName);
            }
        }

        return normalized;
    }

    internal static string NormalizeSelectionMode(string? value)
    {
        string normalized = string.IsNullOrWhiteSpace(value) ? "priority" : value.Trim().ToLowerInvariant();
        if (!string.Equals(normalized, "priority", StringComparison.Ordinal))
        {
            throw new ArgumentException("Only the 'priority' selection mode is currently supported.", nameof(value));
        }

        return normalized;
    }

    private sealed record ConfiguredRouteGroup(
        string Name,
        string SelectionMode,
        IReadOnlyList<ConfiguredRouteCandidate> Candidates);

    private sealed record ConfiguredRouteCandidate(
        string? DeviceRoute,
        ulong SlotId,
        int Priority);
}

public sealed class CryptoApiRuntimeOptionsValidator : IValidateOptions<CryptoApiRuntimeOptions>
{
    public ValidateOptionsResult Validate(string? name, CryptoApiRuntimeOptions options)
    {
        IReadOnlyList<string> errors = CryptoApiConfiguredRouteRegistry.Validate(options);
        return errors.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(errors);
    }
}
