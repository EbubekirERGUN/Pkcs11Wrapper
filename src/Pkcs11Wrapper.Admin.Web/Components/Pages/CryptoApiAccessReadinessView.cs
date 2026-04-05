using Pkcs11Wrapper.Admin.Web.Configuration;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Clients;

namespace Pkcs11Wrapper.Admin.Web.Components.Pages;

public static class CryptoApiAccessReadinessView
{
    public static CryptoApiAccessReadinessState Build(
        CryptoApiClientManagementSnapshot clientSnapshot,
        CryptoApiKeyAccessSnapshot accessSnapshot,
        AdminCryptoApiRouteRuntimeOptions? runtimeOptions,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(clientSnapshot);
        ArgumentNullException.ThrowIfNull(accessSnapshot);

        CryptoApiRuntimeInspection runtimeInspection = CryptoApiRuntimeInspection.Create(runtimeOptions);
        IReadOnlyDictionary<Guid, CryptoApiManagedClient> clientsById = clientSnapshot.Clients.ToDictionary(client => client.ClientId);
        IReadOnlyDictionary<Guid, CryptoApiManagedKeyAlias> aliasesById = accessSnapshot.KeyAliases.ToDictionary(alias => alias.AliasId);
        IReadOnlyDictionary<Guid, CryptoApiManagedPolicy> policiesById = accessSnapshot.Policies.ToDictionary(policy => policy.PolicyId);
        HashSet<Guid> enabledPolicyIds = accessSnapshot.Policies
            .Where(static policy => policy.IsEnabled)
            .Select(policy => policy.PolicyId)
            .ToHashSet();
        IReadOnlyDictionary<Guid, int> activeKeysByClientId = clientSnapshot.Clients.ToDictionary(
            client => client.ClientId,
            client => client.Keys.Count(key => IsActiveKey(key, nowUtc)));

        List<CryptoApiClientAliasReadinessViewItem> routes = [];
        foreach (CryptoApiManagedClient client in clientSnapshot.Clients)
        {
            foreach (CryptoApiManagedKeyAlias alias in accessSnapshot.KeyAliases)
            {
                routes.Add(BuildRoute(client, alias, policiesById, enabledPolicyIds, activeKeysByClientId, runtimeInspection));
            }
        }

        IReadOnlyList<CryptoApiClientReadinessViewItem> clients = clientSnapshot.Clients
            .Select(client => BuildClient(client, accessSnapshot.KeyAliases, routes, enabledPolicyIds, activeKeysByClientId))
            .ToArray();
        IReadOnlyList<CryptoApiAliasReadinessViewItem> aliases = accessSnapshot.KeyAliases
            .Select(alias => BuildAlias(alias, clientSnapshot.Clients, routes, enabledPolicyIds, activeKeysByClientId))
            .ToArray();
        IReadOnlyList<CryptoApiPolicyReadinessViewItem> policies = accessSnapshot.Policies
            .Select(policy => BuildPolicy(policy, clientsById, aliasesById, routes, activeKeysByClientId))
            .ToArray();

        return new CryptoApiAccessReadinessState(
            RuntimeInspectionConfigured: runtimeInspection.HasRuntimeContext,
            RuntimeInspectionSummary: runtimeInspection.Summary,
            Clients: clients,
            Aliases: aliases,
            Policies: policies,
            Routes: routes);
    }

    public static CryptoApiClientReadinessViewItem? GetClient(CryptoApiAccessReadinessState? state, Guid clientId)
        => state?.Clients.FirstOrDefault(item => item.ClientId == clientId);

    public static CryptoApiAliasReadinessViewItem? GetAlias(CryptoApiAccessReadinessState? state, Guid aliasId)
        => state?.Aliases.FirstOrDefault(item => item.AliasId == aliasId);

    public static CryptoApiPolicyReadinessViewItem? GetPolicy(CryptoApiAccessReadinessState? state, Guid policyId)
        => state?.Policies.FirstOrDefault(item => item.PolicyId == policyId);

    public static IReadOnlyList<CryptoApiClientAliasReadinessViewItem> GetRoutesForClient(CryptoApiAccessReadinessState? state, Guid clientId)
        => state?.Routes
            .Where(item => item.ClientId == clientId)
            .OrderBy(item => item.Level)
            .ThenBy(item => item.AliasName, StringComparer.OrdinalIgnoreCase)
            .ToArray()
            ?? [];

    public static IReadOnlyList<CryptoApiClientAliasReadinessViewItem> GetRoutesForAlias(CryptoApiAccessReadinessState? state, Guid aliasId)
        => state?.Routes
            .Where(item => item.AliasId == aliasId)
            .OrderBy(item => item.Level)
            .ThenBy(item => item.ClientDisplayName, StringComparer.OrdinalIgnoreCase)
            .ToArray()
            ?? [];

    private static CryptoApiClientAliasReadinessViewItem BuildRoute(
        CryptoApiManagedClient client,
        CryptoApiManagedKeyAlias alias,
        IReadOnlyDictionary<Guid, CryptoApiManagedPolicy> policiesById,
        HashSet<Guid> enabledPolicyIds,
        IReadOnlyDictionary<Guid, int> activeKeysByClientId,
        CryptoApiRuntimeInspection runtimeInspection)
    {
        List<CryptoApiAccessReadinessIssue> issues = [];

        if (!client.IsEnabled)
        {
            issues.Add(Blocker($"Client '{client.DisplayName}' is disabled.", CryptoApiAccessReadinessTargetKind.Client, client.ClientId, "Open client"));
        }

        if (activeKeysByClientId.TryGetValue(client.ClientId, out int activeKeyCount) && activeKeyCount == 0)
        {
            issues.Add(Blocker($"Client '{client.DisplayName}' has no active API key.", CryptoApiAccessReadinessTargetKind.Client, client.ClientId, "Open client"));
        }

        if (!alias.IsEnabled)
        {
            issues.Add(Blocker($"Alias '{alias.AliasName}' is disabled.", CryptoApiAccessReadinessTargetKind.Alias, alias.AliasId, "Open alias"));
        }

        IReadOnlyList<CryptoApiManagedPolicy> enabledClientPolicies = client.BoundPolicyIds
            .Where(enabledPolicyIds.Contains)
            .Select(policyId => policiesById[policyId])
            .OrderBy(policy => policy.PolicyName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        IReadOnlyList<CryptoApiManagedPolicy> enabledAliasPolicies = alias.BoundPolicyIds
            .Where(enabledPolicyIds.Contains)
            .Select(policyId => policiesById[policyId])
            .OrderBy(policy => policy.PolicyName, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        Guid[] sharedDisabledPolicyIds = client.BoundPolicyIds
            .Intersect(alias.BoundPolicyIds)
            .Where(policyId => policiesById.TryGetValue(policyId, out CryptoApiManagedPolicy? policy) && !policy.IsEnabled)
            .Distinct()
            .ToArray();

        AddPolicyBindingIssues(
            issues,
            ownerLabel: $"Client '{client.DisplayName}'",
            boundPolicyIds: client.BoundPolicyIds,
            enabledPolicies: enabledClientPolicies,
            fallbackTargetKind: CryptoApiAccessReadinessTargetKind.Client,
            fallbackTargetId: client.ClientId,
            fallbackActionLabel: "Open client",
            policiesById);
        AddPolicyBindingIssues(
            issues,
            ownerLabel: $"Alias '{alias.AliasName}'",
            boundPolicyIds: alias.BoundPolicyIds,
            enabledPolicies: enabledAliasPolicies,
            fallbackTargetKind: CryptoApiAccessReadinessTargetKind.Alias,
            fallbackTargetId: alias.AliasId,
            fallbackActionLabel: "Open alias",
            policiesById);

        IReadOnlyList<CryptoApiManagedPolicy> sharedEnabledPolicies = enabledClientPolicies
            .Where(policy => alias.BoundPolicyIds.Contains(policy.PolicyId))
            .OrderBy(policy => policy.PolicyName, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (sharedEnabledPolicies.Count == 0)
        {
            if (sharedDisabledPolicyIds.Length > 0)
            {
                CryptoApiManagedPolicy disabledSharedPolicy = policiesById[sharedDisabledPolicyIds[0]];
                issues.Add(Blocker(
                    $"Client '{client.DisplayName}' and alias '{alias.AliasName}' only share disabled policies.",
                    CryptoApiAccessReadinessTargetKind.Policy,
                    disabledSharedPolicy.PolicyId,
                    "Open policy"));
            }
            else if (client.BoundPolicyIds.Count > 0 && alias.BoundPolicyIds.Count > 0)
            {
                issues.Add(Blocker(
                    $"Client '{client.DisplayName}' and alias '{alias.AliasName}' do not share any enabled policies.",
                    CryptoApiAccessReadinessTargetKind.Client,
                    client.ClientId,
                    "Open client"));
            }
        }

        foreach (CryptoApiAccessReadinessIssue routeIssue in EvaluateRoute(alias, runtimeInspection))
        {
            issues.Add(routeIssue);
        }

        CryptoApiAccessReadinessLevel level = DetermineLevel(issues);
        string summary = level switch
        {
            CryptoApiAccessReadinessLevel.Ready => $"Ready via {sharedEnabledPolicies.Count} shared enabled {(sharedEnabledPolicies.Count == 1 ? "policy" : "policies")}",
            CryptoApiAccessReadinessLevel.NeedsAttention => issues.First(issue => issue.Severity == CryptoApiAccessIssueSeverity.Warning).Message,
            _ => issues.First(issue => issue.Severity == CryptoApiAccessIssueSeverity.Blocker).Message
        };

        string routeSummary = BuildRouteSummary(alias, runtimeInspection);
        IReadOnlyList<string> allowedOperations = sharedEnabledPolicies
            .SelectMany(policy => policy.AllowedOperations)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(operation => operation, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new CryptoApiClientAliasReadinessViewItem(
            ClientId: client.ClientId,
            ClientDisplayName: client.DisplayName,
            ClientName: client.ClientName,
            AliasId: alias.AliasId,
            AliasName: alias.AliasName,
            Level: level,
            Summary: summary,
            RouteSummary: routeSummary,
            SharedPolicyNames: sharedEnabledPolicies.Select(policy => policy.PolicyName).ToArray(),
            AllowedOperations: allowedOperations,
            Issues: issues);
    }

    private static CryptoApiClientReadinessViewItem BuildClient(
        CryptoApiManagedClient client,
        IReadOnlyList<CryptoApiManagedKeyAlias> aliases,
        IReadOnlyList<CryptoApiClientAliasReadinessViewItem> routes,
        HashSet<Guid> enabledPolicyIds,
        IReadOnlyDictionary<Guid, int> activeKeysByClientId)
    {
        IReadOnlyList<CryptoApiClientAliasReadinessViewItem> clientRoutes = routes
            .Where(route => route.ClientId == client.ClientId)
            .ToArray();
        int readyRouteCount = clientRoutes.Count(route => route.Level == CryptoApiAccessReadinessLevel.Ready);
        int attentionRouteCount = clientRoutes.Count(route => route.Level == CryptoApiAccessReadinessLevel.NeedsAttention);
        int blockedRouteCount = clientRoutes.Count - readyRouteCount - attentionRouteCount;
        int activeKeyCount = activeKeysByClientId.TryGetValue(client.ClientId, out int count) ? count : 0;
        List<CryptoApiAccessReadinessIssue> issues = [];

        if (!client.IsEnabled)
        {
            issues.Add(Blocker($"Client '{client.DisplayName}' is disabled.", CryptoApiAccessReadinessTargetKind.Client, client.ClientId, "Open client"));
        }

        if (activeKeyCount == 0)
        {
            issues.Add(Blocker($"Client '{client.DisplayName}' has no active API key.", CryptoApiAccessReadinessTargetKind.Client, client.ClientId, "Open client"));
        }

        IReadOnlyList<Guid> enabledClientPolicyIds = client.BoundPolicyIds.Where(enabledPolicyIds.Contains).ToArray();
        if (client.BoundPolicyIds.Count == 0)
        {
            issues.Add(Blocker($"Client '{client.DisplayName}' is not bound to any policies.", CryptoApiAccessReadinessTargetKind.Client, client.ClientId, "Open client"));
        }
        else if (enabledClientPolicyIds.Count == 0)
        {
            issues.Add(Blocker($"Client '{client.DisplayName}' only has disabled policy bindings.", CryptoApiAccessReadinessTargetKind.Client, client.ClientId, "Open client"));
        }

        if (aliases.Count == 0)
        {
            issues.Add(Blocker("No key aliases exist yet.", CryptoApiAccessReadinessTargetKind.Alias, null, null));
        }
        else if (readyRouteCount == 0 && attentionRouteCount == 0)
        {
            issues.Add(Blocker($"Client '{client.DisplayName}' cannot currently authorize any alias.", CryptoApiAccessReadinessTargetKind.Client, client.ClientId, "Open client"));
        }
        else if (readyRouteCount == 0 && attentionRouteCount > 0)
        {
            issues.Add(Warning($"Client '{client.DisplayName}' has alias routes that still need route-host verification.", CryptoApiAccessReadinessTargetKind.Client, client.ClientId, "Open client"));
        }
        else if (blockedRouteCount > 0)
        {
            issues.Add(Warning($"{blockedRouteCount} alias {(blockedRouteCount == 1 ? "route is" : "routes are")} still blocked for this client.", CryptoApiAccessReadinessTargetKind.Client, client.ClientId, "Open client"));
        }

        CryptoApiAccessReadinessLevel level = DetermineAggregateLevel(readyRouteCount, attentionRouteCount);
        string summary = level switch
        {
            CryptoApiAccessReadinessLevel.Ready => $"Operable against {readyRouteCount} alias {(readyRouteCount == 1 ? "route" : "routes")}",
            CryptoApiAccessReadinessLevel.NeedsAttention => attentionRouteCount == 1
                ? "No alias is fully verified yet, but 1 route is close to ready."
                : $"No alias is fully verified yet, but {attentionRouteCount} routes are close to ready.",
            _ => issues.FirstOrDefault(issue => issue.Severity == CryptoApiAccessIssueSeverity.Blocker)?.Message
                ?? $"No usable alias routes are available for client '{client.DisplayName}'."
        };

        return new CryptoApiClientReadinessViewItem(
            ClientId: client.ClientId,
            Level: level,
            Summary: summary,
            ActiveKeyCount: activeKeyCount,
            ReadyRouteCount: readyRouteCount,
            NeedsAttentionRouteCount: attentionRouteCount,
            BlockedRouteCount: blockedRouteCount,
            Issues: issues);
    }

    private static CryptoApiAliasReadinessViewItem BuildAlias(
        CryptoApiManagedKeyAlias alias,
        IReadOnlyList<CryptoApiManagedClient> clients,
        IReadOnlyList<CryptoApiClientAliasReadinessViewItem> routes,
        HashSet<Guid> enabledPolicyIds,
        IReadOnlyDictionary<Guid, int> activeKeysByClientId)
    {
        IReadOnlyList<CryptoApiClientAliasReadinessViewItem> aliasRoutes = routes
            .Where(route => route.AliasId == alias.AliasId)
            .ToArray();
        int readyClientCount = aliasRoutes.Count(route => route.Level == CryptoApiAccessReadinessLevel.Ready);
        int attentionClientCount = aliasRoutes.Count(route => route.Level == CryptoApiAccessReadinessLevel.NeedsAttention);
        int blockedClientCount = aliasRoutes.Count - readyClientCount - attentionClientCount;
        List<CryptoApiAccessReadinessIssue> issues = [];

        if (!alias.IsEnabled)
        {
            issues.Add(Blocker($"Alias '{alias.AliasName}' is disabled.", CryptoApiAccessReadinessTargetKind.Alias, alias.AliasId, "Open alias"));
        }

        IReadOnlyList<Guid> enabledAliasPolicyIds = alias.BoundPolicyIds.Where(enabledPolicyIds.Contains).ToArray();
        if (alias.BoundPolicyIds.Count == 0)
        {
            issues.Add(Blocker($"Alias '{alias.AliasName}' is not bound to any policies.", CryptoApiAccessReadinessTargetKind.Alias, alias.AliasId, "Open alias"));
        }
        else if (enabledAliasPolicyIds.Count == 0)
        {
            issues.Add(Blocker($"Alias '{alias.AliasName}' only has disabled policy bindings.", CryptoApiAccessReadinessTargetKind.Alias, alias.AliasId, "Open alias"));
        }

        foreach (CryptoApiAccessReadinessIssue routeIssue in EvaluateRoute(alias, CryptoApiRuntimeInspection.None))
        {
            if (routeIssue.Severity == CryptoApiAccessIssueSeverity.Blocker)
            {
                issues.Add(routeIssue);
            }
        }

        if (clients.Count == 0)
        {
            issues.Add(Blocker("No API clients exist yet.", CryptoApiAccessReadinessTargetKind.Client, null, null));
        }
        else if (!clients.Any(client => client.IsEnabled && activeKeysByClientId.TryGetValue(client.ClientId, out int activeKeyCount) && activeKeyCount > 0))
        {
            issues.Add(Blocker("No enabled client currently has an active API key.", CryptoApiAccessReadinessTargetKind.Client, null, null));
        }
        else if (readyClientCount == 0 && attentionClientCount == 0)
        {
            issues.Add(Blocker($"Alias '{alias.AliasName}' is not currently operable for any client.", CryptoApiAccessReadinessTargetKind.Alias, alias.AliasId, "Open alias"));
        }
        else if (readyClientCount == 0 && attentionClientCount > 0)
        {
            issues.Add(Warning($"Alias '{alias.AliasName}' still needs route-host verification before any client is fully ready.", CryptoApiAccessReadinessTargetKind.Alias, alias.AliasId, "Open alias"));
        }
        else if (blockedClientCount > 0)
        {
            issues.Add(Warning($"{blockedClientCount} client {(blockedClientCount == 1 ? "binding is" : "bindings are")} still blocked for this alias.", CryptoApiAccessReadinessTargetKind.Alias, alias.AliasId, "Open alias"));
        }

        CryptoApiAccessReadinessLevel level = DetermineAggregateLevel(readyClientCount, attentionClientCount);
        string summary = level switch
        {
            CryptoApiAccessReadinessLevel.Ready => $"Callable by {readyClientCount} client {(readyClientCount == 1 ? "route" : "routes")}",
            CryptoApiAccessReadinessLevel.NeedsAttention => attentionClientCount == 1
                ? "No client is fully verified yet, but 1 route is close to ready."
                : $"No client is fully verified yet, but {attentionClientCount} routes are close to ready.",
            _ => issues.FirstOrDefault(issue => issue.Severity == CryptoApiAccessIssueSeverity.Blocker)?.Message
                ?? $"Alias '{alias.AliasName}' is not currently operable."
        };

        return new CryptoApiAliasReadinessViewItem(
            AliasId: alias.AliasId,
            Level: level,
            Summary: summary,
            ReadyClientCount: readyClientCount,
            NeedsAttentionClientCount: attentionClientCount,
            BlockedClientCount: blockedClientCount,
            Issues: issues);
    }

    private static CryptoApiPolicyReadinessViewItem BuildPolicy(
        CryptoApiManagedPolicy policy,
        IReadOnlyDictionary<Guid, CryptoApiManagedClient> clientsById,
        IReadOnlyDictionary<Guid, CryptoApiManagedKeyAlias> aliasesById,
        IReadOnlyList<CryptoApiClientAliasReadinessViewItem> routes,
        IReadOnlyDictionary<Guid, int> activeKeysByClientId)
    {
        IReadOnlyList<CryptoApiClientAliasReadinessViewItem> policyRoutes = routes
            .Where(route => route.SharedPolicyNames.Contains(policy.PolicyName, StringComparer.OrdinalIgnoreCase))
            .ToArray();
        int readyRouteCount = policyRoutes.Count(route => route.Level == CryptoApiAccessReadinessLevel.Ready);
        int attentionRouteCount = policyRoutes.Count(route => route.Level == CryptoApiAccessReadinessLevel.NeedsAttention);
        int blockedRouteCount = policyRoutes.Count - readyRouteCount - attentionRouteCount;
        int enabledClientBindingCount = policy.BoundClientIds.Count(clientId => clientsById.TryGetValue(clientId, out CryptoApiManagedClient? client) && client.IsEnabled);
        int enabledAliasBindingCount = policy.BoundAliasIds.Count(aliasId => aliasesById.TryGetValue(aliasId, out CryptoApiManagedKeyAlias? alias) && alias.IsEnabled);
        int activeClientBindingCount = policy.BoundClientIds.Count(clientId => clientsById.TryGetValue(clientId, out CryptoApiManagedClient? client)
            && client.IsEnabled
            && activeKeysByClientId.TryGetValue(clientId, out int activeKeyCount)
            && activeKeyCount > 0);

        List<CryptoApiAccessReadinessIssue> issues = [];
        if (!policy.IsEnabled)
        {
            issues.Add(Blocker($"Policy '{policy.PolicyName}' is disabled.", CryptoApiAccessReadinessTargetKind.Policy, policy.PolicyId, "Open policy"));
        }

        if (policy.BoundClientIds.Count == 0)
        {
            issues.Add(Blocker($"Policy '{policy.PolicyName}' is not bound to any clients.", CryptoApiAccessReadinessTargetKind.Policy, policy.PolicyId, "Open policy"));
        }
        else if (enabledClientBindingCount == 0)
        {
            issues.Add(Blocker($"Policy '{policy.PolicyName}' is only bound to disabled clients.", CryptoApiAccessReadinessTargetKind.Policy, policy.PolicyId, "Open policy"));
        }
        else if (activeClientBindingCount == 0)
        {
            issues.Add(Blocker($"No enabled client bound to policy '{policy.PolicyName}' has an active API key.", CryptoApiAccessReadinessTargetKind.Policy, policy.PolicyId, "Open policy"));
        }

        if (policy.BoundAliasIds.Count == 0)
        {
            issues.Add(Blocker($"Policy '{policy.PolicyName}' is not bound to any aliases.", CryptoApiAccessReadinessTargetKind.Policy, policy.PolicyId, "Open policy"));
        }
        else if (enabledAliasBindingCount == 0)
        {
            issues.Add(Blocker($"Policy '{policy.PolicyName}' is only bound to disabled aliases.", CryptoApiAccessReadinessTargetKind.Policy, policy.PolicyId, "Open policy"));
        }

        if (readyRouteCount == 0 && attentionRouteCount > 0)
        {
            issues.Add(Warning($"Policy '{policy.PolicyName}' is bound on both sides, but route-host verification is still pending.", CryptoApiAccessReadinessTargetKind.Policy, policy.PolicyId, "Open policy"));
        }
        else if (readyRouteCount == 0 && blockedRouteCount > 0)
        {
            issues.Add(Blocker($"Policy '{policy.PolicyName}' does not currently authorize any operable client/alias route.", CryptoApiAccessReadinessTargetKind.Policy, policy.PolicyId, "Open policy"));
        }

        CryptoApiAccessReadinessLevel level = DetermineAggregateLevel(readyRouteCount, attentionRouteCount);
        string summary = level switch
        {
            CryptoApiAccessReadinessLevel.Ready => $"Authorizes {readyRouteCount} ready {(readyRouteCount == 1 ? "route" : "routes")}",
            CryptoApiAccessReadinessLevel.NeedsAttention => attentionRouteCount == 1
                ? "Bound on both sides, but 1 route still needs verification."
                : $"Bound on both sides, but {attentionRouteCount} routes still need verification.",
            _ => issues.FirstOrDefault(issue => issue.Severity == CryptoApiAccessIssueSeverity.Blocker)?.Message
                ?? $"Policy '{policy.PolicyName}' is not currently usable."
        };

        return new CryptoApiPolicyReadinessViewItem(
            PolicyId: policy.PolicyId,
            Level: level,
            Summary: summary,
            ReadyRouteCount: readyRouteCount,
            NeedsAttentionRouteCount: attentionRouteCount,
            BlockedRouteCount: blockedRouteCount,
            Issues: issues);
    }

    private static IReadOnlyList<CryptoApiAccessReadinessIssue> EvaluateRoute(CryptoApiManagedKeyAlias alias, CryptoApiRuntimeInspection runtimeInspection)
    {
        List<CryptoApiAccessReadinessIssue> issues = [];

        if (!string.IsNullOrWhiteSpace(alias.RouteGroupName))
        {
            string routeGroupName = alias.RouteGroupName.Trim();
            if (!runtimeInspection.HasRuntimeContext)
            {
                issues.Add(Warning(
                    $"Route group '{routeGroupName}' is defined in shared state, but the admin host does not expose CryptoApiRuntime config to verify it locally.",
                    CryptoApiAccessReadinessTargetKind.Alias,
                    alias.AliasId,
                    "Open alias"));
                return issues;
            }

            if (!runtimeInspection.RouteGroups.TryGetValue(routeGroupName, out CryptoApiRuntimeRouteGroupInspection? routeGroup))
            {
                issues.Add(Blocker(
                    $"Route group '{routeGroupName}' is not defined in the admin runtime context.",
                    CryptoApiAccessReadinessTargetKind.Alias,
                    alias.AliasId,
                    "Open alias"));
                return issues;
            }

            if (routeGroup.Candidates.Count == 0)
            {
                issues.Add(Blocker(
                    $"Route group '{routeGroupName}' has no enabled backend candidates.",
                    CryptoApiAccessReadinessTargetKind.Alias,
                    alias.AliasId,
                    "Open alias"));
            }

            return issues;
        }

        if (alias.SlotId is null)
        {
            issues.Add(Blocker(
                $"Alias '{alias.AliasName}' does not define a slot id or route group.",
                CryptoApiAccessReadinessTargetKind.Alias,
                alias.AliasId,
                "Open alias"));
            return issues;
        }

        if (!string.IsNullOrWhiteSpace(alias.DeviceRoute)
            && runtimeInspection.EnabledBackendNames.Count > 0
            && !runtimeInspection.EnabledBackendNames.Contains(alias.DeviceRoute.Trim()))
        {
            issues.Add(Blocker(
                $"Legacy device route '{alias.DeviceRoute}' is not enabled in the admin runtime context.",
                CryptoApiAccessReadinessTargetKind.Alias,
                alias.AliasId,
                "Open alias"));
        }

        return issues;
    }

    private static string BuildRouteSummary(CryptoApiManagedKeyAlias alias, CryptoApiRuntimeInspection runtimeInspection)
    {
        if (!string.IsNullOrWhiteSpace(alias.RouteGroupName))
        {
            string routeGroupName = alias.RouteGroupName.Trim();
            if (runtimeInspection.RouteGroups.TryGetValue(routeGroupName, out CryptoApiRuntimeRouteGroupInspection? routeGroup)
                && routeGroup.Candidates.Count > 0)
            {
                return $"group={routeGroupName} ({routeGroup.Candidates.Count} candidate{(routeGroup.Candidates.Count == 1 ? string.Empty : "s")})";
            }

            return $"group={routeGroupName}";
        }

        string slot = alias.SlotId?.ToString() ?? "missing";
        string device = string.IsNullOrWhiteSpace(alias.DeviceRoute) ? "default" : alias.DeviceRoute.Trim();
        return $"slot={slot}, device={device}";
    }

    private static void AddPolicyBindingIssues(
        ICollection<CryptoApiAccessReadinessIssue> issues,
        string ownerLabel,
        IReadOnlyCollection<Guid> boundPolicyIds,
        IReadOnlyList<CryptoApiManagedPolicy> enabledPolicies,
        CryptoApiAccessReadinessTargetKind fallbackTargetKind,
        Guid fallbackTargetId,
        string fallbackActionLabel,
        IReadOnlyDictionary<Guid, CryptoApiManagedPolicy> policiesById)
    {
        if (boundPolicyIds.Count == 0)
        {
            issues.Add(Blocker($"{ownerLabel} is not bound to any policies.", fallbackTargetKind, fallbackTargetId, fallbackActionLabel));
            return;
        }

        if (enabledPolicies.Count > 0)
        {
            return;
        }

        Guid disabledPolicyId = boundPolicyIds.First();
        if (policiesById.TryGetValue(disabledPolicyId, out CryptoApiManagedPolicy? disabledPolicy) && !disabledPolicy.IsEnabled)
        {
            issues.Add(Blocker($"{ownerLabel} only has disabled policy bindings.", CryptoApiAccessReadinessTargetKind.Policy, disabledPolicy.PolicyId, "Open policy"));
            return;
        }

        issues.Add(Blocker($"{ownerLabel} only has unusable policy bindings.", fallbackTargetKind, fallbackTargetId, fallbackActionLabel));
    }

    private static CryptoApiAccessReadinessLevel DetermineLevel(IReadOnlyCollection<CryptoApiAccessReadinessIssue> issues)
        => issues.Any(issue => issue.Severity == CryptoApiAccessIssueSeverity.Blocker)
            ? CryptoApiAccessReadinessLevel.Blocked
            : issues.Any(issue => issue.Severity == CryptoApiAccessIssueSeverity.Warning)
                ? CryptoApiAccessReadinessLevel.NeedsAttention
                : CryptoApiAccessReadinessLevel.Ready;

    private static CryptoApiAccessReadinessLevel DetermineAggregateLevel(int readyCount, int attentionCount)
        => readyCount > 0
            ? CryptoApiAccessReadinessLevel.Ready
            : attentionCount > 0
                ? CryptoApiAccessReadinessLevel.NeedsAttention
                : CryptoApiAccessReadinessLevel.Blocked;

    private static CryptoApiAccessReadinessIssue Blocker(string message, CryptoApiAccessReadinessTargetKind targetKind, Guid? targetId, string? actionLabel)
        => new(CryptoApiAccessIssueSeverity.Blocker, message, targetKind, targetId, actionLabel);

    private static CryptoApiAccessReadinessIssue Warning(string message, CryptoApiAccessReadinessTargetKind targetKind, Guid? targetId, string? actionLabel)
        => new(CryptoApiAccessIssueSeverity.Warning, message, targetKind, targetId, actionLabel);

    private static bool IsActiveKey(CryptoApiManagedClientKey key, DateTimeOffset nowUtc)
        => key.IsEnabled
            && key.RevokedAtUtc is null
            && (key.ExpiresAtUtc is null || key.ExpiresAtUtc > nowUtc);

    private sealed record CryptoApiRuntimeInspection(
        bool HasRuntimeContext,
        string Summary,
        IReadOnlyDictionary<string, CryptoApiRuntimeRouteGroupInspection> RouteGroups,
        HashSet<string> EnabledBackendNames)
    {
        public static CryptoApiRuntimeInspection None { get; } = new(
            HasRuntimeContext: false,
            Summary: "The admin host does not expose CryptoApiRuntime configuration, so route-group aliases are reported as needing local route-host verification.",
            RouteGroups: new Dictionary<string, CryptoApiRuntimeRouteGroupInspection>(StringComparer.OrdinalIgnoreCase),
            EnabledBackendNames: new HashSet<string>(StringComparer.OrdinalIgnoreCase));

        public static CryptoApiRuntimeInspection Create(AdminCryptoApiRouteRuntimeOptions? options)
        {
            if (options is null)
            {
                return None;
            }

            bool hasRuntimeContext = !string.IsNullOrWhiteSpace(options.ModulePath)
                || options.Backends.Count > 0
                || options.RouteGroups.Count > 0;
            if (!hasRuntimeContext)
            {
                return None;
            }

            HashSet<string> enabledBackends = options.Backends
                .Where(static backend => backend.Enabled && !string.IsNullOrWhiteSpace(backend.Name))
                .Select(backend => backend.Name!.Trim())
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            Dictionary<string, CryptoApiRuntimeRouteGroupInspection> routeGroups = new(StringComparer.OrdinalIgnoreCase);
            foreach (AdminCryptoApiRuntimeRouteGroupOptions group in options.RouteGroups)
            {
                if (string.IsNullOrWhiteSpace(group.Name))
                {
                    continue;
                }

                string name = group.Name.Trim();
                IReadOnlyList<CryptoApiRouteCandidate> candidates = group.Backends
                    .Where(static candidate => candidate.Enabled && !string.IsNullOrWhiteSpace(candidate.BackendName))
                    .Select(candidate => new CryptoApiRouteCandidate(candidate.BackendName!.Trim(), candidate.SlotId, candidate.Priority))
                    .Where(candidate => enabledBackends.Count == 0 || enabledBackends.Contains(candidate.DeviceRoute ?? string.Empty))
                    .OrderBy(candidate => candidate.Priority)
                    .ThenBy(candidate => candidate.DeviceRoute, StringComparer.OrdinalIgnoreCase)
                    .ToArray();

                routeGroups[name] = new CryptoApiRuntimeRouteGroupInspection(name, candidates);
            }

            return new CryptoApiRuntimeInspection(
                HasRuntimeContext: true,
                Summary: "Route diagnostics are evaluated against the admin host CryptoApiRuntime configuration. Group availability here should match at least one deployed Crypto API runtime to count as fully ready.",
                RouteGroups: routeGroups,
                EnabledBackendNames: enabledBackends);
        }
    }
}

public sealed record CryptoApiAccessReadinessState(
    bool RuntimeInspectionConfigured,
    string RuntimeInspectionSummary,
    IReadOnlyList<CryptoApiClientReadinessViewItem> Clients,
    IReadOnlyList<CryptoApiAliasReadinessViewItem> Aliases,
    IReadOnlyList<CryptoApiPolicyReadinessViewItem> Policies,
    IReadOnlyList<CryptoApiClientAliasReadinessViewItem> Routes);

public sealed record CryptoApiClientReadinessViewItem(
    Guid ClientId,
    CryptoApiAccessReadinessLevel Level,
    string Summary,
    int ActiveKeyCount,
    int ReadyRouteCount,
    int NeedsAttentionRouteCount,
    int BlockedRouteCount,
    IReadOnlyList<CryptoApiAccessReadinessIssue> Issues);

public sealed record CryptoApiAliasReadinessViewItem(
    Guid AliasId,
    CryptoApiAccessReadinessLevel Level,
    string Summary,
    int ReadyClientCount,
    int NeedsAttentionClientCount,
    int BlockedClientCount,
    IReadOnlyList<CryptoApiAccessReadinessIssue> Issues);

public sealed record CryptoApiPolicyReadinessViewItem(
    Guid PolicyId,
    CryptoApiAccessReadinessLevel Level,
    string Summary,
    int ReadyRouteCount,
    int NeedsAttentionRouteCount,
    int BlockedRouteCount,
    IReadOnlyList<CryptoApiAccessReadinessIssue> Issues);

public sealed record CryptoApiClientAliasReadinessViewItem(
    Guid ClientId,
    string ClientDisplayName,
    string ClientName,
    Guid AliasId,
    string AliasName,
    CryptoApiAccessReadinessLevel Level,
    string Summary,
    string RouteSummary,
    IReadOnlyList<string> SharedPolicyNames,
    IReadOnlyList<string> AllowedOperations,
    IReadOnlyList<CryptoApiAccessReadinessIssue> Issues);

public sealed record CryptoApiAccessReadinessIssue(
    CryptoApiAccessIssueSeverity Severity,
    string Message,
    CryptoApiAccessReadinessTargetKind TargetKind,
    Guid? TargetId,
    string? ActionLabel);

public sealed record CryptoApiRuntimeRouteGroupInspection(
    string Name,
    IReadOnlyList<CryptoApiRouteCandidate> Candidates);

public enum CryptoApiAccessReadinessLevel
{
    Ready = 0,
    NeedsAttention = 1,
    Blocked = 2
}

public enum CryptoApiAccessIssueSeverity
{
    Warning = 0,
    Blocker = 1
}

public enum CryptoApiAccessReadinessTargetKind
{
    None = 0,
    Client,
    Alias,
    Policy
}
