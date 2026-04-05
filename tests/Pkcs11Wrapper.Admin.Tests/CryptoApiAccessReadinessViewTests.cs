using Pkcs11Wrapper.Admin.Web.Components.Pages;
using Pkcs11Wrapper.Admin.Web.Configuration;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Clients;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class CryptoApiAccessReadinessViewTests
{
    private static readonly DateTimeOffset NowUtc = new(2026, 04, 05, 17, 30, 00, TimeSpan.Zero);

    [Fact]
    public void BuildMarksLegacyClientAliasPolicyPathReady()
    {
        Guid clientId = Guid.NewGuid();
        Guid aliasId = Guid.NewGuid();
        Guid policyId = Guid.NewGuid();

        CryptoApiAccessReadinessState state = CryptoApiAccessReadinessView.Build(
            CreateClientSnapshot(CreateClient(clientId, policyId, CreateActiveKey(clientId))),
            CreateAccessSnapshot(CreateAlias(aliasId, policyId, slotId: 7), CreatePolicy(policyId, clientId, aliasId)),
            runtimeOptions: null,
            nowUtc: NowUtc);

        CryptoApiClientReadinessViewItem client = Assert.Single(state.Clients);
        CryptoApiAliasReadinessViewItem alias = Assert.Single(state.Aliases);
        CryptoApiPolicyReadinessViewItem policy = Assert.Single(state.Policies);
        CryptoApiClientAliasReadinessViewItem route = Assert.Single(state.Routes);

        Assert.Equal(CryptoApiAccessReadinessLevel.Ready, client.Level);
        Assert.Equal(CryptoApiAccessReadinessLevel.Ready, alias.Level);
        Assert.Equal(CryptoApiAccessReadinessLevel.Ready, policy.Level);
        Assert.Equal(CryptoApiAccessReadinessLevel.Ready, route.Level);
        Assert.Contains("sign", route.AllowedOperations);
        Assert.Contains("verify", route.AllowedOperations);
    }

    [Fact]
    public void BuildBlocksClientAndRouteWhenNoActiveKeyExists()
    {
        Guid clientId = Guid.NewGuid();
        Guid aliasId = Guid.NewGuid();
        Guid policyId = Guid.NewGuid();

        CryptoApiAccessReadinessState state = CryptoApiAccessReadinessView.Build(
            CreateClientSnapshot(CreateClient(clientId, policyId, CreateDisabledKey(clientId))),
            CreateAccessSnapshot(CreateAlias(aliasId, policyId, slotId: 9), CreatePolicy(policyId, clientId, aliasId)),
            runtimeOptions: null,
            nowUtc: NowUtc);

        CryptoApiClientReadinessViewItem client = Assert.Single(state.Clients);
        CryptoApiClientAliasReadinessViewItem route = Assert.Single(state.Routes);

        Assert.Equal(CryptoApiAccessReadinessLevel.Blocked, client.Level);
        Assert.Equal(CryptoApiAccessReadinessLevel.Blocked, route.Level);
        Assert.Contains(client.Issues, issue => issue.Message.Contains("no active API key", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(route.Issues, issue => issue.Message.Contains("no active API key", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void BuildBlocksWhenClientAndAliasOnlyShareDisabledPolicies()
    {
        Guid clientId = Guid.NewGuid();
        Guid aliasId = Guid.NewGuid();
        Guid policyId = Guid.NewGuid();

        CryptoApiAccessReadinessState state = CryptoApiAccessReadinessView.Build(
            CreateClientSnapshot(CreateClient(clientId, policyId, CreateActiveKey(clientId))),
            CreateAccessSnapshot(CreateAlias(aliasId, policyId, slotId: 4), CreatePolicy(policyId, clientId, aliasId, enabled: false)),
            runtimeOptions: null,
            nowUtc: NowUtc);

        CryptoApiClientAliasReadinessViewItem route = Assert.Single(state.Routes);
        CryptoApiPolicyReadinessViewItem policy = Assert.Single(state.Policies);

        Assert.Equal(CryptoApiAccessReadinessLevel.Blocked, route.Level);
        Assert.Equal(CryptoApiAccessReadinessLevel.Blocked, policy.Level);
        Assert.Contains(route.Issues, issue => issue.Message.Contains("disabled policies", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(policy.Issues, issue => issue.Message.Contains("disabled", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void BuildBlocksWhenClientAndAliasDoNotShareAnyEnabledPolicy()
    {
        Guid clientId = Guid.NewGuid();
        Guid aliasId = Guid.NewGuid();
        Guid clientPolicyId = Guid.NewGuid();
        Guid aliasPolicyId = Guid.NewGuid();

        CryptoApiAccessReadinessState state = CryptoApiAccessReadinessView.Build(
            CreateClientSnapshot(CreateClient(clientId, clientPolicyId, CreateActiveKey(clientId))),
            new CryptoApiKeyAccessSnapshot(
                SharedPersistenceConfigured: true,
                SharedPersistenceProvider: "postgres",
                ConnectionTarget: "postgres://tests",
                SchemaVersion: 1,
                KeyAliases: [CreateAlias(aliasId, aliasPolicyId, slotId: 11)],
                Policies:
                [
                    CreatePolicy(clientPolicyId, clientId, aliasId: Guid.NewGuid()),
                    CreatePolicy(aliasPolicyId, clientId: Guid.NewGuid(), aliasId)
                ]),
            runtimeOptions: null,
            nowUtc: NowUtc);

        CryptoApiClientAliasReadinessViewItem route = Assert.Single(state.Routes);

        Assert.Equal(CryptoApiAccessReadinessLevel.Blocked, route.Level);
        Assert.Contains(route.Issues, issue => issue.Message.Contains("do not share any enabled policies", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void BuildMarksRouteGroupAliasesNeedsAttentionWhenAdminHostCannotValidateThem()
    {
        Guid clientId = Guid.NewGuid();
        Guid aliasId = Guid.NewGuid();
        Guid policyId = Guid.NewGuid();

        CryptoApiAccessReadinessState state = CryptoApiAccessReadinessView.Build(
            CreateClientSnapshot(CreateClient(clientId, policyId, CreateActiveKey(clientId))),
            CreateAccessSnapshot(CreateAlias(aliasId, policyId, slotId: null, routeGroupName: "payments"), CreatePolicy(policyId, clientId, aliasId)),
            runtimeOptions: null,
            nowUtc: NowUtc);

        CryptoApiClientReadinessViewItem client = Assert.Single(state.Clients);
        CryptoApiAliasReadinessViewItem alias = Assert.Single(state.Aliases);
        CryptoApiClientAliasReadinessViewItem route = Assert.Single(state.Routes);

        Assert.Equal(CryptoApiAccessReadinessLevel.NeedsAttention, client.Level);
        Assert.Equal(CryptoApiAccessReadinessLevel.NeedsAttention, alias.Level);
        Assert.Equal(CryptoApiAccessReadinessLevel.NeedsAttention, route.Level);
        Assert.Contains("does not expose CryptoApiRuntime config", route.Summary, StringComparison.OrdinalIgnoreCase);
        Assert.False(state.RuntimeInspectionConfigured);
    }

    [Fact]
    public void BuildBlocksWhenRouteGroupIsMissingFromAdminRuntimeContext()
    {
        Guid clientId = Guid.NewGuid();
        Guid aliasId = Guid.NewGuid();
        Guid policyId = Guid.NewGuid();

        AdminCryptoApiRouteRuntimeOptions runtimeOptions = new()
        {
            ModulePath = "/tmp/pkcs11.so",
            Backends =
            [
                new AdminCryptoApiRuntimeBackendOptions
                {
                    Name = "backend-a",
                    Enabled = true
                }
            ],
            RouteGroups =
            [
                new AdminCryptoApiRuntimeRouteGroupOptions
                {
                    Name = "other-group",
                    Backends =
                    [
                        new AdminCryptoApiRuntimeRouteBackendOptions
                        {
                            BackendName = "backend-a",
                            SlotId = 2,
                            Priority = 0,
                            Enabled = true
                        }
                    ]
                }
            ]
        };

        CryptoApiAccessReadinessState state = CryptoApiAccessReadinessView.Build(
            CreateClientSnapshot(CreateClient(clientId, policyId, CreateActiveKey(clientId))),
            CreateAccessSnapshot(CreateAlias(aliasId, policyId, slotId: null, routeGroupName: "payments"), CreatePolicy(policyId, clientId, aliasId)),
            runtimeOptions,
            nowUtc: NowUtc);

        CryptoApiClientAliasReadinessViewItem route = Assert.Single(state.Routes);

        Assert.Equal(CryptoApiAccessReadinessLevel.Blocked, route.Level);
        Assert.Contains(route.Issues, issue => issue.Message.Contains("not defined in the admin runtime context", StringComparison.OrdinalIgnoreCase));
        Assert.True(state.RuntimeInspectionConfigured);
    }

    private static CryptoApiClientManagementSnapshot CreateClientSnapshot(params CryptoApiManagedClient[] clients)
        => new(
            SharedPersistenceConfigured: true,
            SharedPersistenceProvider: "postgres",
            ConnectionTarget: "postgres://tests",
            SchemaVersion: 1,
            Clients: clients);

    private static CryptoApiKeyAccessSnapshot CreateAccessSnapshot(CryptoApiManagedKeyAlias alias, CryptoApiManagedPolicy policy)
        => new(
            SharedPersistenceConfigured: true,
            SharedPersistenceProvider: "postgres",
            ConnectionTarget: "postgres://tests",
            SchemaVersion: 1,
            KeyAliases: [alias],
            Policies: [policy]);

    private static CryptoApiManagedClient CreateClient(Guid clientId, Guid policyId, params CryptoApiManagedClientKey[] keys)
        => new(
            ClientId: clientId,
            ClientName: "payments-gateway",
            DisplayName: "Payments Gateway",
            ApplicationType: "service",
            AuthenticationMode: "api-key",
            IsEnabled: true,
            Notes: null,
            CreatedAtUtc: NowUtc.AddHours(-2),
            UpdatedAtUtc: NowUtc.AddHours(-1),
            BoundPolicyIds: [policyId],
            Keys: keys);

    private static CryptoApiManagedClientKey CreateActiveKey(Guid clientId)
        => new(
            ClientKeyId: Guid.NewGuid(),
            ClientId: clientId,
            KeyName: "primary",
            KeyIdentifier: "kid-1",
            CredentialType: "shared-secret",
            SecretHashAlgorithm: "sha256",
            SecretHint: null,
            IsEnabled: true,
            CreatedAtUtc: NowUtc.AddHours(-1),
            UpdatedAtUtc: NowUtc.AddMinutes(-30),
            ExpiresAtUtc: NowUtc.AddDays(14),
            RevokedAtUtc: null,
            RevokedReason: null,
            LastUsedAtUtc: null);

    private static CryptoApiManagedClientKey CreateDisabledKey(Guid clientId)
        => CreateActiveKey(clientId) with { IsEnabled = false };

    private static CryptoApiManagedKeyAlias CreateAlias(Guid aliasId, Guid policyId, ulong? slotId, string? routeGroupName = null)
        => new(
            AliasId: aliasId,
            AliasName: "payments-signer",
            RouteGroupName: routeGroupName,
            DeviceRoute: null,
            SlotId: slotId,
            ObjectLabel: "Payments Key",
            ObjectIdHex: null,
            Notes: null,
            IsEnabled: true,
            CreatedAtUtc: NowUtc.AddHours(-2),
            UpdatedAtUtc: NowUtc.AddHours(-1),
            BoundPolicyIds: [policyId]);

    private static CryptoApiManagedPolicy CreatePolicy(Guid policyId, Guid clientId, Guid aliasId, bool enabled = true)
        => new(
            PolicyId: policyId,
            PolicyName: "payments-signing",
            Description: null,
            Revision: 1,
            AllowedOperations: ["sign", "verify"],
            IsEnabled: enabled,
            CreatedAtUtc: NowUtc.AddHours(-2),
            UpdatedAtUtc: NowUtc.AddHours(-1),
            BoundClientIds: [clientId],
            BoundAliasIds: [aliasId]);
}
