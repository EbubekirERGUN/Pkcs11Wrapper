using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Caching;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.SharedState;
using static Pkcs11Wrapper.CryptoApi.Tests.PostgresTestEnvironment;

namespace Pkcs11Wrapper.CryptoApi.Tests;

public sealed class CryptoApiKeyAccessManagementServiceTests
{
    [PostgresFact]
    public async Task BoundClientAndAliasAuthorizeRequestedOperationAndResolveInternalRoute()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        var services = CreateServices(scope.Options);
        CryptoApiManagedClient client = await services.ClientManagement.CreateClientAsync(new CreateCryptoApiClientRequest(
            ClientName: "payments-gateway",
            DisplayName: "Payments Gateway",
            ApplicationType: "gateway",
            Notes: null));
        CryptoApiCreatedClientKey key = await services.ClientManagement.CreateClientKeyAsync(new CreateCryptoApiClientKeyRequest(
            client.ClientId,
            "primary",
            null));
        CryptoApiManagedPolicy policy = await services.AccessManagement.CreatePolicyAsync(new CreateCryptoApiPolicyRequest(
            PolicyName: "payments-sign",
            Description: "Allow signing through the payments alias.",
            AllowedOperations: ["sign"]));
        CryptoApiManagedKeyAlias alias = await services.AccessManagement.CreateKeyAliasAsync(new CreateCryptoApiKeyAliasRequest(
            AliasName: "payments-signer",
            DeviceRoute: "hsm-eu-primary",
            SlotId: 7,
            ObjectLabel: "Payments signing key",
            ObjectIdHex: "a1-b2 c3:d4",
            Notes: "Primary outbound signing route"));

        await services.AccessManagement.ReplaceClientPoliciesAsync(client.ClientId, [policy.PolicyId]);
        await services.AccessManagement.ReplaceKeyAliasPoliciesAsync(alias.AliasId, [policy.PolicyId]);

        CryptoApiClientAuthenticationResult authenticated = await services.Authentication.AuthenticateAsync(key.KeyIdentifier, key.Secret);
        CryptoApiKeyOperationAuthorizationResult authorized = await services.Authorization.AuthorizeAsync(
            Assert.IsType<CryptoApiAuthenticatedClient>(authenticated.Client),
            "payments-signer",
            "sign");

        Assert.True(authorized.Succeeded);
        CryptoApiAuthorizedKeyOperation operation = Assert.IsType<CryptoApiAuthorizedKeyOperation>(authorized.Authorization);
        Assert.Equal("sign", operation.Operation);
        Assert.Equal(alias.AliasId, operation.AliasId);
        Assert.Equal("hsm-eu-primary", operation.ResolvedRoute.DeviceRoute);
        Assert.Equal((ulong)7, operation.ResolvedRoute.SlotId);
        Assert.Equal("Payments signing key", operation.ResolvedRoute.ObjectLabel);
        Assert.Equal("A1B2C3D4", operation.ResolvedRoute.ObjectIdHex);
        CryptoApiMatchedPolicy matchedPolicy = Assert.Single(operation.MatchedPolicies);
        Assert.Equal(policy.PolicyId, matchedPolicy.PolicyId);
    }

    [PostgresFact]
    public async Task AuthorizationFailsWhenOperationIsNotAllowedOrAliasIsDisabled()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        var services = CreateServices(scope.Options);
        CryptoApiManagedClient client = await services.ClientManagement.CreateClientAsync(new CreateCryptoApiClientRequest(
            ClientName: "reporting-worker",
            DisplayName: "Reporting Worker",
            ApplicationType: "worker",
            Notes: null));
        CryptoApiCreatedClientKey key = await services.ClientManagement.CreateClientKeyAsync(new CreateCryptoApiClientKeyRequest(
            client.ClientId,
            "default",
            null));
        CryptoApiManagedPolicy policy = await services.AccessManagement.CreatePolicyAsync(new CreateCryptoApiPolicyRequest(
            PolicyName: "reporting-sign-only",
            Description: null,
            AllowedOperations: ["sign"]));
        CryptoApiManagedKeyAlias alias = await services.AccessManagement.CreateKeyAliasAsync(new CreateCryptoApiKeyAliasRequest(
            AliasName: "reporting-signer",
            DeviceRoute: null,
            SlotId: 3,
            ObjectLabel: "Reporting key",
            ObjectIdHex: null,
            Notes: null));

        await services.AccessManagement.ReplaceClientPoliciesAsync(client.ClientId, [policy.PolicyId]);
        await services.AccessManagement.ReplaceKeyAliasPoliciesAsync(alias.AliasId, [policy.PolicyId]);

        CryptoApiAuthenticatedClient authenticated = Assert.IsType<CryptoApiAuthenticatedClient>((await services.Authentication.AuthenticateAsync(key.KeyIdentifier, key.Secret)).Client);
        CryptoApiKeyOperationAuthorizationResult wrongOperation = await services.Authorization.AuthorizeAsync(authenticated, alias.AliasName, "encrypt");

        Assert.False(wrongOperation.Succeeded);
        Assert.Equal("Requested operation is not allowed for this key alias.", wrongOperation.FailureReason);

        await services.AccessManagement.SetKeyAliasEnabledAsync(alias.AliasId, false);
        CryptoApiKeyOperationAuthorizationResult disabledAlias = await services.Authorization.AuthorizeAsync(authenticated, alias.AliasName, "sign");

        Assert.False(disabledAlias.Succeeded);
        Assert.Equal("Requested key alias is disabled.", disabledAlias.FailureReason);
    }

    [PostgresFact]
    public async Task CreateKeyAliasRequiresSlotIdForOperationalRoute()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        var services = CreateServices(scope.Options);

        ArgumentException ex = await Assert.ThrowsAsync<ArgumentException>(() => services.AccessManagement.CreateKeyAliasAsync(new CreateCryptoApiKeyAliasRequest(
            AliasName: "missing-slot",
            DeviceRoute: null,
            SlotId: null,
            ObjectLabel: "Payments signing key",
            ObjectIdHex: null,
            Notes: null)));

        Assert.Contains("slot id", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [PostgresFact]
    public async Task UpdateAliasAndPolicyPreserveBindingsAndRefreshSnapshot()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        var services = CreateServices(scope.Options);
        CryptoApiManagedClient client = await services.ClientManagement.CreateClientAsync(new CreateCryptoApiClientRequest(
            ClientName: "payments-gateway",
            DisplayName: "Payments Gateway",
            ApplicationType: "gateway",
            Notes: null));
        CryptoApiManagedPolicy policy = await services.AccessManagement.CreatePolicyAsync(new CreateCryptoApiPolicyRequest(
            PolicyName: "payments-sign",
            Description: "Allow signing through the payments alias.",
            AllowedOperations: ["sign"]));
        CryptoApiManagedKeyAlias alias = await services.AccessManagement.CreateKeyAliasAsync(new CreateCryptoApiKeyAliasRequest(
            AliasName: "payments-signer",
            DeviceRoute: "hsm-eu-primary",
            SlotId: 7,
            ObjectLabel: "Payments signing key",
            ObjectIdHex: "a1b2c3d4",
            Notes: null));

        await services.AccessManagement.ReplaceClientPoliciesAsync(client.ClientId, [policy.PolicyId]);
        await services.AccessManagement.ReplaceKeyAliasPoliciesAsync(alias.AliasId, [policy.PolicyId]);

        CryptoApiManagedKeyAlias updatedAlias = await services.AccessManagement.UpdateKeyAliasAsync(new UpdateCryptoApiKeyAliasRequest(
            AliasId: alias.AliasId,
            AliasName: "payments-signer-v2",
            DeviceRoute: "hsm-eu-secondary",
            SlotId: 11,
            ObjectLabel: "Payments signing key v2",
            ObjectIdHex: "ab:cd:ef:01",
            Notes: "Updated route"));

        CryptoApiManagedPolicy updatedPolicy = await services.AccessManagement.UpdatePolicyAsync(new UpdateCryptoApiPolicyRequest(
            PolicyId: policy.PolicyId,
            PolicyName: "payments-authorized-ops",
            Description: "Allow sign and verify.",
            AllowedOperations: ["verify", "sign"]));

        CryptoApiKeyAccessSnapshot snapshot = await services.AccessManagement.GetSnapshotAsync();
        CryptoApiManagedKeyAlias aliasFromSnapshot = Assert.Single(snapshot.KeyAliases, candidate => candidate.AliasId == alias.AliasId);
        CryptoApiManagedPolicy policyFromSnapshot = Assert.Single(snapshot.Policies, candidate => candidate.PolicyId == policy.PolicyId);

        Assert.Equal("payments-signer-v2", updatedAlias.AliasName);
        Assert.Equal((ulong)11, updatedAlias.SlotId);
        Assert.Equal("ABCDEF01", updatedAlias.ObjectIdHex);
        Assert.Contains(policy.PolicyId, updatedAlias.BoundPolicyIds);

        Assert.Equal("payments-authorized-ops", updatedPolicy.PolicyName);
        Assert.Equal(2, updatedPolicy.Revision);
        Assert.Equal(["sign", "verify"], updatedPolicy.AllowedOperations);
        Assert.Contains(client.ClientId, updatedPolicy.BoundClientIds);
        Assert.Contains(alias.AliasId, updatedPolicy.BoundAliasIds);

        Assert.Equal(updatedAlias.AliasName, aliasFromSnapshot.AliasName);
        Assert.Equal(updatedAlias.DeviceRoute, aliasFromSnapshot.DeviceRoute);
        Assert.Equal(updatedAlias.SlotId, aliasFromSnapshot.SlotId);
        Assert.Equal(updatedAlias.ObjectLabel, aliasFromSnapshot.ObjectLabel);
        Assert.Equal(updatedAlias.ObjectIdHex, aliasFromSnapshot.ObjectIdHex);
        Assert.Equal(updatedAlias.Notes, aliasFromSnapshot.Notes);
        Assert.Equal(updatedAlias.BoundPolicyIds, aliasFromSnapshot.BoundPolicyIds);

        Assert.Equal(updatedPolicy.PolicyName, policyFromSnapshot.PolicyName);
        Assert.Equal(updatedPolicy.Description, policyFromSnapshot.Description);
        Assert.Equal(updatedPolicy.Revision, policyFromSnapshot.Revision);
        Assert.Equal(updatedPolicy.AllowedOperations, policyFromSnapshot.AllowedOperations);
        Assert.Equal(updatedPolicy.BoundClientIds, policyFromSnapshot.BoundClientIds);
        Assert.Equal(updatedPolicy.BoundAliasIds, policyFromSnapshot.BoundAliasIds);
    }

    private static (ICryptoApiSharedStateStore Store, CryptoApiClientManagementService ClientManagement, CryptoApiClientAuthenticationService Authentication, CryptoApiKeyAccessManagementService AccessManagement, CryptoApiKeyOperationAuthorizationService Authorization) CreateServices(CryptoApiSharedPersistenceOptions options)
    {
        ICryptoApiSharedStateStore store = new PostgresCryptoApiSharedStateStore(Options.Create(options));
        ICryptoApiDistributedHotPathCache distributedHotPathCache = new NoOpCryptoApiDistributedHotPathCache();
        CryptoApiClientSecretGenerator generator = new();
        CryptoApiClientSecretHasher hasher = new();
        TimeProvider timeProvider = TimeProvider.System;
        return (
            Store: store,
            ClientManagement: new CryptoApiClientManagementService(store, generator, hasher, timeProvider),
            Authentication: new CryptoApiClientAuthenticationService(store, distributedHotPathCache, hasher, timeProvider),
            AccessManagement: new CryptoApiKeyAccessManagementService(store, timeProvider),
            Authorization: new CryptoApiKeyOperationAuthorizationService(store, distributedHotPathCache, timeProvider));
    }
}
