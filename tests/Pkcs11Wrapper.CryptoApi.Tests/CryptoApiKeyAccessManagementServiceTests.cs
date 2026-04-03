using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Tests;

public sealed class CryptoApiKeyAccessManagementServiceTests
{
    [Fact]
    public async Task BoundClientAndAliasAuthorizeRequestedOperationAndResolveInternalRoute()
    {
        string databasePath = CreateDatabasePath();
        try
        {
            var services = CreateServices(databasePath);
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
        finally
        {
            DeleteDatabaseArtifacts(databasePath);
        }
    }

    [Fact]
    public async Task AuthorizationFailsWhenOperationIsNotAllowedOrAliasIsDisabled()
    {
        string databasePath = CreateDatabasePath();
        try
        {
            var services = CreateServices(databasePath);
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
        finally
        {
            DeleteDatabaseArtifacts(databasePath);
        }
    }

    private static (ICryptoApiSharedStateStore Store, CryptoApiClientManagementService ClientManagement, CryptoApiClientAuthenticationService Authentication, CryptoApiKeyAccessManagementService AccessManagement, CryptoApiKeyOperationAuthorizationService Authorization) CreateServices(string databasePath)
    {
        CryptoApiSharedPersistenceOptions options = new()
        {
            Provider = "Sqlite",
            ConnectionString = $"Data Source={databasePath}",
            AutoInitialize = true
        };

        ICryptoApiSharedStateStore store = new SqliteCryptoApiSharedStateStore(Options.Create(options));
        CryptoApiClientSecretGenerator generator = new();
        CryptoApiClientSecretHasher hasher = new();
        TimeProvider timeProvider = TimeProvider.System;
        return (
            Store: store,
            ClientManagement: new CryptoApiClientManagementService(store, generator, hasher, timeProvider),
            Authentication: new CryptoApiClientAuthenticationService(store, hasher, timeProvider),
            AccessManagement: new CryptoApiKeyAccessManagementService(store, timeProvider),
            Authorization: new CryptoApiKeyOperationAuthorizationService(store, timeProvider));
    }

    private static string CreateDatabasePath()
        => Path.Combine(Path.GetTempPath(), $"pkcs11wrapper-cryptoapi-key-access-{Guid.NewGuid():N}.db");

    private static void DeleteDatabaseArtifacts(string databasePath)
    {
        string walPath = databasePath + "-wal";
        string shmPath = databasePath + "-shm";

        if (File.Exists(databasePath)) File.Delete(databasePath);
        if (File.Exists(walPath)) File.Delete(walPath);
        if (File.Exists(shmPath)) File.Delete(shmPath);
    }
}
