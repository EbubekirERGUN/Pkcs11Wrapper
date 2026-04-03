using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Tests;

public sealed class CryptoApiSharedStateStoreTests
{
    [Fact]
    public async Task SharedStateStoreSharesStateAcrossIndependentInstances()
    {
        string databasePath = Path.Combine(Path.GetTempPath(), $"pkcs11wrapper-cryptoapi-{Guid.NewGuid():N}.db");
        try
        {
            CryptoApiSharedPersistenceOptions options = new()
            {
                Provider = "Sqlite",
                ConnectionString = $"Data Source={databasePath}",
                AutoInitialize = true
            };

            ICryptoApiSharedStateStore writer = new SqliteCryptoApiSharedStateStore(Options.Create(options));
            Guid clientId = Guid.NewGuid();
            Guid clientKeyId = Guid.NewGuid();
            Guid aliasId = Guid.NewGuid();
            Guid policyId = Guid.NewGuid();
            DateTimeOffset now = DateTimeOffset.UtcNow;

            await writer.UpsertClientAsync(new CryptoApiClientRecord(
                clientId,
                "ingress-gateway",
                "Ingress Gateway",
                "gateway",
                "api-key",
                true,
                "Primary calling service",
                now,
                now));
            await writer.UpsertClientKeyAsync(new CryptoApiClientKeyRecord(
                clientKeyId,
                clientId,
                "primary-hmac",
                "kid-ingress-primary",
                "api-key-secret",
                "pbkdf2-sha256-v1",
                "pbkdf2-sha256-v1$100000$salt$hash",
                "ing...mary",
                true,
                now,
                now,
                null,
                null,
                null,
                null));
            await writer.UpsertPolicyAsync(new CryptoApiPolicyRecord(
                policyId,
                "signing-default",
                "Default sign policy",
                1,
                "{\"version\":1,\"allowedOperations\":[\"sign\"]}",
                true,
                now,
                now));
            await writer.UpsertKeyAliasAsync(new CryptoApiKeyAliasRecord(
                aliasId,
                "payments-signer",
                "hsm-eu-primary",
                7,
                "Payments signing key",
                "A1B2C3D4",
                "Resolves the default outbound signing key.",
                true,
                now,
                now));
            await writer.ReplaceClientPolicyBindingsAsync(clientId, [policyId]);
            await writer.ReplaceKeyAliasPolicyBindingsAsync(aliasId, [policyId]);

            ICryptoApiSharedStateStore reader = new SqliteCryptoApiSharedStateStore(Options.Create(options));
            CryptoApiSharedStateStatus status = await reader.GetStatusAsync();
            CryptoApiSharedStateSnapshot snapshot = await reader.GetSnapshotAsync();

            Assert.True(status.Configured);
            Assert.Equal(CryptoApiSharedStateConstants.SchemaVersion, status.SchemaVersion);
            Assert.Equal(1, status.ApiClientCount);
            Assert.Equal(1, status.ApiClientKeyCount);
            Assert.Equal(1, status.KeyAliasCount);
            Assert.Equal(1, status.PolicyCount);
            Assert.Equal(1, status.ClientPolicyBindingCount);
            Assert.Equal(1, status.KeyAliasPolicyBindingCount);
            Assert.Equal(databasePath, status.ConnectionTarget);

            CryptoApiClientRecord client = Assert.Single(snapshot.Clients);
            Assert.Equal("ingress-gateway", client.ClientName);
            Assert.Equal("gateway", client.ApplicationType);
            Assert.Equal("api-key", client.AuthenticationMode);

            CryptoApiClientKeyRecord clientKey = Assert.Single(snapshot.ClientKeys);
            Assert.Equal(clientId, clientKey.ClientId);
            Assert.Equal("kid-ingress-primary", clientKey.KeyIdentifier);
            Assert.Equal("pbkdf2-sha256-v1", clientKey.SecretHashAlgorithm);
            Assert.Equal("pbkdf2-sha256-v1$100000$salt$hash", clientKey.SecretHash);
            Assert.Null(clientKey.RevokedAtUtc);
            Assert.Null(clientKey.LastUsedAtUtc);

            CryptoApiKeyAliasRecord alias = Assert.Single(snapshot.KeyAliases);
            Assert.Equal("hsm-eu-primary", alias.DeviceRoute);
            Assert.Equal((ulong)7, alias.SlotId);
            Assert.Equal("Payments signing key", alias.ObjectLabel);

            CryptoApiPolicyRecord policy = Assert.Single(snapshot.Policies);
            Assert.Equal("signing-default", policy.PolicyName);
            Assert.Contains("allowedOperations", policy.DocumentJson, StringComparison.Ordinal);

            CryptoApiClientPolicyBinding clientBinding = Assert.Single(snapshot.ClientPolicyBindings);
            Assert.Equal(clientId, clientBinding.ClientId);
            Assert.Equal(policyId, clientBinding.PolicyId);

            CryptoApiKeyAliasPolicyBinding aliasBinding = Assert.Single(snapshot.KeyAliasPolicyBindings);
            Assert.Equal(aliasId, aliasBinding.AliasId);
            Assert.Equal(policyId, aliasBinding.PolicyId);
        }
        finally
        {
            DeleteDatabaseArtifacts(databasePath);
        }
    }

    private static void DeleteDatabaseArtifacts(string databasePath)
    {
        string walPath = databasePath + "-wal";
        string shmPath = databasePath + "-shm";

        if (File.Exists(databasePath)) File.Delete(databasePath);
        if (File.Exists(walPath)) File.Delete(walPath);
        if (File.Exists(shmPath)) File.Delete(shmPath);
    }
}
