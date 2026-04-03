using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Clients;

namespace Pkcs11Wrapper.CryptoApi.Tests;

public sealed class CryptoApiRoutesTests
{
    [Fact]
    public async Task AuthorizeEndpointAcceptsAliasBasedRequestAndHidesInternalRouteDetails()
    {
        string databasePath = CreateDatabasePath();
        await using WebApplicationFactory<Program> factory = CreateFactory(databasePath);
        try
        {
            using IServiceScope scope = factory.Services.CreateScope();
            CryptoApiClientManagementService clientManagement = scope.ServiceProvider.GetRequiredService<CryptoApiClientManagementService>();
            CryptoApiKeyAccessManagementService accessManagement = scope.ServiceProvider.GetRequiredService<CryptoApiKeyAccessManagementService>();

            CryptoApiManagedClient client = await clientManagement.CreateClientAsync(new CreateCryptoApiClientRequest(
                ClientName: "gateway-a",
                DisplayName: "Gateway A",
                ApplicationType: "gateway",
                Notes: null));
            CryptoApiCreatedClientKey key = await clientManagement.CreateClientKeyAsync(new CreateCryptoApiClientKeyRequest(client.ClientId, "primary", null));
            CryptoApiManagedPolicy policy = await accessManagement.CreatePolicyAsync(new CreateCryptoApiPolicyRequest(
                PolicyName: "gateway-sign",
                Description: null,
                AllowedOperations: ["sign"]));
            CryptoApiManagedKeyAlias alias = await accessManagement.CreateKeyAliasAsync(new CreateCryptoApiKeyAliasRequest(
                AliasName: "payments-signer",
                DeviceRoute: "hsm-eu-primary",
                SlotId: 7,
                ObjectLabel: "Payments signing key",
                ObjectIdHex: "A1B2C3D4",
                Notes: null));
            await accessManagement.ReplaceClientPoliciesAsync(client.ClientId, [policy.PolicyId]);
            await accessManagement.ReplaceKeyAliasPoliciesAsync(alias.AliasId, [policy.PolicyId]);

            HttpClient httpClient = factory.CreateClient();
            httpClient.DefaultRequestHeaders.Add("X-Api-Key-Id", key.KeyIdentifier);
            httpClient.DefaultRequestHeaders.Add("X-Api-Key-Secret", key.Secret);

            using HttpResponseMessage response = await httpClient.PostAsync(
                "/api/v1/operations/authorize",
                CreateJsonContent("{\"keyAlias\":\"payments-signer\",\"operation\":\"sign\"}"));

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using JsonDocument json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            JsonElement root = json.RootElement;
            Assert.Equal("payments-signer", root.GetProperty("authorization").GetProperty("aliasName").GetString());
            Assert.Equal("sign", root.GetProperty("authorization").GetProperty("operation").GetString());
            Assert.Equal("gateway-sign", root.GetProperty("policies")[0].GetProperty("policyName").GetString());
            Assert.False(root.TryGetProperty("resolvedRoute", out _));
            Assert.False(root.GetProperty("authorization").TryGetProperty("deviceRoute", out _));
            Assert.False(root.GetProperty("authorization").TryGetProperty("slotId", out _));
            Assert.False(root.GetProperty("authorization").TryGetProperty("objectLabel", out _));
            Assert.False(root.GetProperty("authorization").TryGetProperty("objectIdHex", out _));
        }
        finally
        {
            DeleteDatabaseArtifacts(databasePath);
        }
    }

    [Fact]
    public async Task AuthorizeEndpointReturnsForbiddenWhenPolicyDoesNotAllowOperation()
    {
        string databasePath = CreateDatabasePath();
        await using WebApplicationFactory<Program> factory = CreateFactory(databasePath);
        try
        {
            using IServiceScope scope = factory.Services.CreateScope();
            CryptoApiClientManagementService clientManagement = scope.ServiceProvider.GetRequiredService<CryptoApiClientManagementService>();
            CryptoApiKeyAccessManagementService accessManagement = scope.ServiceProvider.GetRequiredService<CryptoApiKeyAccessManagementService>();

            CryptoApiManagedClient client = await clientManagement.CreateClientAsync(new CreateCryptoApiClientRequest(
                ClientName: "gateway-b",
                DisplayName: "Gateway B",
                ApplicationType: "gateway",
                Notes: null));
            CryptoApiCreatedClientKey key = await clientManagement.CreateClientKeyAsync(new CreateCryptoApiClientKeyRequest(client.ClientId, "primary", null));
            CryptoApiManagedPolicy policy = await accessManagement.CreatePolicyAsync(new CreateCryptoApiPolicyRequest(
                PolicyName: "gateway-sign-only",
                Description: null,
                AllowedOperations: ["sign"]));
            CryptoApiManagedKeyAlias alias = await accessManagement.CreateKeyAliasAsync(new CreateCryptoApiKeyAliasRequest(
                AliasName: "decrypt-only-target",
                DeviceRoute: null,
                SlotId: 2,
                ObjectLabel: "Decrypt key",
                ObjectIdHex: null,
                Notes: null));
            await accessManagement.ReplaceClientPoliciesAsync(client.ClientId, [policy.PolicyId]);
            await accessManagement.ReplaceKeyAliasPoliciesAsync(alias.AliasId, [policy.PolicyId]);

            HttpClient httpClient = factory.CreateClient();
            httpClient.DefaultRequestHeaders.Add("X-Api-Key-Id", key.KeyIdentifier);
            httpClient.DefaultRequestHeaders.Add("X-Api-Key-Secret", key.Secret);

            using HttpResponseMessage response = await httpClient.PostAsync(
                "/api/v1/operations/authorize",
                CreateJsonContent("{\"keyAlias\":\"decrypt-only-target\",\"operation\":\"decrypt\"}"));

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            string content = await response.Content.ReadAsStringAsync();
            Assert.Contains("Requested operation is not allowed for this key alias.", content, StringComparison.Ordinal);
        }
        finally
        {
            DeleteDatabaseArtifacts(databasePath);
        }
    }

    private static WebApplicationFactory<Program> CreateFactory(string databasePath)
        => new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Development");
                builder.ConfigureAppConfiguration((_, configurationBuilder) =>
                {
                    configurationBuilder.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["CryptoApiHost:ServiceName"] = "Pkcs11Wrapper.CryptoApi.Tests",
                        ["CryptoApiHost:ApiBasePath"] = "/api/v1",
                        ["CryptoApiRuntime:DisableHttpsRedirection"] = "true",
                        ["CryptoApiSharedPersistence:Provider"] = "Sqlite",
                        ["CryptoApiSharedPersistence:ConnectionString"] = $"Data Source={databasePath}",
                        ["CryptoApiSharedPersistence:AutoInitialize"] = "true"
                    });
                });
            });

    private static StringContent CreateJsonContent(string json)
        => new(json, Encoding.UTF8, "application/json");

    private static string CreateDatabasePath()
        => Path.Combine(Path.GetTempPath(), $"pkcs11wrapper-cryptoapi-routes-{Guid.NewGuid():N}.db");

    private static void DeleteDatabaseArtifacts(string databasePath)
    {
        string walPath = databasePath + "-wal";
        string shmPath = databasePath + "-shm";

        if (File.Exists(databasePath)) File.Delete(databasePath);
        if (File.Exists(walPath)) File.Delete(walPath);
        if (File.Exists(shmPath)) File.Delete(shmPath);
    }
}
