using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.Operations;

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
            SeededAccess access = await SeedAuthorizedAccessAsync(factory, ["sign"], "payments-signer");

            HttpClient httpClient = factory.CreateClient();
            httpClient.DefaultRequestHeaders.Add("X-Api-Key-Id", access.Key.KeyIdentifier);
            httpClient.DefaultRequestHeaders.Add("X-Api-Key-Secret", access.Key.Secret);

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
    public async Task SignEndpointReusesAliasAuthorizationAndReturnsCustomerFacingPayload()
    {
        string databasePath = CreateDatabasePath();
        FakeCustomerOperationService fakeOperations = new();
        await using WebApplicationFactory<Program> factory = CreateFactory(databasePath, services =>
        {
            services.AddSingleton<ICryptoApiCustomerOperationService>(fakeOperations);
        });

        try
        {
            SeededAccess access = await SeedAuthorizedAccessAsync(factory, ["sign"], "payments-signer");

            HttpClient httpClient = factory.CreateClient();
            httpClient.DefaultRequestHeaders.Add("X-Api-Key-Id", access.Key.KeyIdentifier);
            httpClient.DefaultRequestHeaders.Add("X-Api-Key-Secret", access.Key.Secret);

            using HttpResponseMessage response = await httpClient.PostAsync(
                "/api/v1/operations/sign",
                CreateJsonContent("{\"keyAlias\":\"payments-signer\",\"algorithm\":\"RS256\",\"payloadBase64\":\"aGVsbG8=\"}"));

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using JsonDocument json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            JsonElement root = json.RootElement;
            Assert.Equal("payments-signer", root.GetProperty("aliasName").GetString());
            Assert.Equal("RS256", root.GetProperty("algorithm").GetString());
            Assert.Equal(Convert.ToBase64String([0x01, 0x02, 0x03, 0x04]), root.GetProperty("signatureBase64").GetString());
            Assert.Equal(4, root.GetProperty("signatureLength").GetInt32());
            Assert.False(root.TryGetProperty("deviceRoute", out _));
            Assert.False(root.TryGetProperty("slotId", out _));
            Assert.Single(fakeOperations.Calls);
            Assert.Equal("sign", fakeOperations.Calls[0].Operation);
            Assert.Equal("payments-signer", fakeOperations.Calls[0].AliasName);
            Assert.Equal("RS256", fakeOperations.Calls[0].Algorithm);
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
            SeededAccess access = await SeedAuthorizedAccessAsync(factory, ["sign"], "decrypt-only-target");

            HttpClient httpClient = factory.CreateClient();
            httpClient.DefaultRequestHeaders.Add("X-Api-Key-Id", access.Key.KeyIdentifier);
            httpClient.DefaultRequestHeaders.Add("X-Api-Key-Secret", access.Key.Secret);

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

    [Fact]
    public async Task RandomEndpointReturnsBadRequestWhenLengthIsInvalid()
    {
        string databasePath = CreateDatabasePath();
        await using WebApplicationFactory<Program> factory = CreateFactory(databasePath);
        try
        {
            SeededAccess access = await SeedAuthorizedAccessAsync(factory, ["random"], "rng-primary");

            HttpClient httpClient = factory.CreateClient();
            httpClient.DefaultRequestHeaders.Add("X-Api-Key-Id", access.Key.KeyIdentifier);
            httpClient.DefaultRequestHeaders.Add("X-Api-Key-Secret", access.Key.Secret);

            using HttpResponseMessage response = await httpClient.PostAsync(
                "/api/v1/operations/random",
                CreateJsonContent("{\"keyAlias\":\"rng-primary\",\"length\":0}"));

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            string content = await response.Content.ReadAsStringAsync();
            Assert.Contains("Random request failed.", content, StringComparison.Ordinal);
            Assert.Contains("400", content, StringComparison.Ordinal);
        }
        finally
        {
            DeleteDatabaseArtifacts(databasePath);
        }
    }

    private static async Task<SeededAccess> SeedAuthorizedAccessAsync(WebApplicationFactory<Program> factory, IReadOnlyCollection<string> allowedOperations, string aliasName)
    {
        using IServiceScope scope = factory.Services.CreateScope();
        CryptoApiClientManagementService clientManagement = scope.ServiceProvider.GetRequiredService<CryptoApiClientManagementService>();
        CryptoApiKeyAccessManagementService accessManagement = scope.ServiceProvider.GetRequiredService<CryptoApiKeyAccessManagementService>();

        CryptoApiManagedClient client = await clientManagement.CreateClientAsync(new CreateCryptoApiClientRequest(
            ClientName: $"client-{Guid.NewGuid():N}",
            DisplayName: "Gateway A",
            ApplicationType: "gateway",
            Notes: null));
        CryptoApiCreatedClientKey key = await clientManagement.CreateClientKeyAsync(new CreateCryptoApiClientKeyRequest(client.ClientId, "primary", null));
        CryptoApiManagedPolicy policy = await accessManagement.CreatePolicyAsync(new CreateCryptoApiPolicyRequest(
            PolicyName: $"gateway-{string.Join('-', allowedOperations)}",
            Description: null,
            AllowedOperations: allowedOperations));
        CryptoApiManagedKeyAlias alias = await accessManagement.CreateKeyAliasAsync(new CreateCryptoApiKeyAliasRequest(
            AliasName: aliasName,
            DeviceRoute: "hsm-eu-primary",
            SlotId: 7,
            ObjectLabel: "Payments signing key",
            ObjectIdHex: "A1B2C3D4",
            Notes: null));
        await accessManagement.ReplaceClientPoliciesAsync(client.ClientId, [policy.PolicyId]);
        await accessManagement.ReplaceKeyAliasPoliciesAsync(alias.AliasId, [policy.PolicyId]);
        return new SeededAccess(client, key, alias, policy);
    }

    private static WebApplicationFactory<Program> CreateFactory(string databasePath, Action<IServiceCollection>? configureServices = null)
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

                if (configureServices is not null)
                {
                    builder.ConfigureServices(configureServices);
                }
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

    private sealed record SeededAccess(
        CryptoApiManagedClient Client,
        CryptoApiCreatedClientKey Key,
        CryptoApiManagedKeyAlias Alias,
        CryptoApiManagedPolicy Policy);

    private sealed class FakeCustomerOperationService : ICryptoApiCustomerOperationService
    {
        public List<FakeOperationCall> Calls { get; } = [];

        public CryptoApiSignOperationResult Sign(CryptoApiAuthorizedKeyOperation authorization, string? algorithm, string? payloadBase64)
        {
            Calls.Add(new FakeOperationCall(authorization.Operation, authorization.AliasName, algorithm ?? string.Empty));
            return new CryptoApiSignOperationResult("RS256", [0x01, 0x02, 0x03, 0x04], DateTimeOffset.Parse("2026-04-03T18:00:00Z"));
        }

        public CryptoApiVerifyOperationResult Verify(CryptoApiAuthorizedKeyOperation authorization, string? algorithm, string? payloadBase64, string? signatureBase64)
        {
            Calls.Add(new FakeOperationCall(authorization.Operation, authorization.AliasName, algorithm ?? string.Empty));
            return new CryptoApiVerifyOperationResult("RS256", true, DateTimeOffset.Parse("2026-04-03T18:01:00Z"));
        }

        public CryptoApiRandomOperationResult GenerateRandom(CryptoApiAuthorizedKeyOperation authorization, int length)
        {
            if (length <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length));
            }

            Calls.Add(new FakeOperationCall(authorization.Operation, authorization.AliasName, length.ToString()));
            return new CryptoApiRandomOperationResult(new byte[length], DateTimeOffset.Parse("2026-04-03T18:02:00Z"));
        }
    }

    private sealed record FakeOperationCall(string Operation, string AliasName, string Algorithm);
}
