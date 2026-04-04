using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.Operations;
using Pkcs11Wrapper.CryptoApi.SharedState;
using static Pkcs11Wrapper.CryptoApi.Tests.PostgresTestEnvironment;

namespace Pkcs11Wrapper.CryptoApi.Tests;

public sealed class CryptoApiRoutesTests
{
    [PostgresFact]
    public async Task AuthorizeEndpointAcceptsAliasBasedRequestAndHidesInternalRouteDetails()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        await using WebApplicationFactory<Program> factory = CreateFactory(scope.Options);
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

    [PostgresFact]
    public async Task SignEndpointReusesAliasAuthorizationAndReturnsCustomerFacingPayload()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        FakeCustomerOperationService fakeOperations = new();
        await using WebApplicationFactory<Program> factory = CreateFactory(scope.Options, services =>
        {
            services.AddSingleton<ICryptoApiCustomerOperationService>(fakeOperations);
        });

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

    [PostgresFact]
    public async Task AuthorizeEndpointReturnsForbiddenWhenPolicyDoesNotAllowOperation()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        await using WebApplicationFactory<Program> factory = CreateFactory(scope.Options);
        SeededAccess access = await SeedAuthorizedAccessAsync(factory, ["sign"], "decrypt-only-target");

        HttpClient httpClient = factory.CreateClient();
        httpClient.DefaultRequestHeaders.Add("X-Api-Key-Id", access.Key.KeyIdentifier);
        httpClient.DefaultRequestHeaders.Add("X-Api-Key-Secret", access.Key.Secret);

        using HttpResponseMessage response = await httpClient.PostAsync(
            "/api/v1/operations/authorize",
            CreateJsonContent("{\"keyAlias\":\"decrypt-only-target\",\"operation\":\"decrypt\"}"));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        string content = await response.Content.ReadAsStringAsync();
        Assert.Contains("The caller is not allowed to use the requested key alias or operation.", content, StringComparison.Ordinal);
        Assert.DoesNotContain("Requested operation is not allowed for this key alias.", content, StringComparison.Ordinal);
    }

    [PostgresFact]
    public async Task RandomEndpointReturnsBadRequestWhenLengthIsInvalid()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        await using WebApplicationFactory<Program> factory = CreateFactory(scope.Options);
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

    [PostgresFact]
    public async Task SharedStateEndpointHidesConnectionTargetAndCountsByDefault()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        await using WebApplicationFactory<Program> factory = CreateFactory(scope.Options);
        using HttpClient httpClient = factory.CreateClient();
        using HttpResponseMessage response = await httpClient.GetAsync("/api/v1/shared-state");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using JsonDocument json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        JsonElement root = json.RootElement;
        Assert.True(root.GetProperty("configured").GetBoolean());
        Assert.Equal("Postgres", root.GetProperty("provider").GetString());
        Assert.True(root.TryGetProperty("schemaVersion", out _));
        Assert.True(root.TryGetProperty("sharedReadyAreas", out _));
        Assert.False(root.TryGetProperty("connectionTarget", out _));
        Assert.False(root.TryGetProperty("apiClientCount", out _));
        Assert.False(root.TryGetProperty("apiClientKeyCount", out _));
        Assert.False(root.TryGetProperty("keyAliasCount", out _));
        Assert.False(root.TryGetProperty("policyCount", out _));
    }

    [PostgresFact]
    public async Task AuthEndpointsUseGenericFailureDetailsByDefault()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        await using WebApplicationFactory<Program> factory = CreateFactory(scope.Options);
        using HttpClient httpClient = factory.CreateClient();

        using HttpResponseMessage authResponse = await httpClient.GetAsync("/api/v1/auth/self");
        string authContent = await authResponse.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, authResponse.StatusCode);
        Assert.Contains("The provided API credentials were rejected.", authContent, StringComparison.Ordinal);
        Assert.DoesNotContain("API key id and secret are required.", authContent, StringComparison.Ordinal);

        SeededAccess access = await SeedAuthorizedAccessAsync(factory, ["sign"], "payments-signer");
        httpClient.DefaultRequestHeaders.Add("X-Api-Key-Id", access.Key.KeyIdentifier);
        httpClient.DefaultRequestHeaders.Add("X-Api-Key-Secret", access.Key.Secret);

        using HttpResponseMessage authorizationResponse = await httpClient.PostAsync(
            "/api/v1/operations/authorize",
            CreateJsonContent("{\"keyAlias\":\"missing-alias\",\"operation\":\"sign\"}"));

        string authorizationContent = await authorizationResponse.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.Forbidden, authorizationResponse.StatusCode);
        Assert.Contains("The caller is not allowed to use the requested key alias or operation.", authorizationContent, StringComparison.Ordinal);
        Assert.DoesNotContain("Requested key alias was not found.", authorizationContent, StringComparison.Ordinal);
    }

    [PostgresFact]
    public async Task SecurityOptionsCanRestoreDetailedDiagnosticsForPrivateDeployments()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        await using WebApplicationFactory<Program> factory = CreateFactory(
            scope.Options,
            null,
            new Dictionary<string, string?>
            {
                ["CryptoApiSecurity:ExposeDetailedErrors"] = "true",
                ["CryptoApiSecurity:ExposeSharedStateDetails"] = "true"
            });

        using HttpClient httpClient = factory.CreateClient();

        using HttpResponseMessage sharedStateResponse = await httpClient.GetAsync("/api/v1/shared-state");
        string sharedStateContent = await sharedStateResponse.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, sharedStateResponse.StatusCode);
        Assert.Contains("connectionTarget", sharedStateContent, StringComparison.Ordinal);
        Assert.Contains("apiClientCount", sharedStateContent, StringComparison.Ordinal);

        using HttpResponseMessage authResponse = await httpClient.GetAsync("/api/v1/auth/self");
        string authContent = await authResponse.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, authResponse.StatusCode);
        Assert.Contains("API key id and secret are required.", authContent, StringComparison.Ordinal);
    }

    [PostgresFact]
    public async Task AuthEndpointReturnsRateLimitProblemDetailsAndRetryAfterHeader()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        await using WebApplicationFactory<Program> factory = CreateFactory(
            scope.Options,
            null,
            new Dictionary<string, string?>
            {
                ["CryptoApiRateLimiting:Authentication:PermitLimit"] = "1",
                ["CryptoApiRateLimiting:Authentication:WindowSeconds"] = "60",
                ["CryptoApiRateLimiting:Authentication:SegmentsPerWindow"] = "6",
                ["CryptoApiRateLimiting:Authentication:QueueLimit"] = "0"
            });

        using HttpClient httpClient = factory.CreateClient();

        using HttpResponseMessage firstResponse = await httpClient.GetAsync("/api/v1/auth/self");
        Assert.Equal(HttpStatusCode.Unauthorized, firstResponse.StatusCode);

        using HttpResponseMessage secondResponse = await httpClient.GetAsync("/api/v1/auth/self");
        string content = await secondResponse.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.TooManyRequests, secondResponse.StatusCode);
        Assert.Equal("application/problem+json", secondResponse.Content.Headers.ContentType?.MediaType);
        Assert.True(secondResponse.Headers.TryGetValues("Retry-After", out IEnumerable<string>? retryAfterValues));
        Assert.NotEmpty(retryAfterValues);
        Assert.Contains("Rate limit exceeded.", content, StringComparison.Ordinal);
        Assert.Contains("customer-authentication", content, StringComparison.Ordinal);
        Assert.Contains("instance-local", content, StringComparison.Ordinal);
        Assert.Contains("retryAfterSeconds", content, StringComparison.Ordinal);
    }

    [PostgresFact]
    public async Task OperationRateLimitsArePartitionedByPresentedApiKeyId()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        FakeCustomerOperationService fakeOperations = new();
        await using WebApplicationFactory<Program> factory = CreateFactory(
            scope.Options,
            services => services.AddSingleton<ICryptoApiCustomerOperationService>(fakeOperations),
            new Dictionary<string, string?>
            {
                ["CryptoApiRateLimiting:Operations:PermitLimit"] = "1",
                ["CryptoApiRateLimiting:Operations:WindowSeconds"] = "60",
                ["CryptoApiRateLimiting:Operations:SegmentsPerWindow"] = "6",
                ["CryptoApiRateLimiting:Operations:QueueLimit"] = "0"
            });

        SeededAccess firstAccess = await SeedAuthorizedAccessAsync(factory, ["sign"], "payments-signer", policyName: $"gateway-sign-{Guid.NewGuid():N}");
        SeededAccess secondAccess = await SeedAuthorizedAccessAsync(factory, ["sign"], "payments-signer-2", policyName: $"gateway-sign-{Guid.NewGuid():N}");

        using HttpClient firstClient = factory.CreateClient();
        firstClient.DefaultRequestHeaders.Add("X-Api-Key-Id", firstAccess.Key.KeyIdentifier);
        firstClient.DefaultRequestHeaders.Add("X-Api-Key-Secret", firstAccess.Key.Secret);

        using HttpResponseMessage firstAllowed = await firstClient.PostAsync(
            "/api/v1/operations/sign",
            CreateJsonContent("{\"keyAlias\":\"payments-signer\",\"algorithm\":\"RS256\",\"payloadBase64\":\"aGVsbG8=\"}"));
        Assert.Equal(HttpStatusCode.OK, firstAllowed.StatusCode);

        using HttpResponseMessage firstRejected = await firstClient.PostAsync(
            "/api/v1/operations/sign",
            CreateJsonContent("{\"keyAlias\":\"payments-signer\",\"algorithm\":\"RS256\",\"payloadBase64\":\"aGVsbG8=\"}"));
        string rejectedContent = await firstRejected.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.TooManyRequests, firstRejected.StatusCode);
        Assert.Contains("customer-operations", rejectedContent, StringComparison.Ordinal);

        using HttpClient secondClient = factory.CreateClient();
        secondClient.DefaultRequestHeaders.Add("X-Api-Key-Id", secondAccess.Key.KeyIdentifier);
        secondClient.DefaultRequestHeaders.Add("X-Api-Key-Secret", secondAccess.Key.Secret);

        using HttpResponseMessage secondAllowed = await secondClient.PostAsync(
            "/api/v1/operations/sign",
            CreateJsonContent("{\"keyAlias\":\"payments-signer-2\",\"algorithm\":\"RS256\",\"payloadBase64\":\"aGVsbG8=\"}"));

        Assert.Equal(HttpStatusCode.OK, secondAllowed.StatusCode);
        Assert.Equal(2, fakeOperations.Calls.Count);
        Assert.Equal("payments-signer", fakeOperations.Calls[0].AliasName);
        Assert.Equal("payments-signer-2", fakeOperations.Calls[1].AliasName);
    }

    [PostgresFact]
    public async Task AuthSelfWarmPathReusesCachedAuthenticationAndThrottlesLastUsedWrites()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        MutableTimeProvider timeProvider = new(DateTimeOffset.Parse("2026-04-04T10:00:00Z"));
        await using WebApplicationFactory<Program> factory = CreateFactory(
            scope.Options,
            services => ConfigureCountingSharedState(services, timeProvider),
            new Dictionary<string, string?>
            {
                ["CryptoApiRequestPathCaching:EntryTtlSeconds"] = "300",
                ["CryptoApiRequestPathCaching:LastUsedWriteIntervalSeconds"] = "30"
            });

        SeededAccess access = await SeedAuthorizedAccessAsync(factory, ["sign"], "payments-signer");
        CountingSharedStateStore store = factory.Services.GetRequiredService<CountingSharedStateStore>();
        int baselineSnapshotReads = store.SnapshotReads;
        int baselineAuthenticationStateReads = store.AuthenticationStateReads;
        int baselineLastUsedTouches = store.LastUsedTouches;

        using HttpClient httpClient = factory.CreateClient();
        httpClient.DefaultRequestHeaders.Add("X-Api-Key-Id", access.Key.KeyIdentifier);
        httpClient.DefaultRequestHeaders.Add("X-Api-Key-Secret", access.Key.Secret);

        for (int i = 0; i < 3; i++)
        {
            using HttpResponseMessage response = await httpClient.GetAsync("/api/v1/auth/self");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            timeProvider.Advance(TimeSpan.FromSeconds(10));
        }

        Assert.Equal(0, store.SnapshotReads - baselineSnapshotReads);
        Assert.Equal(1, store.AuthenticationStateReads - baselineAuthenticationStateReads);
        Assert.Equal(1, store.LastUsedTouches - baselineLastUsedTouches);

        timeProvider.Advance(TimeSpan.FromSeconds(15));
        using HttpResponseMessage afterInterval = await httpClient.GetAsync("/api/v1/auth/self");
        Assert.Equal(HttpStatusCode.OK, afterInterval.StatusCode);

        Assert.Equal(0, store.SnapshotReads - baselineSnapshotReads);
        Assert.Equal(1, store.AuthenticationStateReads - baselineAuthenticationStateReads);
        Assert.Equal(2, store.LastUsedTouches - baselineLastUsedTouches);
    }

    [PostgresFact]
    public async Task OperationWarmPathReusesAuthenticationAndAuthorizationCaches()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        MutableTimeProvider timeProvider = new(DateTimeOffset.Parse("2026-04-04T10:00:00Z"));
        FakeCustomerOperationService fakeOperations = new();
        await using WebApplicationFactory<Program> factory = CreateFactory(
            scope.Options,
            services =>
            {
                ConfigureCountingSharedState(services, timeProvider);
                services.AddSingleton<ICryptoApiCustomerOperationService>(fakeOperations);
            },
            new Dictionary<string, string?>
            {
                ["CryptoApiRequestPathCaching:EntryTtlSeconds"] = "300",
                ["CryptoApiRequestPathCaching:LastUsedWriteIntervalSeconds"] = "30"
            });

        SeededAccess access = await SeedAuthorizedAccessAsync(factory, ["sign"], "payments-signer");
        CountingSharedStateStore store = factory.Services.GetRequiredService<CountingSharedStateStore>();
        int baselineSnapshotReads = store.SnapshotReads;
        int baselineAuthenticationStateReads = store.AuthenticationStateReads;
        int baselineAuthorizationStateReads = store.AuthorizationStateReads;
        int baselineLastUsedTouches = store.LastUsedTouches;

        using HttpClient httpClient = factory.CreateClient();
        httpClient.DefaultRequestHeaders.Add("X-Api-Key-Id", access.Key.KeyIdentifier);
        httpClient.DefaultRequestHeaders.Add("X-Api-Key-Secret", access.Key.Secret);

        for (int i = 0; i < 3; i++)
        {
            using HttpResponseMessage response = await httpClient.PostAsync(
                "/api/v1/operations/sign",
                CreateJsonContent("{\"keyAlias\":\"payments-signer\",\"algorithm\":\"RS256\",\"payloadBase64\":\"aGVsbG8=\"}"));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            timeProvider.Advance(TimeSpan.FromSeconds(5));
        }

        Assert.Equal(0, store.SnapshotReads - baselineSnapshotReads);
        Assert.Equal(1, store.AuthenticationStateReads - baselineAuthenticationStateReads);
        Assert.Equal(1, store.AuthorizationStateReads - baselineAuthorizationStateReads);
        Assert.Equal(1, store.LastUsedTouches - baselineLastUsedTouches);
        Assert.Equal(3, fakeOperations.Calls.Count);
    }

    [PostgresFact]
    public async Task OperationAuthorizationCacheInvalidatesWhenKeyIsRevoked()
    {
        await using PostgresTestScope scope = await CreateScopeAsync();
        MutableTimeProvider timeProvider = new(DateTimeOffset.Parse("2026-04-04T10:00:00Z"));
        FakeCustomerOperationService fakeOperations = new();
        await using WebApplicationFactory<Program> factory = CreateFactory(
            scope.Options,
            services =>
            {
                ConfigureCountingSharedState(services, timeProvider);
                services.AddSingleton<ICryptoApiCustomerOperationService>(fakeOperations);
            },
            new Dictionary<string, string?>
            {
                ["CryptoApiRequestPathCaching:EntryTtlSeconds"] = "300",
                ["CryptoApiRequestPathCaching:LastUsedWriteIntervalSeconds"] = "30"
            });

        SeededAccess access = await SeedAuthorizedAccessAsync(factory, ["sign"], "payments-signer");

        using HttpClient httpClient = factory.CreateClient();
        httpClient.DefaultRequestHeaders.Add("X-Api-Key-Id", access.Key.KeyIdentifier);
        httpClient.DefaultRequestHeaders.Add("X-Api-Key-Secret", access.Key.Secret);

        using HttpResponseMessage firstResponse = await httpClient.PostAsync(
            "/api/v1/operations/sign",
            CreateJsonContent("{\"keyAlias\":\"payments-signer\",\"algorithm\":\"RS256\",\"payloadBase64\":\"aGVsbG8=\"}"));
        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);

        using (IServiceScope requestScope = factory.Services.CreateScope())
        {
            CryptoApiClientManagementService clientManagement = requestScope.ServiceProvider.GetRequiredService<CryptoApiClientManagementService>();
            await clientManagement.RevokeClientKeyAsync(access.Key.ClientKeyId, "rotation");
        }

        using HttpResponseMessage secondResponse = await httpClient.PostAsync(
            "/api/v1/operations/sign",
            CreateJsonContent("{\"keyAlias\":\"payments-signer\",\"algorithm\":\"RS256\",\"payloadBase64\":\"aGVsbG8=\"}"));
        string content = await secondResponse.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Unauthorized, secondResponse.StatusCode);
        Assert.Contains("The provided API credentials were rejected.", content, StringComparison.Ordinal);
        Assert.Single(fakeOperations.Calls);
    }

    private static void ConfigureCountingSharedState(IServiceCollection services, TimeProvider timeProvider)
    {
        services.RemoveAll<TimeProvider>();
        services.AddSingleton<TimeProvider>(timeProvider);
        services.RemoveAll<ICryptoApiSharedStateStore>();
        services.AddSingleton(sp => new PostgresCryptoApiSharedStateStore(sp.GetRequiredService<IOptions<CryptoApiSharedPersistenceOptions>>()));
        services.AddSingleton<CountingSharedStateStore>();
        services.AddSingleton<ICryptoApiSharedStateStore>(sp => sp.GetRequiredService<CountingSharedStateStore>());
    }

    private static async Task<SeededAccess> SeedAuthorizedAccessAsync(WebApplicationFactory<Program> factory, IReadOnlyCollection<string> allowedOperations, string aliasName, string? policyName = null)
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
            PolicyName: policyName ?? $"gateway-{string.Join('-', allowedOperations)}",
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

    private static WebApplicationFactory<Program> CreateFactory(CryptoApiSharedPersistenceOptions sharedPersistenceOptions, Action<IServiceCollection>? configureServices = null, IReadOnlyDictionary<string, string?>? additionalConfiguration = null)
        => new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Development");
                builder.ConfigureAppConfiguration((_, configurationBuilder) =>
                {
                    Dictionary<string, string?> configuration = new()
                    {
                        ["CryptoApiHost:ServiceName"] = "Pkcs11Wrapper.CryptoApi.Tests",
                        ["CryptoApiHost:ApiBasePath"] = "/api/v1",
                        ["CryptoApiRuntime:DisableHttpsRedirection"] = "true",
                        ["CryptoApiSharedPersistence:Provider"] = sharedPersistenceOptions.Provider,
                        ["CryptoApiSharedPersistence:ConnectionString"] = sharedPersistenceOptions.ConnectionString,
                        ["CryptoApiSharedPersistence:AutoInitialize"] = sharedPersistenceOptions.AutoInitialize ? "true" : "false"
                    };

                    if (additionalConfiguration is not null)
                    {
                        foreach ((string key, string? value) in additionalConfiguration)
                        {
                            configuration[key] = value;
                        }
                    }

                    configurationBuilder.AddInMemoryCollection(configuration);
                });

                if (configureServices is not null)
                {
                    builder.ConfigureServices(configureServices);
                }
            });

    private static StringContent CreateJsonContent(string json)
        => new(json, Encoding.UTF8, "application/json");

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

    private sealed class CountingSharedStateStore(PostgresCryptoApiSharedStateStore inner) : ICryptoApiSharedStateStore
    {
        public int SnapshotReads { get; private set; }

        public int AuthenticationStateReads { get; private set; }

        public int AuthorizationStateReads { get; private set; }

        public int LastUsedTouches { get; private set; }

        public Task InitializeAsync(CancellationToken cancellationToken = default)
            => inner.InitializeAsync(cancellationToken);

        public Task<CryptoApiSharedStateStatus> GetStatusAsync(CancellationToken cancellationToken = default)
            => inner.GetStatusAsync(cancellationToken);

        public Task<long> GetAuthStateRevisionAsync(CancellationToken cancellationToken = default)
            => inner.GetAuthStateRevisionAsync(cancellationToken);

        public async Task<CryptoApiClientAuthenticationState?> GetClientAuthenticationStateAsync(string keyIdentifier, CancellationToken cancellationToken = default)
        {
            AuthenticationStateReads++;
            return await inner.GetClientAuthenticationStateAsync(keyIdentifier, cancellationToken);
        }

        public async Task<CryptoApiKeyAuthorizationState> GetKeyAuthorizationStateAsync(Guid clientId, string aliasName, CancellationToken cancellationToken = default)
        {
            AuthorizationStateReads++;
            return await inner.GetKeyAuthorizationStateAsync(clientId, aliasName, cancellationToken);
        }

        public Task UpsertClientAsync(CryptoApiClientRecord client, CancellationToken cancellationToken = default)
            => inner.UpsertClientAsync(client, cancellationToken);

        public Task UpsertClientKeyAsync(CryptoApiClientKeyRecord clientKey, CancellationToken cancellationToken = default)
            => inner.UpsertClientKeyAsync(clientKey, cancellationToken);

        public async Task<bool> TryTouchClientKeyLastUsedAsync(Guid clientKeyId, DateTimeOffset lastUsedAtUtc, TimeSpan minimumInterval, CancellationToken cancellationToken = default)
        {
            LastUsedTouches++;
            return await inner.TryTouchClientKeyLastUsedAsync(clientKeyId, lastUsedAtUtc, minimumInterval, cancellationToken);
        }

        public Task UpsertKeyAliasAsync(CryptoApiKeyAliasRecord keyAlias, CancellationToken cancellationToken = default)
            => inner.UpsertKeyAliasAsync(keyAlias, cancellationToken);

        public Task UpsertPolicyAsync(CryptoApiPolicyRecord policy, CancellationToken cancellationToken = default)
            => inner.UpsertPolicyAsync(policy, cancellationToken);

        public Task ReplaceClientPolicyBindingsAsync(Guid clientId, IReadOnlyCollection<Guid> policyIds, CancellationToken cancellationToken = default)
            => inner.ReplaceClientPolicyBindingsAsync(clientId, policyIds, cancellationToken);

        public Task ReplaceKeyAliasPolicyBindingsAsync(Guid aliasId, IReadOnlyCollection<Guid> policyIds, CancellationToken cancellationToken = default)
            => inner.ReplaceKeyAliasPolicyBindingsAsync(aliasId, policyIds, cancellationToken);

        public async Task<CryptoApiSharedStateSnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
        {
            SnapshotReads++;
            return await inner.GetSnapshotAsync(cancellationToken);
        }
    }

    private sealed class MutableTimeProvider(DateTimeOffset initialUtcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = initialUtcNow;

        public override DateTimeOffset GetUtcNow()
            => _utcNow;

        public void Advance(TimeSpan delta)
            => _utcNow = _utcNow.Add(delta);
    }
}
