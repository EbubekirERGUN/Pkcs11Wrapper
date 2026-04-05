using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Pkcs11Wrapper;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.SharedState;
using Pkcs11Wrapper.Native;

namespace Pkcs11Wrapper.CryptoApiPerf;

internal static class Program
{
    private static async Task<int> Main(string[] args)
    {
        try
        {
            CryptoApiPerfOptions options = CryptoApiPerfOptions.Parse(args);
            Directory.CreateDirectory(options.ResultsRoot);

            SeededAccess seededAccess = await SeedAuthorizedAccessAsync(options);
            using HttpClient singleClient = CreateHttpClient(options.SingleBaseUrl, seededAccess);
            using HttpClient multiClient = CreateHttpClient(options.MultiBaseUrl, seededAccess);

            List<CryptoApiPerfResult> results =
            [
                await RunSignScenarioAsync(options, singleClient, seededAccess.Alias.AliasName, topology: "single-instance", targetBaseUrl: options.SingleBaseUrl, copies: options.SingleInstanceCopies),
                await RunRandomScenarioAsync(options, singleClient, seededAccess.Alias.AliasName, topology: "single-instance", targetBaseUrl: options.SingleBaseUrl, copies: options.SingleInstanceCopies),
                await RunMixedScenarioAsync(options, singleClient, seededAccess.Alias.AliasName, topology: "single-instance", targetBaseUrl: options.SingleBaseUrl, copies: options.SingleInstanceCopies),
                await RunSignScenarioAsync(options, multiClient, seededAccess.Alias.AliasName, topology: "multi-instance", targetBaseUrl: options.MultiBaseUrl, copies: options.MultiInstanceCopies),
                await RunRandomScenarioAsync(options, multiClient, seededAccess.Alias.AliasName, topology: "multi-instance", targetBaseUrl: options.MultiBaseUrl, copies: options.MultiInstanceCopies),
                await RunMixedScenarioAsync(options, multiClient, seededAccess.Alias.AliasName, topology: "multi-instance", targetBaseUrl: options.MultiBaseUrl, copies: options.MultiInstanceCopies)
            ];

            CryptoApiPerfSummaryWriter.Write(options, results);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex);
            return 1;
        }
    }

    private static HttpClient CreateHttpClient(string baseUrl, SeededAccess seededAccess)
    {
        SocketsHttpHandler handler = new()
        {
            MaxConnectionsPerServer = 512,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate
        };

        HttpClient client = new(handler)
        {
            BaseAddress = new Uri(baseUrl),
            Timeout = TimeSpan.FromSeconds(30)
        };

        client.DefaultRequestHeaders.Add(CryptoApiAuthenticationDefaults.ApiKeyIdHeaderName, seededAccess.Key.KeyIdentifier);
        client.DefaultRequestHeaders.Add(CryptoApiAuthenticationDefaults.ApiKeySecretHeaderName, seededAccess.Key.Secret);
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return client;
    }

    private static async Task<SeededAccess> SeedAuthorizedAccessAsync(CryptoApiPerfOptions options)
    {
        ServiceCollection services = new();
        services.AddSingleton(TimeProvider.System);
        services.AddOptions<CryptoApiSharedPersistenceOptions>()
            .Configure(sharedOptions =>
            {
                sharedOptions.Provider = CryptoApiSharedPersistenceDefaults.PostgresProvider;
                sharedOptions.ConnectionString = options.SharedPersistenceConnectionString;
                sharedOptions.AutoInitialize = true;
            });
        services.AddCryptoApiSharedStateStore();
        services.AddSingleton<CryptoApiClientSecretGenerator>();
        services.AddSingleton<CryptoApiClientSecretHasher>();
        services.AddSingleton<CryptoApiClientManagementService>();
        services.AddSingleton<CryptoApiKeyAccessManagementService>();

        await using ServiceProvider serviceProvider = services.BuildServiceProvider();
        ICryptoApiSharedStateStore sharedStateStore = serviceProvider.GetRequiredService<ICryptoApiSharedStateStore>();
        await sharedStateStore.InitializeAsync();

        CryptoApiClientManagementService clientManagement = serviceProvider.GetRequiredService<CryptoApiClientManagementService>();
        CryptoApiKeyAccessManagementService accessManagement = serviceProvider.GetRequiredService<CryptoApiKeyAccessManagementService>();

        string suffix = Guid.NewGuid().ToString("N");
        CryptoApiManagedClient client = await clientManagement.CreateClientAsync(new CreateCryptoApiClientRequest(
            ClientName: $"perf-client-{suffix}",
            DisplayName: "Crypto API Perf Client",
            ApplicationType: "perf-harness",
            Notes: "Committed Crypto API performance regression harness client."));
        CryptoApiCreatedClientKey key = await clientManagement.CreateClientKeyAsync(new CreateCryptoApiClientKeyRequest(client.ClientId, "primary", null));
        CryptoApiManagedPolicy policy = await accessManagement.CreatePolicyAsync(new CreateCryptoApiPolicyRequest(
            PolicyName: $"perf-policy-{suffix}",
            Description: "Allows sign/random for the committed Crypto API performance regression harness.",
            AllowedOperations: ["sign", "random"]));
        ulong slotId = ResolveSlotId(options.ModulePath, options.TokenLabel);
        CryptoApiManagedKeyAlias alias = await accessManagement.CreateKeyAliasAsync(new CreateCryptoApiKeyAliasRequest(
            AliasName: $"perf-signer-{suffix}",
            RouteGroupName: null,
            DeviceRoute: null,
            SlotId: slotId,
            ObjectLabel: options.SignObjectLabel,
            ObjectIdHex: options.SignObjectIdHex,
            Notes: "SoftHSM-backed alias for Crypto API perf regression runs."));
        await accessManagement.ReplaceClientPoliciesAsync(client.ClientId, [policy.PolicyId]);
        await accessManagement.ReplaceKeyAliasPoliciesAsync(alias.AliasId, [policy.PolicyId]);
        return new SeededAccess(client, key, alias, policy);
    }

    private static ulong ResolveSlotId(string modulePath, string tokenLabel)
    {
        using Pkcs11Module module = Pkcs11Module.Load(modulePath);
        module.Initialize();

        int slotCount = module.GetSlotCount(tokenPresentOnly: false);
        Pkcs11SlotId[] slots = new Pkcs11SlotId[slotCount];
        _ = module.TryGetSlots(slots, out int written, tokenPresentOnly: false);

        for (int i = 0; i < written; i++)
        {
            if (module.TryGetTokenInfo(slots[i], out Pkcs11TokenInfo tokenInfo)
                && string.Equals(tokenInfo.Label.Trim(), tokenLabel, StringComparison.Ordinal))
            {
                return (ulong)slots[i].Value;
            }
        }

        throw new InvalidOperationException($"Token '{tokenLabel}' was not found in module '{modulePath}'.");
    }

    private static Task<CryptoApiPerfResult> RunSignScenarioAsync(CryptoApiPerfOptions options, HttpClient client, string aliasName, string topology, string targetBaseUrl, int copies)
    {
        string payloadBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(new string('S', 1024)));
        string requestBody = JsonSerializer.Serialize(new { keyAlias = aliasName, algorithm = "RS256", payloadBase64 });
        return RunScenarioAsync(
            options,
            name: $"{topology}-sign",
            topology: topology,
            workload: "sign",
            description: "RS256 sign with a fixed 1 KiB payload.",
            targetBaseUrl: targetBaseUrl,
            copies: copies,
            requestFactory: () => PostJsonAsync(client, "/api/v1/operations/sign", requestBody));
    }

    private static Task<CryptoApiPerfResult> RunRandomScenarioAsync(CryptoApiPerfOptions options, HttpClient client, string aliasName, string topology, string targetBaseUrl, int copies)
    {
        string requestBody = JsonSerializer.Serialize(new { keyAlias = aliasName, length = 32 });
        return RunScenarioAsync(
            options,
            name: $"{topology}-random",
            topology: topology,
            workload: "random",
            description: "32-byte PKCS#11 random generation.",
            targetBaseUrl: targetBaseUrl,
            copies: copies,
            requestFactory: () => PostJsonAsync(client, "/api/v1/operations/random", requestBody));
    }

    private static Task<CryptoApiPerfResult> RunMixedScenarioAsync(CryptoApiPerfOptions options, HttpClient client, string aliasName, string topology, string targetBaseUrl, int copies)
    {
        string payloadBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(new string('M', 1024)));
        string signBody = JsonSerializer.Serialize(new { keyAlias = aliasName, algorithm = "RS256", payloadBase64 });
        string randomBody = JsonSerializer.Serialize(new { keyAlias = aliasName, length = 32 });
        DeterministicMixedSelector selector = new();

        return RunScenarioAsync(
            options,
            name: $"{topology}-mixed",
            topology: topology,
            workload: "mixed",
            description: "Deterministic 70/30 mix of RS256 sign and 32-byte random requests.",
            targetBaseUrl: targetBaseUrl,
            copies: copies,
            requestFactory: () => selector.NextIsSign()
                ? PostJsonAsync(client, "/api/v1/operations/sign", signBody)
                : PostJsonAsync(client, "/api/v1/operations/random", randomBody));
    }

    private static async Task<CryptoApiPerfResult> RunScenarioAsync(
        CryptoApiPerfOptions options,
        string name,
        string topology,
        string workload,
        string description,
        string targetBaseUrl,
        int copies,
        Func<Task<RequestOutcome>> requestFactory)
    {
        string reportFolder = Path.Combine(options.ResultsRoot, name);
        Directory.CreateDirectory(reportFolder);

        Console.WriteLine($"[{DateTimeOffset.UtcNow:O}] Warm-up {name} ({copies} copies for {options.WarmUpDuration}).");
        await RunPhaseAsync(requestFactory, copies, options.WarmUpDuration, collectLatencies: false);

        Console.WriteLine($"[{DateTimeOffset.UtcNow:O}] Measure {name} ({copies} copies for {options.BombingDuration}).");
        ScenarioMeasurement measurement = await RunPhaseAsync(requestFactory, copies, options.BombingDuration, collectLatencies: true);
        await WriteScenarioArtifactsAsync(reportFolder, name, topology, workload, description, targetBaseUrl, copies, measurement);

        return new CryptoApiPerfResult(
            Name: name,
            Topology: topology,
            Workload: workload,
            Description: description,
            TargetBaseUrl: targetBaseUrl,
            Copies: copies,
            OkCount: measurement.OkCount,
            FailCount: measurement.FailCount,
            RequestRate: measurement.OkCount / options.BombingDuration.TotalSeconds,
            MeanLatencyMilliseconds: measurement.MeanLatencyMilliseconds,
            P50LatencyMilliseconds: measurement.P50LatencyMilliseconds,
            P95LatencyMilliseconds: measurement.P95LatencyMilliseconds,
            P99LatencyMilliseconds: measurement.P99LatencyMilliseconds,
            MaxLatencyMilliseconds: measurement.MaxLatencyMilliseconds);
    }

    private static async Task<ScenarioMeasurement> RunPhaseAsync(
        Func<Task<RequestOutcome>> requestFactory,
        int copies,
        TimeSpan duration,
        bool collectLatencies)
    {
        long deadline = Stopwatch.GetTimestamp() + (long)(duration.TotalSeconds * Stopwatch.Frequency);
        WorkerResult[] workerResults = await Task.WhenAll(Enumerable.Range(0, copies).Select(_ => Task.Run(async () =>
        {
            List<double> latencies = collectLatencies ? [] : new List<double>(0);
            List<string> errors = [];
            int okCount = 0;
            int failCount = 0;

            while (Stopwatch.GetTimestamp() < deadline)
            {
                long started = Stopwatch.GetTimestamp();
                RequestOutcome outcome = await requestFactory();
                double elapsedMs = Stopwatch.GetElapsedTime(started).TotalMilliseconds;

                if (collectLatencies)
                {
                    latencies.Add(elapsedMs);
                }

                if (outcome.Success)
                {
                    okCount++;
                }
                else
                {
                    failCount++;
                    if (errors.Count < 10)
                    {
                        errors.Add(outcome.Error ?? "Unknown request failure.");
                    }
                }
            }

            return new WorkerResult(okCount, failCount, latencies, errors);
        })));

        List<double> allLatencies = collectLatencies
            ? workerResults.SelectMany(static result => result.Latencies).ToList()
            : [];
        allLatencies.Sort();

        int ok = workerResults.Sum(static result => result.OkCount);
        int fail = workerResults.Sum(static result => result.FailCount);
        List<string> errors = workerResults.SelectMany(static result => result.Errors).Take(20).ToList();

        if (ok == 0 && fail > 0)
        {
            throw new InvalidOperationException($"All requests failed during the measured phase.{Environment.NewLine}{string.Join(Environment.NewLine, errors)}");
        }

        return new ScenarioMeasurement(
            OkCount: ok,
            FailCount: fail,
            MeanLatencyMilliseconds: allLatencies.Count == 0 ? 0 : allLatencies.Average(),
            P50LatencyMilliseconds: Percentile(allLatencies, 0.50),
            P95LatencyMilliseconds: Percentile(allLatencies, 0.95),
            P99LatencyMilliseconds: Percentile(allLatencies, 0.99),
            MaxLatencyMilliseconds: allLatencies.Count == 0 ? 0 : allLatencies[^1],
            Errors: errors);
    }

    private static async Task WriteScenarioArtifactsAsync(
        string reportFolder,
        string name,
        string topology,
        string workload,
        string description,
        string targetBaseUrl,
        int copies,
        ScenarioMeasurement measurement)
    {
        ScenarioArtifact artifact = new(
            Name: name,
            Topology: topology,
            Workload: workload,
            Description: description,
            TargetBaseUrl: targetBaseUrl,
            Copies: copies,
            OkCount: measurement.OkCount,
            FailCount: measurement.FailCount,
            MeanLatencyMilliseconds: measurement.MeanLatencyMilliseconds,
            P50LatencyMilliseconds: measurement.P50LatencyMilliseconds,
            P95LatencyMilliseconds: measurement.P95LatencyMilliseconds,
            P99LatencyMilliseconds: measurement.P99LatencyMilliseconds,
            MaxLatencyMilliseconds: measurement.MaxLatencyMilliseconds,
            Errors: measurement.Errors);

        string json = JsonSerializer.Serialize(artifact, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(reportFolder, "scenario.json"), json, new UTF8Encoding(false));
    }

    private static double Percentile(IReadOnlyList<double> values, double percentile)
    {
        if (values.Count == 0)
        {
            return 0;
        }

        int index = (int)Math.Ceiling((values.Count - 1) * percentile);
        index = Math.Clamp(index, 0, values.Count - 1);
        return values[index];
    }

    private static async Task<RequestOutcome> PostJsonAsync(HttpClient client, string path, string json)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, path)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        using HttpResponseMessage response = await client.SendAsync(request, HttpCompletionOption.ResponseContentRead);
        string body = await response.Content.ReadAsStringAsync();
        return response.IsSuccessStatusCode
            ? RequestOutcome.Ok()
            : RequestOutcome.Fail($"HTTP {(int)response.StatusCode}: {body}");
    }

    private sealed record SeededAccess(
        CryptoApiManagedClient Client,
        CryptoApiCreatedClientKey Key,
        CryptoApiManagedKeyAlias Alias,
        CryptoApiManagedPolicy Policy);

    private sealed record WorkerResult(int OkCount, int FailCount, IReadOnlyList<double> Latencies, IReadOnlyList<string> Errors);

    private sealed record ScenarioMeasurement(
        int OkCount,
        int FailCount,
        double MeanLatencyMilliseconds,
        double P50LatencyMilliseconds,
        double P95LatencyMilliseconds,
        double P99LatencyMilliseconds,
        double MaxLatencyMilliseconds,
        IReadOnlyList<string> Errors);

    private sealed record ScenarioArtifact(
        string Name,
        string Topology,
        string Workload,
        string Description,
        string TargetBaseUrl,
        int Copies,
        int OkCount,
        int FailCount,
        double MeanLatencyMilliseconds,
        double P50LatencyMilliseconds,
        double P95LatencyMilliseconds,
        double P99LatencyMilliseconds,
        double MaxLatencyMilliseconds,
        IReadOnlyList<string> Errors);

    private sealed record RequestOutcome(bool Success, string? Error)
    {
        public static RequestOutcome Ok() => new(true, null);

        public static RequestOutcome Fail(string error) => new(false, error);
    }

    private sealed class DeterministicMixedSelector
    {
        private static readonly bool[] Pattern = [true, true, true, false, true, true, false, true, true, false];
        private int _cursor = -1;

        public bool NextIsSign()
        {
            int index = Interlocked.Increment(ref _cursor);
            return Pattern[index % Pattern.Length];
        }
    }
}
