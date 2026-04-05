using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace Pkcs11Wrapper.CryptoApi.Gateway.Tests;

public sealed class CryptoApiGatewayRoutingTests
{
    [Fact]
    public async Task ServiceDocumentReportsConfiguredGatewayTopology()
    {
        await using TestBackendHost backendA = await TestBackendHost.StartAsync("crypto-a", HttpStatusCode.OK);
        await using TestBackendHost backendB = await TestBackendHost.StartAsync("crypto-b", HttpStatusCode.OK);
        await using WebApplicationFactory<Program> factory = CreateFactory([backendA, backendB]);

        using HttpClient client = factory.CreateClient();
        using HttpResponseMessage response = await client.GetAsync("/");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using JsonDocument json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        JsonElement root = json.RootElement;
        Assert.Equal("Pkcs11Wrapper.CryptoApi.Gateway.Tests", root.GetProperty("serviceName").GetString());
        Assert.Equal("crypto-api-fleet", root.GetProperty("clusterId").GetString());
        Assert.Equal("/api/v1", root.GetProperty("apiBasePath").GetString());
        Assert.Equal("RoundRobin", root.GetProperty("loadBalancingPolicy").GetString());
        Assert.Equal(2, root.GetProperty("configuredDestinationCount").GetInt32());
        Assert.True(root.GetProperty("activeHealthChecksEnabled").GetBoolean());
    }

    [Fact]
    public async Task GatewayBalancesAcrossHealthyBackends()
    {
        await using TestBackendHost backendA = await TestBackendHost.StartAsync("crypto-a", HttpStatusCode.OK);
        await using TestBackendHost backendB = await TestBackendHost.StartAsync("crypto-b", HttpStatusCode.OK);
        await using WebApplicationFactory<Program> factory = CreateFactory([backendA, backendB]);

        using HttpClient client = factory.CreateClient();
        List<string> instances = [];

        for (int i = 0; i < 6; i++)
        {
            using HttpResponseMessage response = await client.GetAsync("/api/v1/runtime");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using JsonDocument json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            instances.Add(json.RootElement.GetProperty("instanceName").GetString()!);
        }

        Assert.Contains("crypto-a", instances);
        Assert.Contains("crypto-b", instances);
        Assert.InRange(Math.Abs(instances.Count(static instance => instance == "crypto-a") - instances.Count(static instance => instance == "crypto-b")), 0, 1);
    }

    [Fact]
    public async Task ActiveHealthChecksRemoveUnhealthyDestinationFromSelection()
    {
        await using TestBackendHost healthyBackend = await TestBackendHost.StartAsync("crypto-healthy", HttpStatusCode.OK);
        await using TestBackendHost unhealthyBackend = await TestBackendHost.StartAsync("crypto-unhealthy", HttpStatusCode.ServiceUnavailable);
        await using WebApplicationFactory<Program> factory = CreateFactory(
            [healthyBackend, unhealthyBackend],
            new Dictionary<string, string?>
            {
                ["CryptoApiGateway:HealthChecks:Active:IntervalSeconds"] = "1",
                ["CryptoApiGateway:HealthChecks:Active:TimeoutSeconds"] = "1",
                ["CryptoApiGateway:HealthChecks:Active:ConsecutiveFailuresThreshold"] = "1"
            });

        await Task.Delay(TimeSpan.FromSeconds(3));

        using HttpClient client = factory.CreateClient();
        List<string> instances = [];
        for (int i = 0; i < 4; i++)
        {
            using HttpResponseMessage response = await client.GetAsync("/api/v1/runtime");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            using JsonDocument json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            instances.Add(json.RootElement.GetProperty("instanceName").GetString()!);
        }

        Assert.All(instances, static instance => Assert.Equal("crypto-healthy", instance));
    }

    [Fact]
    public async Task GatewayGeneratesAndPreservesCorrelationIdHeader()
    {
        await using TestBackendHost backend = await TestBackendHost.StartAsync("crypto-a", HttpStatusCode.OK);
        await using WebApplicationFactory<Program> factory = CreateFactory([backend]);
        using HttpClient client = factory.CreateClient();

        using HttpResponseMessage generatedResponse = await client.GetAsync("/api/v1/runtime");
        Assert.Equal(HttpStatusCode.OK, generatedResponse.StatusCode);
        Assert.True(generatedResponse.Headers.TryGetValues("X-Correlation-Id", out IEnumerable<string>? generatedValues));
        string generatedCorrelationId = Assert.Single(generatedValues);

        using JsonDocument generatedJson = JsonDocument.Parse(await generatedResponse.Content.ReadAsStringAsync());
        Assert.Equal(generatedCorrelationId, generatedJson.RootElement.GetProperty("correlationId").GetString());
        Assert.NotEmpty(generatedCorrelationId);

        HttpRequestMessage preservedRequest = new(HttpMethod.Get, "/api/v1/runtime");
        preservedRequest.Headers.Add("X-Correlation-Id", "corr-12345");
        using HttpResponseMessage preservedResponse = await client.SendAsync(preservedRequest);
        Assert.Equal(HttpStatusCode.OK, preservedResponse.StatusCode);
        Assert.True(preservedResponse.Headers.TryGetValues("X-Correlation-Id", out IEnumerable<string>? preservedValues));
        Assert.Equal("corr-12345", Assert.Single(preservedValues));

        using JsonDocument preservedJson = JsonDocument.Parse(await preservedResponse.Content.ReadAsStringAsync());
        Assert.Equal("corr-12345", preservedJson.RootElement.GetProperty("correlationId").GetString());
    }

    [Fact]
    public async Task GatewayRejectsRequestsAboveConfiguredBodyLimitBeforeProxying()
    {
        await using TestBackendHost backend = await TestBackendHost.StartAsync("crypto-a", HttpStatusCode.OK);
        await using WebApplicationFactory<Program> factory = CreateFactory(
            [backend],
            new Dictionary<string, string?>
            {
                ["CryptoApiGateway:MaxRequestBodySizeBytes"] = "16"
            });

        using HttpClient client = factory.CreateClient();

        using HttpResponseMessage rejected = await client.PostAsync(
            "/api/v1/echo",
            new StringContent("0123456789abcdefghijklmnop", Encoding.UTF8, "text/plain"));

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, rejected.StatusCode);
        Assert.Equal(0, backend.EchoRequestCount);

        using HttpResponseMessage accepted = await client.PostAsync(
            "/api/v1/echo",
            new StringContent("12345678", Encoding.UTF8, "text/plain"));

        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal(1, backend.EchoRequestCount);
    }

    [Fact]
    public async Task MetricsEndpointPublishesGatewayReadinessAndIngressCounters()
    {
        await using TestBackendHost backend = await TestBackendHost.StartAsync("crypto-a", HttpStatusCode.OK);
        await using WebApplicationFactory<Program> factory = CreateFactory(
            [backend],
            new Dictionary<string, string?>
            {
                ["CryptoApiGateway:MaxRequestBodySizeBytes"] = "8"
            });

        using HttpClient client = factory.CreateClient();

        using (HttpResponseMessage readyResponse = await client.GetAsync("/health/ready"))
        {
            Assert.Equal(HttpStatusCode.OK, readyResponse.StatusCode);
        }

        using (HttpResponseMessage rejected = await client.PostAsync(
                   "/api/v1/echo",
                   new StringContent("0123456789", Encoding.UTF8, "text/plain")))
        {
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, rejected.StatusCode);
        }

        using HttpResponseMessage metricsResponse = await client.GetAsync("/metrics");
        string metrics = await metricsResponse.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, metricsResponse.StatusCode);
        Assert.Contains("pkcs11wrapper_crypto_api_gateway_backend_readiness_probes_total", metrics, StringComparison.Ordinal);
        Assert.Contains("pkcs11wrapper_crypto_api_gateway_backend_readiness_probe_duration_seconds", metrics, StringComparison.Ordinal);
        Assert.Contains("pkcs11wrapper_crypto_api_gateway_request_body_rejections_total", metrics, StringComparison.Ordinal);
        Assert.Contains("pkcs11wrapper_crypto_api_gateway_healthy_destinations", metrics, StringComparison.Ordinal);
        Assert.Contains("pkcs11wrapper_crypto_api_gateway_configured_destinations", metrics, StringComparison.Ordinal);
    }

    private static WebApplicationFactory<Program> CreateFactory(IReadOnlyList<TestBackendHost> backends, IReadOnlyDictionary<string, string?>? additionalConfiguration = null)
        => new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Development");
                builder.ConfigureAppConfiguration((_, configurationBuilder) =>
                {
                    Dictionary<string, string?> configuration = new(StringComparer.OrdinalIgnoreCase)
                    {
                        ["CryptoApiGateway:ServiceName"] = "Pkcs11Wrapper.CryptoApi.Gateway.Tests",
                        ["CryptoApiGateway:ClusterId"] = "crypto-api-fleet",
                        ["CryptoApiGateway:ApiBasePath"] = "/api/v1",
                        ["CryptoApiGateway:LoadBalancingPolicy"] = "RoundRobin",
                        ["CryptoApiGateway:CorrelationIdHeaderName"] = "X-Correlation-Id",
                        ["CryptoApiGateway:HttpClient:ActivityTimeoutSeconds"] = "30",
                        ["CryptoApiGateway:HttpClient:DangerousAcceptAnyServerCertificate"] = "false",
                        ["CryptoApiGateway:HealthChecks:Active:Enabled"] = "true",
                        ["CryptoApiGateway:HealthChecks:Active:IntervalSeconds"] = "2",
                        ["CryptoApiGateway:HealthChecks:Active:TimeoutSeconds"] = "2",
                        ["CryptoApiGateway:HealthChecks:Active:ConsecutiveFailuresThreshold"] = "2",
                        ["CryptoApiGateway:HealthChecks:Active:Path"] = "/health/ready",
                        ["CryptoApiGateway:MaxRequestBodySizeBytes"] = "1048576"
                    };

                    for (int i = 0; i < backends.Count; i++)
                    {
                        configuration[$"CryptoApiGateway:Destinations:{i}:Name"] = backends[i].Name;
                        configuration[$"CryptoApiGateway:Destinations:{i}:Address"] = backends[i].BaseAddress;
                        configuration[$"CryptoApiGateway:Destinations:{i}:Health"] = backends[i].BaseAddress;
                        configuration[$"CryptoApiGateway:Destinations:{i}:Enabled"] = "true";
                    }

                    if (additionalConfiguration is not null)
                    {
                        foreach ((string key, string? value) in additionalConfiguration)
                        {
                            configuration[key] = value;
                        }
                    }

                    configurationBuilder.AddInMemoryCollection(configuration);
                });
            });

    private sealed class TestBackendHost : IAsyncDisposable
    {
        private readonly WebApplication _application;
        private readonly RequestCounts _requestCounts;

        private TestBackendHost(string name, string baseAddress, WebApplication application, RequestCounts requestCounts)
        {
            Name = name;
            BaseAddress = baseAddress;
            _application = application;
            _requestCounts = requestCounts;
        }

        public string Name { get; }

        public string BaseAddress { get; }

        public int EchoRequestCount => _requestCounts.EchoRequests;

        public static async Task<TestBackendHost> StartAsync(string name, HttpStatusCode readinessStatusCode)
        {
            int port = GetFreePort();
            string baseAddress = $"http://127.0.0.1:{port}/";
            RequestCounts requestCounts = new();

            WebApplicationBuilder builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                EnvironmentName = "Development"
            });
            builder.WebHost.UseUrls(baseAddress);

            WebApplication app = builder.Build();
            app.MapGet("/health/ready", () => Results.StatusCode((int)readinessStatusCode));
            app.MapGet("/api/v1/runtime", (HttpContext context) =>
            {
                int requestNumber = Interlocked.Increment(ref requestCounts.RuntimeRequests);
                return Results.Ok(new
                {
                    instanceName = name,
                    requestNumber,
                    correlationId = context.Request.Headers["X-Correlation-Id"].ToString()
                });
            });
            app.MapPost("/api/v1/echo", async (HttpContext context) =>
            {
                Interlocked.Increment(ref requestCounts.EchoRequests);
                using StreamReader reader = new(context.Request.Body, Encoding.UTF8, leaveOpen: true);
                string body = await reader.ReadToEndAsync();
                return Results.Ok(new
                {
                    instanceName = name,
                    correlationId = context.Request.Headers["X-Correlation-Id"].ToString(),
                    bodyLength = body.Length
                });
            });

            await app.StartAsync();
            return new TestBackendHost(name, baseAddress, app, requestCounts);
        }

        public async ValueTask DisposeAsync()
        {
            await _application.StopAsync();
            await _application.DisposeAsync();
        }

        private static int GetFreePort()
        {
            TcpListener listener = new(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        private sealed class RequestCounts
        {
            public int EchoRequests;

            public int RuntimeRequests;
        }
    }
}
