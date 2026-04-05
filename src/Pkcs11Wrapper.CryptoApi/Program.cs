using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using OpenTelemetry.Metrics;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Caching;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.Endpoints;
using Pkcs11Wrapper.CryptoApi.Health;
using Pkcs11Wrapper.CryptoApi.Observability;
using Pkcs11Wrapper.CryptoApi.Operations;
using Pkcs11Wrapper.CryptoApi.RateLimiting;
using Pkcs11Wrapper.CryptoApi.Runtime;
using Pkcs11Wrapper.CryptoApi.SharedState;
using Pkcs11Wrapper.Observability;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddProblemDetails();
builder.Services.AddOptions<CryptoApiHostOptions>()
    .Bind(builder.Configuration.GetSection(CryptoApiHostOptions.SectionName))
    .PostConfigure(static options =>
    {
        options.ServiceName = string.IsNullOrWhiteSpace(options.ServiceName)
            ? CryptoApiHostDefaults.DefaultServiceName
            : options.ServiceName.Trim();
        options.ApiBasePath = CryptoApiHostDefaults.NormalizeBasePath(options.ApiBasePath);
    })
    .Validate(static options => !string.IsNullOrWhiteSpace(options.ServiceName), "Crypto API service name must be configured.")
    .Validate(static options => options.ApiBasePath.StartsWith("/", StringComparison.Ordinal), "Crypto API base path must start with '/'.")
    .ValidateOnStart();

builder.Services.AddOptions<CryptoApiRuntimeOptions>()
    .Bind(builder.Configuration.GetSection(CryptoApiRuntimeOptions.SectionName))
    .PostConfigure(static options =>
    {
        options.ModulePath = options.ModulePath?.Trim();
        options.UserPin = options.UserPin?.Trim();
    })
    .Services.AddSingleton<IValidateOptions<CryptoApiRuntimeOptions>, CryptoApiRuntimeOptionsValidator>();

builder.Services.AddOptions<CryptoApiRuntimeOptions>()
    .Validate(static options => options.RouteFailureCooldownSeconds >= 0, "Crypto API route failure cooldown must be zero or greater.")
    .ValidateOnStart();

builder.Services.AddOptions<CryptoApiSecurityOptions>()
    .Bind(builder.Configuration.GetSection(CryptoApiSecurityOptions.SectionName));

builder.Services.AddOptions<CryptoApiRequestPathCachingOptions>()
    .Bind(builder.Configuration.GetSection(CryptoApiRequestPathCachingOptions.SectionName))
    .Validate(
        static options => options.AuthenticationEntryLimit > 0
            && options.AuthorizationEntryLimit > 0
            && options.EntryTtlSeconds > 0
            && options.LastUsedWriteIntervalSeconds > 0,
        "Crypto API request-path caching must define positive cache limits, TTL, and last-used write interval values.")
    .Validate(
        static options => !options.Redis.Enabled || !string.IsNullOrWhiteSpace(options.Redis.Configuration),
        "Crypto API Redis hot-path acceleration requires CryptoApiRequestPathCaching:Redis:Configuration when enabled.")
    .Validate(
        static options => !options.Redis.Enabled
            || (options.Redis.ConnectTimeoutMilliseconds > 0
                && options.Redis.OperationTimeoutMilliseconds > 0
                && options.Redis.AuthStateRevisionTtlSeconds > 0),
        "Crypto API Redis hot-path acceleration must define positive Redis timeout and auth-state revision TTL values.")
    .ValidateOnStart();

builder.Services.AddOptions<CryptoApiRateLimitingOptions>()
    .Bind(builder.Configuration.GetSection(CryptoApiRateLimitingOptions.SectionName))
    .Validate(
        static options => CryptoApiRateLimitingOptions.IsValid(options.Authentication),
        "Crypto API authentication rate limiting must define positive permit/window/segment values and a non-negative queue limit.")
    .Validate(
        static options => CryptoApiRateLimitingOptions.IsValid(options.Operations),
        "Crypto API operation rate limiting must define positive permit/window/segment values and a non-negative queue limit.")
    .ValidateOnStart();

builder.Services.AddOptions<CryptoApiSharedPersistenceOptions>()
    .Bind(builder.Configuration.GetSection(CryptoApiSharedPersistenceOptions.SectionName))
    .PostConfigure(static options =>
    {
        options.Provider = CryptoApiSharedPersistenceDefaults.NormalizeProvider(options.Provider);
        options.ConnectionString = options.ConnectionString?.Trim();
    })
    .Validate(
        static options => CryptoApiSharedPersistenceDefaults.IsSupportedProvider(options.Provider),
        $"Crypto API shared persistence supports '{CryptoApiSharedPersistenceDefaults.PostgresProvider}' only.")
    .ValidateOnStart();

builder.Services.AddOptions<ObservabilityOptions>()
    .Bind(builder.Configuration.GetSection(ObservabilityOptions.SectionName))
    .PostConfigure(ObservabilityOptions.Normalize)
    .Validate(static options => options.MetricsPath.StartsWith("/", StringComparison.Ordinal), "Observability metrics path must start with '/'.")
    .ValidateOnStart();

builder.Services.AddSingleton<CryptoApiMetrics>();
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics =>
    {
        metrics
            .AddPrometheusExporter()
            .AddMeter(
                "Microsoft.AspNetCore.Hosting",
                "Microsoft.AspNetCore.Server.Kestrel",
                "System.Net.Http",
                CryptoApiMetrics.MeterName);
    });

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(sp => new CryptoApiRequestPathCache(
    sp.GetRequiredService<TimeProvider>(),
    sp.GetRequiredService<IOptions<CryptoApiRequestPathCachingOptions>>().Value));
builder.Services.AddSingleton<ICryptoApiDistributedHotPathCache>(sp =>
{
    CryptoApiRequestPathCachingOptions options = sp.GetRequiredService<IOptions<CryptoApiRequestPathCachingOptions>>().Value;
    return options.Redis.Enabled && !string.IsNullOrWhiteSpace(options.Redis.Configuration)
        ? new RedisCryptoApiDistributedHotPathCache(
            sp.GetRequiredService<IOptions<CryptoApiRequestPathCachingOptions>>(),
            sp.GetRequiredService<TimeProvider>(),
            sp.GetRequiredService<ILogger<RedisCryptoApiDistributedHotPathCache>>())
        : new NoOpCryptoApiDistributedHotPathCache();
});
builder.Services.AddSingleton<CryptoApiRuntimeDescriptorProvider>();
builder.Services.AddSingleton<CryptoApiPkcs11Runtime>();
builder.Services.AddSingleton<ICryptoApiRouteRegistry, CryptoApiConfiguredRouteRegistry>();
builder.Services.AddSingleton<CryptoApiClientSecretGenerator>();
builder.Services.AddSingleton<CryptoApiClientSecretHasher>();
builder.Services.AddSingleton<CryptoApiClientManagementService>();
builder.Services.AddSingleton<CryptoApiClientAuthenticationService>();
builder.Services.AddSingleton<CryptoApiKeyAccessManagementService>();
builder.Services.AddSingleton<CryptoApiRouteDispatchService>();
builder.Services.AddSingleton<CryptoApiKeyOperationAuthorizationService>(sp => new CryptoApiKeyOperationAuthorizationService(
    sp.GetRequiredService<ICryptoApiSharedStateStore>(),
    sp.GetRequiredService<ICryptoApiDistributedHotPathCache>(),
    sp.GetRequiredService<TimeProvider>(),
    sp.GetRequiredService<CryptoApiClientSecretHasher>(),
    sp.GetRequiredService<CryptoApiRequestPathCache>(),
    sp.GetRequiredService<ICryptoApiRouteRegistry>()));
builder.Services.AddSingleton<ICryptoApiCustomerOperationService, CryptoApiPkcs11CustomerOperationService>();
builder.Services.AddCryptoApiSharedStateStore();

builder.Services.AddSingleton<IConfigureOptions<RateLimiterOptions>, ConfigureCryptoApiRateLimiterOptions>();
builder.Services.AddRateLimiter(_ => { });

builder.Services.AddHealthChecks()
    .AddCheck<CryptoApiModuleReadinessHealthCheck>("pkcs11-module", tags: ["ready"])
    .AddCheck<CryptoApiSharedStateHealthCheck>("shared-persistence", tags: ["ready"]);

WebApplication app = builder.Build();
CryptoApiHostOptions hostOptions = app.Services.GetRequiredService<IOptions<CryptoApiHostOptions>>().Value;
CryptoApiRuntimeOptions runtimeOptions = app.Services.GetRequiredService<IOptions<CryptoApiRuntimeOptions>>().Value;
CryptoApiSecurityOptions securityOptions = app.Services.GetRequiredService<IOptions<CryptoApiSecurityOptions>>().Value;
CryptoApiRateLimitingOptions rateLimitingOptions = app.Services.GetRequiredService<IOptions<CryptoApiRateLimitingOptions>>().Value;
CryptoApiSharedPersistenceOptions sharedPersistenceOptions = app.Services.GetRequiredService<IOptions<CryptoApiSharedPersistenceOptions>>().Value;
ObservabilityOptions observabilityOptions = app.Services.GetRequiredService<IOptions<ObservabilityOptions>>().Value;
CryptoApiMetrics cryptoApiMetrics = app.Services.GetRequiredService<CryptoApiMetrics>();

cryptoApiMetrics.RegisterRequestPathCache(app.Services.GetRequiredService<CryptoApiRequestPathCache>());
if (app.Services.GetRequiredService<ICryptoApiAuthoritativeSharedStateStore>() is ICryptoApiSharedStateMetricsSource sharedStateMetricsSource)
{
    cryptoApiMetrics.RegisterSharedStateSource(sharedStateMetricsSource);
}

cryptoApiMetrics.RegisterRuntimeSource(app.Services.GetRequiredService<CryptoApiPkcs11Runtime>());

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler();
    app.UseHsts();
}

if (!runtimeOptions.DisableHttpsRedirection)
{
    app.UseHttpsRedirection();
}

app.UseRateLimiter();

if (!string.IsNullOrWhiteSpace(sharedPersistenceOptions.ConnectionString) && sharedPersistenceOptions.AutoInitialize)
{
    ICryptoApiSharedStateStore sharedStateStore = app.Services.GetRequiredService<ICryptoApiSharedStateStore>();
    await sharedStateStore.InitializeAsync();
}

app.MapGet("/", (CryptoApiRuntimeDescriptorProvider descriptorProvider) =>
{
    CryptoApiRuntimeDescriptor descriptor = descriptorProvider.Describe();
    return TypedResults.Ok(new
    {
        descriptor.ServiceName,
        descriptor.InstanceId,
        descriptor.DeploymentModel,
        descriptor.ApiBasePath,
        descriptor.SharedPersistenceConfigured,
        descriptor.SharedPersistenceProvider,
        descriptor.SharedReadyAreas,
        Health = new
        {
            Live = CryptoApiHostDefaults.HealthLivePath,
            Ready = CryptoApiHostDefaults.HealthReadyPath
        },
        Metrics = observabilityOptions.EnablePrometheusScrapingEndpoint ? observabilityOptions.MetricsPath : null
    });
});
app.MapHealthChecks(CryptoApiHostDefaults.HealthLivePath, new HealthCheckOptions
{
    Predicate = static _ => false,
    ResponseWriter = CryptoApiHealthResponseWriter.WriteAsync
});
app.MapHealthChecks(CryptoApiHostDefaults.HealthReadyPath, new HealthCheckOptions
{
    Predicate = static registration => registration.Tags.Contains("ready", StringComparer.Ordinal),
    ResponseWriter = CryptoApiHealthResponseWriter.WriteAsync
});

if (observabilityOptions.EnablePrometheusScrapingEndpoint)
{
    app.MapPrometheusScrapingEndpoint(observabilityOptions.MetricsPath);
}

app.MapCryptoApiRoutes(hostOptions, securityOptions, rateLimitingOptions);

app.Run();

public partial class Program;
