using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.Endpoints;
using Pkcs11Wrapper.CryptoApi.Health;
using Pkcs11Wrapper.CryptoApi.Runtime;
using Pkcs11Wrapper.CryptoApi.SharedState;

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
    });

builder.Services.AddOptions<CryptoApiSharedPersistenceOptions>()
    .Bind(builder.Configuration.GetSection(CryptoApiSharedPersistenceOptions.SectionName))
    .PostConfigure(static options =>
    {
        options.Provider = CryptoApiSharedPersistenceDefaults.NormalizeProvider(options.Provider);
        options.ConnectionString = options.ConnectionString?.Trim();
    })
    .Validate(
        static options => string.Equals(options.Provider, CryptoApiSharedPersistenceDefaults.SqliteProvider, StringComparison.OrdinalIgnoreCase),
        $"Crypto API shared persistence currently supports only '{CryptoApiSharedPersistenceDefaults.SqliteProvider}'.")
    .ValidateOnStart();

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<CryptoApiRuntimeDescriptorProvider>();
builder.Services.AddSingleton<CryptoApiClientSecretGenerator>();
builder.Services.AddSingleton<CryptoApiClientSecretHasher>();
builder.Services.AddSingleton<CryptoApiClientManagementService>();
builder.Services.AddSingleton<CryptoApiClientAuthenticationService>();
builder.Services.AddSingleton<CryptoApiKeyAccessManagementService>();
builder.Services.AddSingleton<CryptoApiKeyOperationAuthorizationService>();
builder.Services.AddSingleton<ICryptoApiSharedStateStore, SqliteCryptoApiSharedStateStore>();
builder.Services.AddHealthChecks()
    .AddCheck<CryptoApiModuleReadinessHealthCheck>("pkcs11-module", tags: ["ready"])
    .AddCheck<CryptoApiSharedStateHealthCheck>("shared-persistence", tags: ["ready"]);

WebApplication app = builder.Build();
CryptoApiHostOptions hostOptions = app.Services.GetRequiredService<IOptions<CryptoApiHostOptions>>().Value;
CryptoApiRuntimeOptions runtimeOptions = app.Services.GetRequiredService<IOptions<CryptoApiRuntimeOptions>>().Value;
CryptoApiSharedPersistenceOptions sharedPersistenceOptions = app.Services.GetRequiredService<IOptions<CryptoApiSharedPersistenceOptions>>().Value;

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler();
    app.UseHsts();
}

if (!runtimeOptions.DisableHttpsRedirection)
{
    app.UseHttpsRedirection();
}

if (!string.IsNullOrWhiteSpace(sharedPersistenceOptions.ConnectionString) && sharedPersistenceOptions.AutoInitialize)
{
    ICryptoApiSharedStateStore sharedStateStore = app.Services.GetRequiredService<ICryptoApiSharedStateStore>();
    await sharedStateStore.InitializeAsync();
}

app.MapGet("/", static (CryptoApiRuntimeDescriptorProvider descriptorProvider) =>
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
        }
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
app.MapCryptoApiRoutes(hostOptions);

app.Run();

public partial class Program;
