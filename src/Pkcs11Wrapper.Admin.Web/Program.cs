using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Observability;
using Pkcs11Wrapper.Admin.Application.Services;
using Pkcs11Wrapper.Admin.Infrastructure;
using Pkcs11Wrapper.Admin.Web.Components;
using Pkcs11Wrapper.Admin.Web.Configuration;
using Pkcs11Wrapper.Admin.Web.Health;
using Pkcs11Wrapper.Admin.Web.Lab;
using Pkcs11Wrapper.Admin.Web.OpenApi;
using Pkcs11Wrapper.Admin.Web.Security;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.SharedState;
using Pkcs11Wrapper.Observability;
using OpenTelemetry.Metrics;

if (await AdminContainerHealthProbe.TryExecuteAsync(args))
{
    return;
}

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseStaticWebAssets();

builder.Services.AddHttpContextAccessor();
builder.Services.AddAdminOpenApi();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/forbidden";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.SlidingExpiration = true;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy(AdminRoles.Viewer, policy => policy.RequireRole(AdminRoles.Viewer, AdminRoles.Operator, AdminRoles.Admin))
    .AddPolicy(AdminRoles.Operator, policy => policy.RequireRole(AdminRoles.Operator, AdminRoles.Admin))
    .AddPolicy(AdminRoles.Admin, policy => policy.RequireRole(AdminRoles.Admin));

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
builder.Services.AddHealthChecks()
    .AddCheck<AdminStorageHealthCheck>("admin-storage", tags: ["ready"]);
builder.Services.AddOptions<ObservabilityOptions>()
    .Bind(builder.Configuration.GetSection(ObservabilityOptions.SectionName))
    .PostConfigure(ObservabilityOptions.Normalize)
    .Validate(static options => options.MetricsPath.StartsWith("/", StringComparison.Ordinal), "Observability metrics path must start with '/'.")
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
builder.Services.AddOptions<AdminCryptoApiRouteRuntimeOptions>()
    .Bind(builder.Configuration.GetSection(AdminCryptoApiRouteRuntimeOptions.SectionName));

AdminStorageOptions adminStorage = builder.Configuration.GetSection("AdminStorage").Get<AdminStorageOptions>() ?? new();
adminStorage.DataRoot = AdminHostDefaults.ResolveStorageRoot(adminStorage.DataRoot, builder.Environment.ContentRootPath);
Directory.CreateDirectory(adminStorage.DataRoot);
Directory.CreateDirectory(AdminHostDefaults.GetKeysRoot(adminStorage.DataRoot));
Directory.CreateDirectory(AdminHostDefaults.GetHomeRoot(adminStorage.DataRoot));
Directory.CreateDirectory(AdminHostDefaults.GetTempRoot(adminStorage.DataRoot));

AdminSessionRegistryOptions sessionOptions = builder.Configuration.GetSection("AdminSessionRegistry").Get<AdminSessionRegistryOptions>() ?? new();
LocalAdminLoginThrottleOptions throttleOptions = builder.Configuration.GetSection("LocalAdminLoginThrottle").Get<LocalAdminLoginThrottleOptions>() ?? new();
LocalAdminBootstrapOptions bootstrapOptions = builder.Configuration.GetSection("LocalAdminBootstrap").Get<LocalAdminBootstrapOptions>() ?? new();
AdminBootstrapDeviceOptions bootstrapDeviceOptions = builder.Configuration.GetSection("AdminBootstrapDevice").Get<AdminBootstrapDeviceOptions>() ?? new();
AdminRuntimeOptions runtimeOptions = builder.Configuration.GetSection("AdminRuntime").Get<AdminRuntimeOptions>() ?? new();
AdminPkcs11TelemetryOptions telemetryOptions = builder.Configuration.GetSection("AdminTelemetry").Get<AdminPkcs11TelemetryOptions>() ?? new();

builder.Services.AddSingleton(adminStorage);
builder.Services.AddSingleton<IOptions<AdminStorageOptions>>(Options.Create(adminStorage));
builder.Services.AddSingleton(sessionOptions);
builder.Services.AddSingleton(throttleOptions);
builder.Services.AddSingleton(bootstrapOptions);
builder.Services.AddSingleton<IOptions<LocalAdminBootstrapOptions>>(Options.Create(bootstrapOptions));
builder.Services.AddSingleton(bootstrapDeviceOptions);
builder.Services.AddSingleton<IOptions<AdminBootstrapDeviceOptions>>(Options.Create(bootstrapDeviceOptions));
builder.Services.AddSingleton(runtimeOptions);
builder.Services.AddSingleton<IOptions<AdminRuntimeOptions>>(Options.Create(runtimeOptions));
builder.Services.AddSingleton(telemetryOptions);
builder.Services.AddSingleton<IOptions<AdminPkcs11TelemetryOptions>>(Options.Create(telemetryOptions));
builder.Services.AddSingleton<AdminMetrics>();
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics =>
    {
        metrics
            .AddPrometheusExporter()
            .AddMeter(
                "Microsoft.AspNetCore.Hosting",
                "Microsoft.AspNetCore.Server.Kestrel",
                AdminMetrics.MeterName);
    });
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(AdminHostDefaults.GetKeysRoot(adminStorage.DataRoot)));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<CryptoApiClientSecretGenerator>();
builder.Services.AddSingleton<CryptoApiClientSecretHasher>();
builder.Services.AddCryptoApiSharedStateStore();
builder.Services.AddScoped<CryptoApiClientManagementService>();
builder.Services.AddScoped<CryptoApiClientAuthenticationService>();
builder.Services.AddScoped<CryptoApiKeyAccessManagementService>();
builder.Services.AddSingleton<IDeviceProfileStore, JsonDeviceProfileStore>();
builder.Services.AddSingleton<IAuditLogStore, JsonLineAuditLogStore>();
builder.Services.AddSingleton<IPkcs11TelemetryStore, JsonLinePkcs11TelemetryStore>();
builder.Services.AddSingleton<ProtectedPinStore>();
builder.Services.AddSingleton<Pkcs11LabTemplateStore>();
builder.Services.AddSingleton<IDeviceDependencyCleanupService, DeviceDependencyCleanupService>();
builder.Services.AddSingleton<DeviceProfileService>();
builder.Services.AddSingleton<AdminPkcs11Runtime>();
builder.Services.AddSingleton<AdminBootstrapDeviceSeeder>();
builder.Services.AddSingleton(sp => new AdminSessionRegistry(sp.GetRequiredService<AdminSessionRegistryOptions>()));
builder.Services.AddSingleton<LocalAdminUserStore>();
builder.Services.AddSingleton(sp => new LocalAdminLoginThrottleService(sp.GetRequiredService<LocalAdminLoginThrottleOptions>()));
builder.Services.AddScoped<IAdminActorContext, HttpContextAdminActorContext>();
builder.Services.AddScoped<IAdminAuthorizationService, HttpContextAdminAuthorizationService>();
builder.Services.AddScoped<AuditLogService>();
builder.Services.AddScoped<Pkcs11TelemetryService>();
builder.Services.AddScoped<LocalAdminSecurityService>();
builder.Services.AddScoped<LocalAdminLoginService>();
builder.Services.AddScoped<HsmAdminService>();

var app = builder.Build();
ObservabilityOptions observabilityOptions = app.Services.GetRequiredService<IOptions<ObservabilityOptions>>().Value;
AdminMetrics adminMetrics = app.Services.GetRequiredService<AdminMetrics>();
adminMetrics.RegisterSessionRegistry(app.Services.GetRequiredService<AdminSessionRegistry>());

await app.Services.GetRequiredService<LocalAdminUserStore>().EnsureSeedDataAsync();
await app.Services.GetRequiredService<AdminBootstrapDeviceSeeder>().EnsureSeedDataAsync();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}
else
{
    app.UseAdminOpenApi();
}

app.UseStatusCodePagesWithReExecute("/not-found");
if (!runtimeOptions.DisableHttpsRedirection)
{
    app.UseHttpsRedirection();
}

app.UseAdminSecurityResponseHeaders();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();
app.MapGet(AdminHostDefaults.HealthLivePath, (Delegate)AdminHealthEndpoints.LiveAsync)
    .AllowAnonymous()
    .WithName("AdminHealthLive")
    .WithTags("Health")
    .WithSummary("Gets the admin host liveness status.")
    .WithDescription("Returns a lightweight liveness payload for process availability checks.")
    .Produces<AdminHealthResponse>(StatusCodes.Status200OK, contentType: "application/json")
    .Produces<AdminHealthResponse>(StatusCodes.Status503ServiceUnavailable, contentType: "application/json");
app.MapGet(AdminHostDefaults.HealthReadyPath, (Delegate)AdminHealthEndpoints.ReadyAsync)
    .AllowAnonymous()
    .WithName("AdminHealthReady")
    .WithTags("Health")
    .WithSummary("Gets the admin host readiness status.")
    .WithDescription("Returns the storage-focused readiness payload used by container and orchestrator probes.")
    .Produces<AdminHealthResponse>(StatusCodes.Status200OK, contentType: "application/json")
    .Produces<AdminHealthResponse>(StatusCodes.Status503ServiceUnavailable, contentType: "application/json");

if (observabilityOptions.EnablePrometheusScrapingEndpoint)
{
    app.MapPrometheusScrapingEndpoint(observabilityOptions.MetricsPath);
}

app.MapStaticAssets();
app.MapPost("/account/login", (Delegate)AccountEndpoints.LoginAsync)
    .AllowAnonymous()
    .WithName("AdminAccountLogin")
    .WithTags("Authentication")
    .WithSummary("Signs in a local admin user.")
    .WithDescription("Accepts the admin login form as application/x-www-form-urlencoded, validates the antiforgery token, and issues the local admin cookie session before redirecting back to the requested page.")
    .Accepts<AdminLoginRequest>("application/x-www-form-urlencoded")
    .Produces(StatusCodes.Status302Found)
    .ProducesProblem(StatusCodes.Status400BadRequest);
app.MapPost("/account/logout", (Delegate)AccountEndpoints.LogoutAsync)
    .AllowAnonymous()
    .WithName("AdminAccountLogout")
    .WithTags("Authentication")
    .WithSummary("Signs out the current local admin session.")
    .WithDescription("Accepts an antiforgery-protected form post, clears the local admin cookie session, writes a logout audit entry when a user was signed in, and redirects to /login.")
    .Accepts<AdminLogoutRequest>("application/x-www-form-urlencoded")
    .Produces(StatusCodes.Status302Found)
    .ProducesProblem(StatusCodes.Status400BadRequest);
app.MapGet("/configuration/export", (Delegate)ConfigurationEndpoints.ExportAsync)
    .RequireAuthorization(AdminRoles.Admin)
    .WithName("AdminConfigurationExport")
    .WithTags("Configuration")
    .WithSummary("Downloads the admin configuration export bundle.")
    .WithDescription("Requires an authenticated admin cookie session and returns the current admin configuration export as a JSON attachment. The documented schema describes the JSON payload even though the response is served with download headers.")
    .Produces<AdminConfigurationExportBundle>(StatusCodes.Status200OK, contentType: "application/json")
    .Produces(StatusCodes.Status302Found);
app.MapGet("/telemetry/export", (Delegate)TelemetryEndpoints.ExportAsync)
    .RequireAuthorization(AdminRoles.Viewer)
    .WithName("AdminTelemetryExport")
    .WithTags("Telemetry")
    .WithSummary("Downloads a filtered PKCS#11 telemetry export bundle.")
    .WithDescription("Requires an authenticated viewer/operator/admin cookie session, applies the supplied query filters, and returns the redacted PKCS#11 telemetry export bundle as a JSON attachment. The documented schema describes the JSON payload even though the response is served with download headers.")
    .Produces<AdminPkcs11TelemetryExportBundle>(StatusCodes.Status200OK, contentType: "application/json")
    .Produces(StatusCodes.Status302Found);
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();

public partial class Program;
