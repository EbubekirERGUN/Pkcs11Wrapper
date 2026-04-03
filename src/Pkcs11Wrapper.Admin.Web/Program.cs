using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;
using Pkcs11Wrapper.Admin.Infrastructure;
using Pkcs11Wrapper.Admin.Web.Lab;
using Pkcs11Wrapper.Admin.Web.Components;
using Pkcs11Wrapper.Admin.Web.Configuration;
using Pkcs11Wrapper.Admin.Web.Health;
using Pkcs11Wrapper.Admin.Web.Security;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.SharedState;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

if (await AdminContainerHealthProbe.TryExecuteAsync(args))
{
    return;
}

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseStaticWebAssets();

builder.Services.AddHttpContextAccessor();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.AccessDeniedPath = "/forbidden";
        options.SlidingExpiration = true;
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy(AdminRoles.Viewer, policy => policy.RequireRole(AdminRoles.Viewer, AdminRoles.Operator, AdminRoles.Admin))
    .AddPolicy(AdminRoles.Operator, policy => policy.RequireRole(AdminRoles.Operator, AdminRoles.Admin))
    .AddPolicy(AdminRoles.Admin, policy => policy.RequireRole(AdminRoles.Admin));

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();
builder.Services.AddHealthChecks()
    .AddCheck<AdminStorageHealthCheck>("admin-storage", tags: ["ready"]);
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
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(AdminHostDefaults.GetKeysRoot(adminStorage.DataRoot)));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<CryptoApiClientSecretGenerator>();
builder.Services.AddSingleton<CryptoApiClientSecretHasher>();
builder.Services.AddSingleton<ICryptoApiSharedStateStore, SqliteCryptoApiSharedStateStore>();
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

await app.Services.GetRequiredService<LocalAdminUserStore>().EnsureSeedDataAsync();
await app.Services.GetRequiredService<AdminBootstrapDeviceSeeder>().EnsureSeedDataAsync();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute("/not-found");
if (!runtimeOptions.DisableHttpsRedirection)
{
    app.UseHttpsRedirection();
}

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();
app.MapHealthChecks(AdminHostDefaults.HealthLivePath, new HealthCheckOptions
{
    Predicate = static _ => false,
    ResponseWriter = AdminHealthResponseWriter.WriteAsync
});
app.MapHealthChecks(AdminHostDefaults.HealthReadyPath, new HealthCheckOptions
{
    Predicate = static registration => registration.Tags.Contains("ready", StringComparer.Ordinal),
    ResponseWriter = AdminHealthResponseWriter.WriteAsync
});
app.MapStaticAssets();
app.MapPost("/account/login", (Delegate)AccountEndpoints.LoginAsync);
app.MapPost("/account/logout", (Delegate)AccountEndpoints.LogoutAsync);
app.MapGet("/configuration/export", (Delegate)ConfigurationEndpoints.ExportAsync)
    .RequireAuthorization(AdminRoles.Admin);
app.MapGet("/telemetry/export", (Delegate)TelemetryEndpoints.ExportAsync)
    .RequireAuthorization(AdminRoles.Viewer);
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
