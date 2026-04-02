using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;
using Pkcs11Wrapper.Admin.Infrastructure;
using Pkcs11Wrapper.Admin.Web.Lab;
using Pkcs11Wrapper.Admin.Web.Components;
using Pkcs11Wrapper.Admin.Web.Configuration;
using Pkcs11Wrapper.Admin.Web.Security;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

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

AdminStorageOptions adminStorage = new()
{
    DataRoot = Path.Combine(builder.Environment.ContentRootPath, "App_Data")
};
Directory.CreateDirectory(adminStorage.DataRoot);

AdminSessionRegistryOptions sessionOptions = builder.Configuration.GetSection("AdminSessionRegistry").Get<AdminSessionRegistryOptions>() ?? new();
LocalAdminLoginThrottleOptions throttleOptions = builder.Configuration.GetSection("LocalAdminLoginThrottle").Get<LocalAdminLoginThrottleOptions>() ?? new();

builder.Services.AddSingleton(adminStorage);
builder.Services.AddSingleton<IOptions<AdminStorageOptions>>(Options.Create(adminStorage));
builder.Services.AddSingleton(sessionOptions);
builder.Services.AddSingleton(throttleOptions);
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(adminStorage.DataRoot, "keys")));
builder.Services.AddSingleton<IDeviceProfileStore, JsonDeviceProfileStore>();
builder.Services.AddSingleton<IAuditLogStore, JsonLineAuditLogStore>();
builder.Services.AddSingleton<IPkcs11TelemetryStore, JsonLinePkcs11TelemetryStore>();
builder.Services.AddSingleton<ProtectedPinStore>();
builder.Services.AddSingleton<Pkcs11LabTemplateStore>();
builder.Services.AddSingleton<IDeviceDependencyCleanupService, DeviceDependencyCleanupService>();
builder.Services.AddSingleton<DeviceProfileService>();
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

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute("/not-found");
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();
app.MapStaticAssets();
app.MapPost("/account/login", (Delegate)AccountEndpoints.LoginAsync);
app.MapPost("/account/logout", (Delegate)AccountEndpoints.LogoutAsync);
app.MapGet("/configuration/export", (Delegate)ConfigurationEndpoints.ExportAsync)
    .RequireAuthorization(AdminRoles.Admin);
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
