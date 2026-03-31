using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;
using Pkcs11Wrapper.Admin.Infrastructure;
using Pkcs11Wrapper.Admin.Web.Components;
using Pkcs11Wrapper.Admin.Web.Configuration;
using Pkcs11Wrapper.Admin.Web.Security;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

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

builder.Services.AddSingleton(adminStorage);
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(adminStorage.DataRoot, "keys")));
builder.Services.AddSingleton<IDeviceProfileStore, JsonDeviceProfileStore>();
builder.Services.AddSingleton<IAuditLogStore, JsonLineAuditLogStore>();
builder.Services.AddSingleton<ProtectedPinStore>();
builder.Services.AddSingleton<DeviceProfileService>();
builder.Services.AddSingleton<AdminSessionRegistry>();
builder.Services.AddSingleton<LocalAdminUserStore>();
builder.Services.AddScoped<IAdminActorContext, HttpContextAdminActorContext>();
builder.Services.AddScoped<IAdminAuthorizationService, HttpContextAdminAuthorizationService>();
builder.Services.AddScoped<AuditLogService>();
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
