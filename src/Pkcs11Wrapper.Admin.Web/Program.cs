using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Services;
using Pkcs11Wrapper.Admin.Infrastructure;
using Pkcs11Wrapper.Admin.Web.Components;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

AdminStorageOptions adminStorage = new()
{
    DataRoot = Path.Combine(builder.Environment.ContentRootPath, "App_Data")
};
Directory.CreateDirectory(adminStorage.DataRoot);

builder.Services.AddSingleton(adminStorage);
builder.Services.AddSingleton<IDeviceProfileStore, JsonDeviceProfileStore>();
builder.Services.AddSingleton<IAuditLogStore, JsonLineAuditLogStore>();
builder.Services.AddSingleton<DeviceProfileService>();
builder.Services.AddSingleton<AuditLogService>();
builder.Services.AddSingleton<AdminSessionRegistry>();
builder.Services.AddSingleton<HsmAdminService>();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute("/not-found");
app.UseHttpsRedirection();
app.UseAntiforgery();
app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
