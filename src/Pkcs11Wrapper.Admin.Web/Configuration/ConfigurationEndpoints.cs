using System.Text.Json;
using Pkcs11Wrapper.Admin.Application;
using Pkcs11Wrapper.Admin.Application.Services;

namespace Pkcs11Wrapper.Admin.Web.Configuration;

public static class ConfigurationEndpoints
{
    public static async Task<IResult> ExportAsync(HsmAdminService admin, CancellationToken cancellationToken)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(await admin.ExportConfigurationAsync(cancellationToken), AdminApplicationJsonContext.Default.AdminConfigurationExportBundle);
        string fileName = $"pkcs11wrapper-admin-config-{DateTime.UtcNow:yyyyMMdd-HHmmss}.json";
        return Results.File(payload, "application/json; charset=utf-8", fileName);
    }
}
