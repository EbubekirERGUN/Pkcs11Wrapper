using System.Text.Json.Serialization;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application;

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(AdminConfigurationExportBundle))]
[JsonSerializable(typeof(AdminPkcs11TelemetryExportBundle))]
public sealed partial class AdminApplicationJsonContext : JsonSerializerContext
{
}
