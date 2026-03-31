using System.Text.Json.Serialization;

namespace Pkcs11Wrapper.Admin.Web.Security;

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(AdminWebUserRecord))]
[JsonSerializable(typeof(AdminWebUserRecord[]))]
public sealed partial class AdminWebJsonContext : JsonSerializerContext
{
}
