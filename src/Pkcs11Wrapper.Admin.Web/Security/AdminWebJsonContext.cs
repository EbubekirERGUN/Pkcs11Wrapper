using System.Text.Json.Serialization;

namespace Pkcs11Wrapper.Admin.Web.Security;

[JsonSerializable(typeof(List<AdminWebUserRecord>))]
internal sealed partial class AdminWebJsonContext : JsonSerializerContext
{
}
