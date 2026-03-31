using System.Text.Json.Serialization;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Infrastructure;

[JsonSerializable(typeof(List<HsmDeviceProfile>))]
[JsonSerializable(typeof(AdminAuditLogEntry))]
internal sealed partial class AdminJsonContext : JsonSerializerContext
{
}
