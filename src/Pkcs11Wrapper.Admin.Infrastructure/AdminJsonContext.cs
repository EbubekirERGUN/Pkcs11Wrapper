using System.Text.Json.Serialization;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Infrastructure;

[JsonSerializable(typeof(List<HsmDeviceProfile>))]
[JsonSerializable(typeof(AdminAuditLogEntry))]
[JsonSerializable(typeof(List<ProtectedPinRecord>))]
internal sealed partial class AdminJsonContext : JsonSerializerContext
{
}
