using System.Text.Json.Serialization;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Web.Lab;

namespace Pkcs11Wrapper.Admin.Web.Security;

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(AdminWebUserRecord))]
[JsonSerializable(typeof(AdminWebUserRecord[]))]
[JsonSerializable(typeof(Pkcs11LabRequest))]
[JsonSerializable(typeof(Pkcs11LabSavedTemplate))]
[JsonSerializable(typeof(Pkcs11LabSavedTemplate[]))]
public sealed partial class AdminWebJsonContext : JsonSerializerContext
{
}
