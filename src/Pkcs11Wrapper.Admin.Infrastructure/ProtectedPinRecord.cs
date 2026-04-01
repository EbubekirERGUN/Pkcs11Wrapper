using System.Text.Json.Serialization;

namespace Pkcs11Wrapper.Admin.Infrastructure;

public sealed record ProtectedPinRecord(
    Guid DeviceId,
    [property: JsonConverter(typeof(NUIntJsonConverter))] nuint SlotId,
    string Purpose,
    string Ciphertext,
    DateTimeOffset UpdatedUtc,
    string MaskedValue);
