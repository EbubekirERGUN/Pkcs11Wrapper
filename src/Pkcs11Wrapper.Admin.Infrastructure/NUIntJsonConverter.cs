using System.Text.Json;
using System.Text.Json.Serialization;

namespace Pkcs11Wrapper.Admin.Infrastructure;

public sealed class NUIntJsonConverter : JsonConverter<nuint>
{
    public override nuint Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => checked((nuint)reader.GetUInt64());

    public override void Write(Utf8JsonWriter writer, nuint value, JsonSerializerOptions options)
        => writer.WriteNumberValue((ulong)value);
}
