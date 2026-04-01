using System.Runtime.InteropServices;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper;

[StructLayout(LayoutKind.Sequential)]
public readonly struct Pkcs11AttributeType : IEquatable<Pkcs11AttributeType>
{
    private readonly CK_ATTRIBUTE_TYPE _value;

    public Pkcs11AttributeType(nuint value) => _value = new CK_ATTRIBUTE_TYPE(value);

    internal CK_ATTRIBUTE_TYPE NativeValue => _value;

    public nuint Value => (nuint)_value;

    public bool Equals(Pkcs11AttributeType other) => _value == other._value;

    public override bool Equals(object? obj) => obj is Pkcs11AttributeType other && Equals(other);

    public override int GetHashCode() => _value.GetHashCode();

    public override string ToString() => $"0x{Value:x}";

    public static bool operator ==(Pkcs11AttributeType left, Pkcs11AttributeType right) => left.Equals(right);

    public static bool operator !=(Pkcs11AttributeType left, Pkcs11AttributeType right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct Pkcs11ObjectClass : IEquatable<Pkcs11ObjectClass>
{
    private readonly CK_OBJECT_CLASS _value;

    public Pkcs11ObjectClass(nuint value) => _value = new CK_OBJECT_CLASS(value);

    internal CK_OBJECT_CLASS NativeValue => _value;

    public nuint Value => (nuint)_value;

    public bool Equals(Pkcs11ObjectClass other) => _value == other._value;

    public override bool Equals(object? obj) => obj is Pkcs11ObjectClass other && Equals(other);

    public override int GetHashCode() => _value.GetHashCode();

    public override string ToString() => Value.ToString();

    public static bool operator ==(Pkcs11ObjectClass left, Pkcs11ObjectClass right) => left.Equals(right);

    public static bool operator !=(Pkcs11ObjectClass left, Pkcs11ObjectClass right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct Pkcs11KeyType : IEquatable<Pkcs11KeyType>
{
    private readonly CK_KEY_TYPE _value;

    public Pkcs11KeyType(nuint value) => _value = new CK_KEY_TYPE(value);

    internal CK_KEY_TYPE NativeValue => _value;

    public nuint Value => (nuint)_value;

    public bool Equals(Pkcs11KeyType other) => _value == other._value;

    public override bool Equals(object? obj) => obj is Pkcs11KeyType other && Equals(other);

    public override int GetHashCode() => _value.GetHashCode();

    public override string ToString() => Value.ToString();

    public static bool operator ==(Pkcs11KeyType left, Pkcs11KeyType right) => left.Equals(right);

    public static bool operator !=(Pkcs11KeyType left, Pkcs11KeyType right) => !left.Equals(right);
}

public static class Pkcs11AttributeTypes
{
    public static Pkcs11AttributeType Class => new(0x00000000u);
    public static Pkcs11AttributeType Token => new(0x00000001u);
    public static Pkcs11AttributeType Private => new(0x00000002u);
    public static Pkcs11AttributeType Label => new(0x00000003u);
    public static Pkcs11AttributeType Application => new(0x00000010u);
    public static Pkcs11AttributeType Value => new(0x00000011u);
    public static Pkcs11AttributeType CertificateType => new(0x00000080u);
    public static Pkcs11AttributeType KeyType => new(0x00000100u);
    public static Pkcs11AttributeType Sensitive => new(0x00000103u);
    public static Pkcs11AttributeType Id => new(0x00000102u);
    public static Pkcs11AttributeType Encrypt => new(0x00000104u);
    public static Pkcs11AttributeType Decrypt => new(0x00000105u);
    public static Pkcs11AttributeType Wrap => new(0x00000106u);
    public static Pkcs11AttributeType Unwrap => new(0x00000107u);
    public static Pkcs11AttributeType Sign => new(0x00000108u);
    public static Pkcs11AttributeType Verify => new(0x0000010au);
    public static Pkcs11AttributeType Derive => new(0x0000010cu);
    public static Pkcs11AttributeType ModulusBits => new(0x00000121u);
    public static Pkcs11AttributeType PublicExponent => new(0x00000122u);
    public static Pkcs11AttributeType ValueLen => new(0x00000161u);
    public static Pkcs11AttributeType Extractable => new(0x00000162u);
    public static Pkcs11AttributeType Modifiable => new(0x00000170u);
    public static Pkcs11AttributeType EcParams => new(0x00000180u);
    public static Pkcs11AttributeType EcPoint => new(0x00000181u);
}

public static class Pkcs11ObjectClasses
{
    public static Pkcs11ObjectClass Data => new(0x00000000u);
    public static Pkcs11ObjectClass Certificate => new(0x00000001u);
    public static Pkcs11ObjectClass PublicKey => new(0x00000002u);
    public static Pkcs11ObjectClass PrivateKey => new(0x00000003u);
    public static Pkcs11ObjectClass SecretKey => new(0x00000004u);
}

public static class Pkcs11KeyTypes
{
    public static Pkcs11KeyType Rsa => new(0x00000000u);
    public static Pkcs11KeyType Dsa => new(0x00000001u);
    public static Pkcs11KeyType Dh => new(0x00000002u);
    public static Pkcs11KeyType Ec => new(0x00000003u);
    public static Pkcs11KeyType Aes => new(0x0000001fu);
    public static Pkcs11KeyType GenericSecret => new(0x00000010u);
}

public enum Pkcs11AttributeReadStatus
{
    Success = 0,
    BufferTooSmall = 1,
    UnavailableInformation = 2,
    Sensitive = 3,
    TypeInvalid = 4,
}

public readonly record struct Pkcs11AttributeReadResult(Pkcs11AttributeReadStatus Status, nuint Length)
{
    public bool IsSuccess => Status == Pkcs11AttributeReadStatus.Success;

    public bool IsReadable => Status == Pkcs11AttributeReadStatus.Success && Length != nuint.MaxValue;
}

public readonly record struct Pkcs11AttributeValue(Pkcs11AttributeType Type, Pkcs11AttributeReadResult Result, byte[]? Value)
{
    public bool IsReadable => Result.IsReadable && Value is not null;
}

public readonly struct Pkcs11ObjectAttribute
{
    private readonly ReadOnlyMemory<byte> _bytes;
    private readonly nuint _scalar;
    private readonly byte _scalarLength;

    private Pkcs11ObjectAttribute(Pkcs11AttributeType type, ReadOnlyMemory<byte> bytes, nuint scalar, byte scalarLength)
    {
        Type = type;
        _bytes = bytes;
        _scalar = scalar;
        _scalarLength = scalarLength;
    }

    public Pkcs11AttributeType Type { get; }

    public ReadOnlySpan<byte> Value => _scalarLength == 0
        ? _bytes.Span
        : MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(in _scalar, 1))[.._scalarLength];

    public static Pkcs11ObjectAttribute Bytes(Pkcs11AttributeType type, ReadOnlyMemory<byte> value)
        => new(type, value, 0, 0);

    public static Pkcs11ObjectAttribute Boolean(Pkcs11AttributeType type, bool value)
        => new(type, default, value ? 1u : 0u, sizeof(byte));

    public static Pkcs11ObjectAttribute Nuint(Pkcs11AttributeType type, nuint value)
        => new(type, default, value, (byte)IntPtr.Size);

    public static Pkcs11ObjectAttribute ObjectClass(Pkcs11AttributeType type, Pkcs11ObjectClass value)
        => Nuint(type, value.Value);

    public static Pkcs11ObjectAttribute KeyType(Pkcs11AttributeType type, Pkcs11KeyType value)
        => Nuint(type, value.Value);
}

public readonly record struct Pkcs11GeneratedKeyPair(Pkcs11ObjectHandle PublicKeyHandle, Pkcs11ObjectHandle PrivateKeyHandle);

public readonly ref struct Pkcs11ObjectSearchParameters
{
    private readonly ReadOnlySpan<byte> _label;
    private readonly ReadOnlySpan<byte> _id;

    public Pkcs11ObjectSearchParameters(
        ReadOnlySpan<byte> label = default,
        ReadOnlySpan<byte> id = default,
        Pkcs11ObjectClass? objectClass = null,
        Pkcs11KeyType? keyType = null,
        bool? requireEncrypt = null,
        bool? requireDecrypt = null,
        bool? requireSign = null,
        bool? requireVerify = null,
        bool? requireWrap = null,
        bool? requireUnwrap = null)
    {
        _label = label;
        _id = id;
        ObjectClass = objectClass;
        KeyType = keyType;
        RequireEncrypt = requireEncrypt;
        RequireDecrypt = requireDecrypt;
        RequireSign = requireSign;
        RequireVerify = requireVerify;
        RequireWrap = requireWrap;
        RequireUnwrap = requireUnwrap;
    }

    public ReadOnlySpan<byte> Label => _label;

    public ReadOnlySpan<byte> Id => _id;

    public Pkcs11ObjectClass? ObjectClass { get; }

    public Pkcs11KeyType? KeyType { get; }

    public bool? RequireEncrypt { get; }

    public bool? RequireDecrypt { get; }

    public bool? RequireSign { get; }

    public bool? RequireVerify { get; }

    public bool? RequireWrap { get; }

    public bool? RequireUnwrap { get; }

    public static Pkcs11ObjectSearchParametersBuilder CreateBuilder() => new();
}

public ref struct Pkcs11ObjectSearchParametersBuilder
{
    private ReadOnlySpan<byte> _label;
    private ReadOnlySpan<byte> _id;
    private Pkcs11ObjectClass? _objectClass;
    private Pkcs11KeyType? _keyType;
    private bool? _requireEncrypt;
    private bool? _requireDecrypt;
    private bool? _requireSign;
    private bool? _requireVerify;
    private bool? _requireWrap;
    private bool? _requireUnwrap;

    public Pkcs11ObjectSearchParametersBuilder WithLabel(ReadOnlySpan<byte> label)
    {
        _label = label;
        return this;
    }

    public Pkcs11ObjectSearchParametersBuilder WithId(ReadOnlySpan<byte> id)
    {
        _id = id;
        return this;
    }

    public Pkcs11ObjectSearchParametersBuilder WithObjectClass(Pkcs11ObjectClass objectClass)
    {
        _objectClass = objectClass;
        return this;
    }

    public Pkcs11ObjectSearchParametersBuilder WithKeyType(Pkcs11KeyType keyType)
    {
        _keyType = keyType;
        return this;
    }

    public Pkcs11ObjectSearchParametersBuilder RequireEncrypt(bool required = true)
    {
        _requireEncrypt = required;
        return this;
    }

    public Pkcs11ObjectSearchParametersBuilder RequireDecrypt(bool required = true)
    {
        _requireDecrypt = required;
        return this;
    }

    public Pkcs11ObjectSearchParametersBuilder RequireSign(bool required = true)
    {
        _requireSign = required;
        return this;
    }

    public Pkcs11ObjectSearchParametersBuilder RequireVerify(bool required = true)
    {
        _requireVerify = required;
        return this;
    }

    public Pkcs11ObjectSearchParametersBuilder RequireWrap(bool required = true)
    {
        _requireWrap = required;
        return this;
    }

    public Pkcs11ObjectSearchParametersBuilder RequireUnwrap(bool required = true)
    {
        _requireUnwrap = required;
        return this;
    }

    public Pkcs11ObjectSearchParameters Build()
        => new(
            label: _label,
            id: _id,
            objectClass: _objectClass,
            keyType: _keyType,
            requireEncrypt: _requireEncrypt,
            requireDecrypt: _requireDecrypt,
            requireSign: _requireSign,
            requireVerify: _requireVerify,
            requireWrap: _requireWrap,
            requireUnwrap: _requireUnwrap);
}
