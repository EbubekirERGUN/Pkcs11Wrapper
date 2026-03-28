using System.Runtime.InteropServices;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper;

[StructLayout(LayoutKind.Sequential)]
public readonly struct Pkcs11MechanismType : IEquatable<Pkcs11MechanismType>
{
    private readonly CK_MECHANISM_TYPE _value;

    public Pkcs11MechanismType(nuint value) => _value = new CK_MECHANISM_TYPE(value);

    internal CK_MECHANISM_TYPE NativeValue => _value;

    public nuint Value => (nuint)_value;

    public bool Equals(Pkcs11MechanismType other) => _value == other._value;

    public override bool Equals(object? obj) => obj is Pkcs11MechanismType other && Equals(other);

    public override int GetHashCode() => _value.GetHashCode();

    public override string ToString() => $"0x{Value:x}";

    public static bool operator ==(Pkcs11MechanismType left, Pkcs11MechanismType right) => left.Equals(right);

    public static bool operator !=(Pkcs11MechanismType left, Pkcs11MechanismType right) => !left.Equals(right);
}

[Flags]
public enum Pkcs11MechanismFlags : ulong
{
    None = 0,
    Hardware = 0x00000001,
    Encrypt = 0x00000100,
    Decrypt = 0x00000200,
    Digest = 0x00000400,
    Sign = 0x00000800,
    SignRecover = 0x00001000,
    Verify = 0x00002000,
    VerifyRecover = 0x00004000,
    Generate = 0x00008000,
    GenerateKeyPair = 0x00010000,
    Wrap = 0x00020000,
    Unwrap = 0x00040000,
    Derive = 0x00080000,
    EcFp = 0x00100000,
    EcF2m = 0x00200000,
    EcParameters = 0x00400000,
    EcNamedCurve = 0x00800000,
    EcUncompress = 0x01000000,
    EcCompress = 0x02000000,
    Extension = 0x80000000,
}

public readonly record struct Pkcs11MechanismInfo(
    nuint MinKeySize,
    nuint MaxKeySize,
    Pkcs11MechanismFlags Flags)
{
    internal static Pkcs11MechanismInfo FromNative(CK_MECHANISM_INFO info) => new(
        (nuint)info.MinKeySize,
        (nuint)info.MaxKeySize,
        (Pkcs11MechanismFlags)(ulong)info.Flags.Value);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct Pkcs11ObjectHandle : IEquatable<Pkcs11ObjectHandle>
{
    private readonly CK_OBJECT_HANDLE _value;

    public Pkcs11ObjectHandle(nuint value) => _value = new CK_OBJECT_HANDLE(value);

    internal CK_OBJECT_HANDLE NativeValue => _value;

    public nuint Value => (nuint)_value;

    public bool Equals(Pkcs11ObjectHandle other) => _value == other._value;

    public override bool Equals(object? obj) => obj is Pkcs11ObjectHandle other && Equals(other);

    public override int GetHashCode() => _value.GetHashCode();

    public override string ToString() => Value.ToString();

    public static bool operator ==(Pkcs11ObjectHandle left, Pkcs11ObjectHandle right) => left.Equals(right);

    public static bool operator !=(Pkcs11ObjectHandle left, Pkcs11ObjectHandle right) => !left.Equals(right);
}

public readonly ref struct Pkcs11Mechanism
{
    private readonly ReadOnlySpan<byte> _parameter;

    public Pkcs11Mechanism(Pkcs11MechanismType type)
        : this(type, ReadOnlySpan<byte>.Empty)
    {
    }

    public Pkcs11Mechanism(Pkcs11MechanismType type, ReadOnlySpan<byte> parameter)
    {
        Type = type;
        _parameter = parameter;
    }

    public Pkcs11MechanismType Type { get; }

    public ReadOnlySpan<byte> Parameter => _parameter;
}

public static class Pkcs11MechanismTypes
{
    public static Pkcs11MechanismType RsaPkcsKeyPairGen => new(0x00000000u);
    public static Pkcs11MechanismType EcKeyPairGen => new(0x00001040u);
    public static Pkcs11MechanismType Ecdh1Derive => new(0x00001050u);
    public static Pkcs11MechanismType Sha1 => new(0x00000220u);
    public static Pkcs11MechanismType Sha224 => new(0x00000255u);
    public static Pkcs11MechanismType Sha256 => new(0x00000250u);
    public static Pkcs11MechanismType Sha384 => new(0x00000260u);
    public static Pkcs11MechanismType Sha512 => new(0x00000270u);
    public static Pkcs11MechanismType AesKeyGen => new(0x00001080u);
    public static Pkcs11MechanismType AesCbc => new(0x00001082u);
    public static Pkcs11MechanismType AesCbcPad => new(0x00001085u);
    public static Pkcs11MechanismType AesKeyWrapPad => new(0x0000210au);
    public static Pkcs11MechanismType Sha256RsaPkcs => new(0x00000040u);
}
