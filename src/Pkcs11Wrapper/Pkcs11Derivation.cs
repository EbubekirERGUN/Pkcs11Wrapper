using System.Runtime.InteropServices;

namespace Pkcs11Wrapper;

[StructLayout(LayoutKind.Sequential)]
public readonly struct Pkcs11EcKdfType : IEquatable<Pkcs11EcKdfType>
{
    private readonly nuint _value;

    public Pkcs11EcKdfType(nuint value) => _value = value;

    public nuint Value => _value;

    public bool Equals(Pkcs11EcKdfType other) => _value == other._value;

    public override bool Equals(object? obj) => obj is Pkcs11EcKdfType other && Equals(other);

    public override int GetHashCode() => _value.GetHashCode();

    public override string ToString() => $"0x{_value:x}";

    public static bool operator ==(Pkcs11EcKdfType left, Pkcs11EcKdfType right) => left.Equals(right);

    public static bool operator !=(Pkcs11EcKdfType left, Pkcs11EcKdfType right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct Pkcs11RsaMgfType : IEquatable<Pkcs11RsaMgfType>
{
    private readonly nuint _value;

    public Pkcs11RsaMgfType(nuint value) => _value = value;

    public nuint Value => _value;

    public bool Equals(Pkcs11RsaMgfType other) => _value == other._value;

    public override bool Equals(object? obj) => obj is Pkcs11RsaMgfType other && Equals(other);

    public override int GetHashCode() => _value.GetHashCode();

    public override string ToString() => $"0x{_value:x}";

    public static bool operator ==(Pkcs11RsaMgfType left, Pkcs11RsaMgfType right) => left.Equals(right);

    public static bool operator !=(Pkcs11RsaMgfType left, Pkcs11RsaMgfType right) => !left.Equals(right);
}

public static class Pkcs11RsaMgfTypes
{
    public static Pkcs11RsaMgfType Mgf1Sha1 => new(0x00000001u);
    public static Pkcs11RsaMgfType Mgf1Sha224 => new(0x00000005u);
    public static Pkcs11RsaMgfType Mgf1Sha256 => new(0x00000002u);
    public static Pkcs11RsaMgfType Mgf1Sha384 => new(0x00000003u);
    public static Pkcs11RsaMgfType Mgf1Sha512 => new(0x00000004u);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct Pkcs11RsaOaepSourceType : IEquatable<Pkcs11RsaOaepSourceType>
{
    private readonly nuint _value;

    public Pkcs11RsaOaepSourceType(nuint value) => _value = value;

    public nuint Value => _value;

    public bool Equals(Pkcs11RsaOaepSourceType other) => _value == other._value;

    public override bool Equals(object? obj) => obj is Pkcs11RsaOaepSourceType other && Equals(other);

    public override int GetHashCode() => _value.GetHashCode();

    public override string ToString() => $"0x{_value:x}";

    public static bool operator ==(Pkcs11RsaOaepSourceType left, Pkcs11RsaOaepSourceType right) => left.Equals(right);

    public static bool operator !=(Pkcs11RsaOaepSourceType left, Pkcs11RsaOaepSourceType right) => !left.Equals(right);
}

public static class Pkcs11RsaOaepSourceTypes
{
    public static Pkcs11RsaOaepSourceType DataSpecified => new(0x00000001u);
}

public static class Pkcs11EcKdfTypes
{
    public static Pkcs11EcKdfType Null => new(0x00000001u);
}

public static class Pkcs11MechanismParameters
{
    public static byte[] AesGcm(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> additionalAuthenticatedData = default, nuint tagBits = 128, nuint? ivBits = null)
    {
        nuint effectiveIvBits = ivBits ?? checked((nuint)iv.Length * (nuint)8);
        int headerLength = IntPtr.Size * 4;
        ArgumentOutOfRangeException.ThrowIfGreaterThan(additionalAuthenticatedData.Length, int.MaxValue - iv.Length - headerLength);

        byte[] parameter = new byte[headerLength + iv.Length + additionalAuthenticatedData.Length];
        WriteNuint(parameter, 0, (nuint)iv.Length);
        WriteNuint(parameter, IntPtr.Size, effectiveIvBits);
        WriteNuint(parameter, IntPtr.Size * 2, (nuint)additionalAuthenticatedData.Length);
        WriteNuint(parameter, IntPtr.Size * 3, tagBits);

        iv.CopyTo(parameter.AsSpan(headerLength));
        additionalAuthenticatedData.CopyTo(parameter.AsSpan(headerLength + iv.Length));
        return parameter;
    }

    public static byte[] RsaOaep(Pkcs11MechanismType hashAlgorithm, Pkcs11RsaMgfType mgf, ReadOnlySpan<byte> sourceData = default)
        => RsaOaep(hashAlgorithm, mgf, Pkcs11RsaOaepSourceTypes.DataSpecified, sourceData);

    public static byte[] RsaOaep(Pkcs11MechanismType hashAlgorithm, Pkcs11RsaMgfType mgf, Pkcs11RsaOaepSourceType sourceType, ReadOnlySpan<byte> sourceData = default)
    {
        int headerLength = IntPtr.Size * 4;
        ArgumentOutOfRangeException.ThrowIfGreaterThan(sourceData.Length, int.MaxValue - headerLength);

        byte[] parameter = new byte[headerLength + sourceData.Length];
        WriteNuint(parameter, 0, hashAlgorithm.Value);
        WriteNuint(parameter, IntPtr.Size, mgf.Value);
        WriteNuint(parameter, IntPtr.Size * 2, sourceType.Value);
        WriteNuint(parameter, IntPtr.Size * 3, (nuint)sourceData.Length);
        sourceData.CopyTo(parameter.AsSpan(headerLength));
        return parameter;
    }

    public static byte[] RsaPss(Pkcs11MechanismType hashAlgorithm, Pkcs11RsaMgfType mgf, nuint saltLength)
    {
        int headerLength = IntPtr.Size * 3;
        byte[] parameter = new byte[headerLength];
        WriteNuint(parameter, 0, hashAlgorithm.Value);
        WriteNuint(parameter, IntPtr.Size, mgf.Value);
        WriteNuint(parameter, IntPtr.Size * 2, saltLength);
        return parameter;
    }

    public static byte[] Ecdh1Derive(ReadOnlySpan<byte> publicData, ReadOnlySpan<byte> sharedData = default)
        => Ecdh1Derive(Pkcs11EcKdfTypes.Null, publicData, sharedData);

    public static byte[] Ecdh1Derive(Pkcs11EcKdfType kdf, ReadOnlySpan<byte> publicData, ReadOnlySpan<byte> sharedData = default)
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThan(sharedData.Length, int.MaxValue - publicData.Length - (IntPtr.Size * 3));

        int headerLength = IntPtr.Size * 3;
        byte[] parameter = new byte[headerLength + sharedData.Length + publicData.Length];

        WriteNuint(parameter, 0, kdf.Value);
        WriteNuint(parameter, IntPtr.Size, (nuint)sharedData.Length);
        WriteNuint(parameter, IntPtr.Size * 2, (nuint)publicData.Length);

        sharedData.CopyTo(parameter.AsSpan(headerLength));
        publicData.CopyTo(parameter.AsSpan(headerLength + sharedData.Length));
        return parameter;
    }

    private static void WriteNuint(byte[] destination, int offset, nuint value)
        => MemoryMarshal.Write(destination.AsSpan(offset, IntPtr.Size), in value);
}
