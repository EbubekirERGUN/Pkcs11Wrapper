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

public static class Pkcs11EcKdfTypes
{
    public static Pkcs11EcKdfType Null => new(0x00000001u);
}

public static class Pkcs11MechanismParameters
{
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
