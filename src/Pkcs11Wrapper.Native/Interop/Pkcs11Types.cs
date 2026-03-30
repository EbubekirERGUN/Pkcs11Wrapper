using System.Runtime.InteropServices;

namespace Pkcs11Wrapper.Native.Interop;

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_FLAGS : IEquatable<CK_FLAGS>
{
    public CK_FLAGS(nuint value) => Value = value;

    public readonly nuint Value;

    public static implicit operator CK_FLAGS(nuint value) => new(value);

    public static explicit operator nuint(CK_FLAGS value) => value.Value;

    public bool Equals(CK_FLAGS other) => Value == other.Value;

    public override bool Equals(object? obj) => obj is CK_FLAGS other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => $"0x{Value:x}";

    public static bool operator ==(CK_FLAGS left, CK_FLAGS right) => left.Equals(right);

    public static bool operator !=(CK_FLAGS left, CK_FLAGS right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_BBOOL : IEquatable<CK_BBOOL>
{
    public static readonly CK_BBOOL False = new(0);
    public static readonly CK_BBOOL True = new(1);

    public CK_BBOOL(byte value) => Value = value;

    public readonly byte Value;

    public bool Equals(CK_BBOOL other) => Value == other.Value;

    public override bool Equals(object? obj) => obj is CK_BBOOL other && Equals(other);

    public override int GetHashCode() => Value;

    public override string ToString() => Value == 0 ? "False" : "True";

    public static bool operator ==(CK_BBOOL left, CK_BBOOL right) => left.Equals(right);

    public static bool operator !=(CK_BBOOL left, CK_BBOOL right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_RV : IEquatable<CK_RV>
{
    public static readonly CK_RV Ok = new(0);

    public CK_RV(nuint value) => Value = value;

    public readonly nuint Value;

    public bool IsSuccess => Value == Ok.Value;

    public static implicit operator CK_RV(nuint value) => new(value);

    public static explicit operator nuint(CK_RV value) => value.Value;

    public bool Equals(CK_RV other) => Value == other.Value;

    public override bool Equals(object? obj) => obj is CK_RV other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => $"0x{Value:x}";

    public static bool operator ==(CK_RV left, CK_RV right) => left.Equals(right);

    public static bool operator !=(CK_RV left, CK_RV right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_ULONG : IEquatable<CK_ULONG>
{
    public CK_ULONG(nuint value) => Value = value;

    public readonly nuint Value;

    public static implicit operator CK_ULONG(nuint value) => new(value);

    public static explicit operator nuint(CK_ULONG value) => value.Value;

    public bool Equals(CK_ULONG other) => Value == other.Value;

    public override bool Equals(object? obj) => obj is CK_ULONG other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => Value.ToString();

    public static bool operator ==(CK_ULONG left, CK_ULONG right) => left.Equals(right);

    public static bool operator !=(CK_ULONG left, CK_ULONG right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_SLOT_ID : IEquatable<CK_SLOT_ID>
{
    public CK_SLOT_ID(nuint value) => Value = value;

    public readonly nuint Value;

    public static implicit operator CK_SLOT_ID(nuint value) => new(value);

    public static explicit operator nuint(CK_SLOT_ID value) => value.Value;

    public bool Equals(CK_SLOT_ID other) => Value == other.Value;

    public override bool Equals(object? obj) => obj is CK_SLOT_ID other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => Value.ToString();

    public static bool operator ==(CK_SLOT_ID left, CK_SLOT_ID right) => left.Equals(right);

    public static bool operator !=(CK_SLOT_ID left, CK_SLOT_ID right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_SESSION_HANDLE : IEquatable<CK_SESSION_HANDLE>
{
    public CK_SESSION_HANDLE(nuint value) => Value = value;

    public readonly nuint Value;

    public static implicit operator CK_SESSION_HANDLE(nuint value) => new(value);

    public static explicit operator nuint(CK_SESSION_HANDLE value) => value.Value;

    public bool Equals(CK_SESSION_HANDLE other) => Value == other.Value;

    public override bool Equals(object? obj) => obj is CK_SESSION_HANDLE other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => Value.ToString();

    public static bool operator ==(CK_SESSION_HANDLE left, CK_SESSION_HANDLE right) => left.Equals(right);

    public static bool operator !=(CK_SESSION_HANDLE left, CK_SESSION_HANDLE right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_STATE : IEquatable<CK_STATE>
{
    public CK_STATE(nuint value) => Value = value;

    public readonly nuint Value;

    public static implicit operator CK_STATE(nuint value) => new(value);

    public static explicit operator nuint(CK_STATE value) => value.Value;

    public bool Equals(CK_STATE other) => Value == other.Value;

    public override bool Equals(object? obj) => obj is CK_STATE other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => Value.ToString();

    public static bool operator ==(CK_STATE left, CK_STATE right) => left.Equals(right);

    public static bool operator !=(CK_STATE left, CK_STATE right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_USER_TYPE : IEquatable<CK_USER_TYPE>
{
    public CK_USER_TYPE(nuint value) => Value = value;

    public readonly nuint Value;

    public static implicit operator CK_USER_TYPE(nuint value) => new(value);

    public static explicit operator nuint(CK_USER_TYPE value) => value.Value;

    public bool Equals(CK_USER_TYPE other) => Value == other.Value;

    public override bool Equals(object? obj) => obj is CK_USER_TYPE other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => Value.ToString();

    public static bool operator ==(CK_USER_TYPE left, CK_USER_TYPE right) => left.Equals(right);

    public static bool operator !=(CK_USER_TYPE left, CK_USER_TYPE right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_MECHANISM_TYPE : IEquatable<CK_MECHANISM_TYPE>
{
    public CK_MECHANISM_TYPE(nuint value) => Value = value;

    public readonly nuint Value;

    public static implicit operator CK_MECHANISM_TYPE(nuint value) => new(value);

    public static explicit operator nuint(CK_MECHANISM_TYPE value) => value.Value;

    public bool Equals(CK_MECHANISM_TYPE other) => Value == other.Value;

    public override bool Equals(object? obj) => obj is CK_MECHANISM_TYPE other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => Value.ToString();

    public static bool operator ==(CK_MECHANISM_TYPE left, CK_MECHANISM_TYPE right) => left.Equals(right);

    public static bool operator !=(CK_MECHANISM_TYPE left, CK_MECHANISM_TYPE right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_ATTRIBUTE_TYPE : IEquatable<CK_ATTRIBUTE_TYPE>
{
    public CK_ATTRIBUTE_TYPE(nuint value) => Value = value;

    public readonly nuint Value;

    public static implicit operator CK_ATTRIBUTE_TYPE(nuint value) => new(value);

    public static explicit operator nuint(CK_ATTRIBUTE_TYPE value) => value.Value;

    public bool Equals(CK_ATTRIBUTE_TYPE other) => Value == other.Value;

    public override bool Equals(object? obj) => obj is CK_ATTRIBUTE_TYPE other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => $"0x{Value:x}";

    public static bool operator ==(CK_ATTRIBUTE_TYPE left, CK_ATTRIBUTE_TYPE right) => left.Equals(right);

    public static bool operator !=(CK_ATTRIBUTE_TYPE left, CK_ATTRIBUTE_TYPE right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_OBJECT_CLASS : IEquatable<CK_OBJECT_CLASS>
{
    public CK_OBJECT_CLASS(nuint value) => Value = value;

    public readonly nuint Value;

    public static implicit operator CK_OBJECT_CLASS(nuint value) => new(value);

    public static explicit operator nuint(CK_OBJECT_CLASS value) => value.Value;

    public bool Equals(CK_OBJECT_CLASS other) => Value == other.Value;

    public override bool Equals(object? obj) => obj is CK_OBJECT_CLASS other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => Value.ToString();

    public static bool operator ==(CK_OBJECT_CLASS left, CK_OBJECT_CLASS right) => left.Equals(right);

    public static bool operator !=(CK_OBJECT_CLASS left, CK_OBJECT_CLASS right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_KEY_TYPE : IEquatable<CK_KEY_TYPE>
{
    public CK_KEY_TYPE(nuint value) => Value = value;

    public readonly nuint Value;

    public static implicit operator CK_KEY_TYPE(nuint value) => new(value);

    public static explicit operator nuint(CK_KEY_TYPE value) => value.Value;

    public bool Equals(CK_KEY_TYPE other) => Value == other.Value;

    public override bool Equals(object? obj) => obj is CK_KEY_TYPE other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => Value.ToString();

    public static bool operator ==(CK_KEY_TYPE left, CK_KEY_TYPE right) => left.Equals(right);

    public static bool operator !=(CK_KEY_TYPE left, CK_KEY_TYPE right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_CERTIFICATE_TYPE : IEquatable<CK_CERTIFICATE_TYPE>
{
    public CK_CERTIFICATE_TYPE(nuint value) => Value = value;

    public readonly nuint Value;

    public static implicit operator CK_CERTIFICATE_TYPE(nuint value) => new(value);

    public static explicit operator nuint(CK_CERTIFICATE_TYPE value) => value.Value;

    public bool Equals(CK_CERTIFICATE_TYPE other) => Value == other.Value;

    public override bool Equals(object? obj) => obj is CK_CERTIFICATE_TYPE other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => Value.ToString();

    public static bool operator ==(CK_CERTIFICATE_TYPE left, CK_CERTIFICATE_TYPE right) => left.Equals(right);

    public static bool operator !=(CK_CERTIFICATE_TYPE left, CK_CERTIFICATE_TYPE right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_OBJECT_HANDLE : IEquatable<CK_OBJECT_HANDLE>
{
    public CK_OBJECT_HANDLE(nuint value) => Value = value;

    public readonly nuint Value;

    public static implicit operator CK_OBJECT_HANDLE(nuint value) => new(value);

    public static explicit operator nuint(CK_OBJECT_HANDLE value) => value.Value;

    public bool Equals(CK_OBJECT_HANDLE other) => Value == other.Value;

    public override bool Equals(object? obj) => obj is CK_OBJECT_HANDLE other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => Value.ToString();

    public static bool operator ==(CK_OBJECT_HANDLE left, CK_OBJECT_HANDLE right) => left.Equals(right);

    public static bool operator !=(CK_OBJECT_HANDLE left, CK_OBJECT_HANDLE right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct CK_MECHANISM
{
    public CK_MECHANISM_TYPE Mechanism;
    public void* Parameter;
    public CK_ULONG ParameterLength;
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_EC_KDF_TYPE : IEquatable<CK_EC_KDF_TYPE>
{
    public CK_EC_KDF_TYPE(nuint value) => Value = value;

    public readonly nuint Value;

    public static implicit operator CK_EC_KDF_TYPE(nuint value) => new(value);

    public static explicit operator nuint(CK_EC_KDF_TYPE value) => value.Value;

    public bool Equals(CK_EC_KDF_TYPE other) => Value == other.Value;

    public override bool Equals(object? obj) => obj is CK_EC_KDF_TYPE other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => $"0x{Value:x}";

    public static bool operator ==(CK_EC_KDF_TYPE left, CK_EC_KDF_TYPE right) => left.Equals(right);

    public static bool operator !=(CK_EC_KDF_TYPE left, CK_EC_KDF_TYPE right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct CK_ECDH1_DERIVE_PARAMS
{
    public CK_EC_KDF_TYPE Kdf;
    public CK_ULONG SharedDataLen;
    public byte* SharedData;
    public CK_ULONG PublicDataLen;
    public byte* PublicData;
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_RSA_PKCS_MGF_TYPE : IEquatable<CK_RSA_PKCS_MGF_TYPE>
{
    public CK_RSA_PKCS_MGF_TYPE(nuint value) => Value = value;

    public readonly nuint Value;

    public static implicit operator CK_RSA_PKCS_MGF_TYPE(nuint value) => new(value);

    public static explicit operator nuint(CK_RSA_PKCS_MGF_TYPE value) => value.Value;

    public bool Equals(CK_RSA_PKCS_MGF_TYPE other) => Value == other.Value;

    public override bool Equals(object? obj) => obj is CK_RSA_PKCS_MGF_TYPE other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => $"0x{Value:x}";

    public static bool operator ==(CK_RSA_PKCS_MGF_TYPE left, CK_RSA_PKCS_MGF_TYPE right) => left.Equals(right);

    public static bool operator !=(CK_RSA_PKCS_MGF_TYPE left, CK_RSA_PKCS_MGF_TYPE right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_RSA_PKCS_OAEP_SOURCE_TYPE : IEquatable<CK_RSA_PKCS_OAEP_SOURCE_TYPE>
{
    public CK_RSA_PKCS_OAEP_SOURCE_TYPE(nuint value) => Value = value;

    public readonly nuint Value;

    public static implicit operator CK_RSA_PKCS_OAEP_SOURCE_TYPE(nuint value) => new(value);

    public static explicit operator nuint(CK_RSA_PKCS_OAEP_SOURCE_TYPE value) => value.Value;

    public bool Equals(CK_RSA_PKCS_OAEP_SOURCE_TYPE other) => Value == other.Value;

    public override bool Equals(object? obj) => obj is CK_RSA_PKCS_OAEP_SOURCE_TYPE other && Equals(other);

    public override int GetHashCode() => Value.GetHashCode();

    public override string ToString() => $"0x{Value:x}";

    public static bool operator ==(CK_RSA_PKCS_OAEP_SOURCE_TYPE left, CK_RSA_PKCS_OAEP_SOURCE_TYPE right) => left.Equals(right);

    public static bool operator !=(CK_RSA_PKCS_OAEP_SOURCE_TYPE left, CK_RSA_PKCS_OAEP_SOURCE_TYPE right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct CK_AES_CTR_PARAMS
{
    public CK_ULONG CounterBits;
    public fixed byte Cb[16];
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct CK_CCM_PARAMS
{
    public CK_ULONG DataLen;
    public byte* Nonce;
    public CK_ULONG NonceLen;
    public byte* Aad;
    public CK_ULONG AadLen;
    public CK_ULONG MacLen;
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct CK_GCM_PARAMS
{
    public byte* Iv;
    public CK_ULONG IvLen;
    public CK_ULONG IvBits;
    public byte* Aad;
    public CK_ULONG AadLen;
    public CK_ULONG TagBits;
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct CK_RSA_PKCS_OAEP_PARAMS
{
    public CK_MECHANISM_TYPE HashAlg;
    public CK_RSA_PKCS_MGF_TYPE Mgf;
    public CK_RSA_PKCS_OAEP_SOURCE_TYPE Source;
    public void* SourceData;
    public CK_ULONG SourceDataLen;
}

[StructLayout(LayoutKind.Sequential)]
public struct CK_RSA_PKCS_PSS_PARAMS
{
    public CK_MECHANISM_TYPE HashAlg;
    public CK_RSA_PKCS_MGF_TYPE Mgf;
    public CK_ULONG SaltLen;
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct CK_ATTRIBUTE
{
    public CK_ATTRIBUTE_TYPE Type;
    public void* Value;
    public CK_ULONG ValueLength;
}

[StructLayout(LayoutKind.Sequential)]
public struct CK_MECHANISM_INFO
{
    public CK_ULONG MinKeySize;
    public CK_ULONG MaxKeySize;
    public CK_FLAGS Flags;
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct CK_VERSION : IEquatable<CK_VERSION>
{
    public CK_VERSION(byte major, byte minor)
    {
        Major = major;
        Minor = minor;
    }

    public readonly byte Major;

    public readonly byte Minor;

    public bool Equals(CK_VERSION other) => Major == other.Major && Minor == other.Minor;

    public override bool Equals(object? obj) => obj is CK_VERSION other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(Major, Minor);

    public override string ToString() => $"{Major}.{Minor}";

    public static bool operator ==(CK_VERSION left, CK_VERSION right) => left.Equals(right);

    public static bool operator !=(CK_VERSION left, CK_VERSION right) => !left.Equals(right);
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct CK_INFO
{
    public CK_VERSION CryptokiVersion;
    public fixed byte ManufacturerId[32];
    public CK_FLAGS Flags;
    public fixed byte LibraryDescription[32];
    public CK_VERSION LibraryVersion;
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct CK_SLOT_INFO
{
    public fixed byte SlotDescription[64];
    public fixed byte ManufacturerId[32];
    public CK_FLAGS Flags;
    public CK_VERSION HardwareVersion;
    public CK_VERSION FirmwareVersion;
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct CK_TOKEN_INFO
{
    public fixed byte Label[32];
    public fixed byte ManufacturerId[32];
    public fixed byte Model[16];
    public fixed byte SerialNumber[16];
    public CK_FLAGS Flags;
    public CK_ULONG MaxSessionCount;
    public CK_ULONG SessionCount;
    public CK_ULONG MaxRwSessionCount;
    public CK_ULONG RwSessionCount;
    public CK_ULONG MaxPinLen;
    public CK_ULONG MinPinLen;
    public CK_ULONG TotalPublicMemory;
    public CK_ULONG FreePublicMemory;
    public CK_ULONG TotalPrivateMemory;
    public CK_ULONG FreePrivateMemory;
    public CK_VERSION HardwareVersion;
    public CK_VERSION FirmwareVersion;
    public fixed byte UtcTime[16];
}

[StructLayout(LayoutKind.Sequential)]
public struct CK_SESSION_INFO
{
    public CK_SLOT_ID SlotId;
    public CK_STATE State;
    public CK_FLAGS Flags;
    public CK_ULONG DeviceError;
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct CK_FUNCTION_LIST
{
    public CK_VERSION Version;
    public delegate* unmanaged[Cdecl]<void*, CK_RV> C_Initialize;
    public delegate* unmanaged[Cdecl]<void*, CK_RV> C_Finalize;
    public delegate* unmanaged[Cdecl]<CK_INFO*, CK_RV> C_GetInfo;
    public delegate* unmanaged[Cdecl]<CK_FUNCTION_LIST**, CK_RV> C_GetFunctionList;
    public delegate* unmanaged[Cdecl]<CK_BBOOL, CK_SLOT_ID*, CK_ULONG*, CK_RV> C_GetSlotList;
    public delegate* unmanaged[Cdecl]<CK_SLOT_ID, CK_SLOT_INFO*, CK_RV> C_GetSlotInfo;
    public delegate* unmanaged[Cdecl]<CK_SLOT_ID, CK_TOKEN_INFO*, CK_RV> C_GetTokenInfo;
    public delegate* unmanaged[Cdecl]<CK_SLOT_ID, CK_MECHANISM_TYPE*, CK_ULONG*, CK_RV> C_GetMechanismList;
    public delegate* unmanaged[Cdecl]<CK_SLOT_ID, CK_MECHANISM_TYPE, void*, CK_RV> C_GetMechanismInfo;
    public delegate* unmanaged[Cdecl]<CK_SLOT_ID, byte*, CK_ULONG, byte*, CK_RV> C_InitToken;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, CK_RV> C_InitPIN;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG, CK_RV> C_SetPIN;
    public delegate* unmanaged[Cdecl]<CK_SLOT_ID, CK_FLAGS, void*, void*, CK_SESSION_HANDLE*, CK_RV> C_OpenSession;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_RV> C_CloseSession;
    public delegate* unmanaged[Cdecl]<CK_SLOT_ID, CK_RV> C_CloseAllSessions;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_SESSION_INFO*, CK_RV> C_GetSessionInfo;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG*, CK_RV> C_GetOperationState;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, CK_RV> C_SetOperationState;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_USER_TYPE, byte*, CK_ULONG, CK_RV> C_Login;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_RV> C_Logout;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_RV> C_CreateObject;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_RV> C_CopyObject;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_RV> C_DestroyObject;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG*, CK_RV> C_GetObjectSize;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_RV> C_GetAttributeValue;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_RV> C_SetAttributeValue;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_RV> C_FindObjectsInit;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_OBJECT_HANDLE*, CK_ULONG, CK_ULONG*, CK_RV> C_FindObjects;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_RV> C_FindObjectsFinal;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_RV> C_EncryptInit;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> C_Encrypt;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> C_EncryptUpdate;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG*, CK_RV> C_EncryptFinal;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_RV> C_DecryptInit;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> C_Decrypt;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> C_DecryptUpdate;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG*, CK_RV> C_DecryptFinal;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_RV> C_DigestInit;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> C_Digest;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, CK_RV> C_DigestUpdate;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_RV> C_DigestKey;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG*, CK_RV> C_DigestFinal;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_RV> C_SignInit;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> C_Sign;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, CK_RV> C_SignUpdate;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG*, CK_RV> C_SignFinal;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_RV> C_SignRecoverInit;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> C_SignRecover;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_RV> C_VerifyInit;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG, CK_RV> C_Verify;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, CK_RV> C_VerifyUpdate;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, CK_RV> C_VerifyFinal;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_RV> C_VerifyRecoverInit;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> C_VerifyRecover;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> C_DigestEncryptUpdate;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> C_DecryptDigestUpdate;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> C_SignEncryptUpdate;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> C_DecryptVerifyUpdate;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_RV> C_GenerateKey;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_ATTRIBUTE*, CK_ULONG, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*, CK_RV> C_GenerateKeyPair;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE, byte*, CK_ULONG*, CK_RV> C_WrapKey;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, byte*, CK_ULONG, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_RV> C_UnwrapKey;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG, CK_OBJECT_HANDLE*, CK_RV> C_DeriveKey;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, CK_RV> C_SeedRandom;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, CK_RV> C_GenerateRandom;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_RV> C_GetFunctionStatus;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_RV> C_CancelFunction;
    public delegate* unmanaged[Cdecl]<CK_FLAGS, CK_SLOT_ID*, void*, CK_RV> C_WaitForSlotEvent;
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct CK_INTERFACE
{
    public byte* InterfaceName;
    public void* FunctionList;
    public CK_FLAGS Flags;
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct CK_FUNCTION_LIST_3_0
{
    public CK_FUNCTION_LIST Base;
    public delegate* unmanaged[Cdecl]<CK_INTERFACE*, CK_ULONG*, CK_RV> C_GetInterfaceList;
    public delegate* unmanaged[Cdecl]<byte*, CK_VERSION*, CK_INTERFACE**, CK_FLAGS, CK_RV> C_GetInterface;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_USER_TYPE, byte*, CK_ULONG, byte*, CK_ULONG, CK_RV> C_LoginUser;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_FLAGS, CK_RV> C_SessionCancel;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_RV> C_MessageEncryptInit;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> C_EncryptMessage;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, CK_RV> C_EncryptMessageBegin;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG*, CK_FLAGS, CK_RV> C_EncryptMessageNext;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_RV> C_MessageEncryptFinal;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_RV> C_MessageDecryptInit;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> C_DecryptMessage;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, CK_RV> C_DecryptMessageBegin;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG*, CK_FLAGS, CK_RV> C_DecryptMessageNext;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_RV> C_MessageDecryptFinal;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_RV> C_MessageSignInit;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> C_SignMessage;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, CK_RV> C_SignMessageBegin;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> C_SignMessageNext;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_RV> C_MessageSignFinal;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_RV> C_MessageVerifyInit;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG, CK_RV> C_VerifyMessage;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, CK_RV> C_VerifyMessageBegin;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG, CK_RV> C_VerifyMessageNext;
    public delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_RV> C_MessageVerifyFinal;
}


[StructLayout(LayoutKind.Sequential)]
public unsafe struct CK_C_INITIALIZE_ARGS
{
    public delegate* unmanaged[Cdecl]<void**, CK_RV> CreateMutex;
    public delegate* unmanaged[Cdecl]<void*, CK_RV> DestroyMutex;
    public delegate* unmanaged[Cdecl]<void*, CK_RV> LockMutex;
    public delegate* unmanaged[Cdecl]<void*, CK_RV> UnlockMutex;
    public CK_FLAGS Flags;
    public void* Reserved;
}
