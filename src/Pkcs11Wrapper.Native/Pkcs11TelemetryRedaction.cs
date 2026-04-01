using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper.Native;

internal static unsafe class Pkcs11TelemetryRedaction
{
    private const nuint CkaClass = 0x00000000u;
    private const nuint CkaToken = 0x00000001u;
    private const nuint CkaPrivate = 0x00000002u;
    private const nuint CkaLabel = 0x00000003u;
    private const nuint CkaApplication = 0x00000010u;
    private const nuint CkaValue = 0x00000011u;
    private const nuint CkaObjectId = 0x00000012u;
    private const nuint CkaCertificateType = 0x00000080u;
    private const nuint CkaKeyType = 0x00000100u;
    private const nuint CkaId = 0x00000102u;
    private const nuint CkaSensitive = 0x00000103u;
    private const nuint CkaEncrypt = 0x00000104u;
    private const nuint CkaDecrypt = 0x00000105u;
    private const nuint CkaWrap = 0x00000106u;
    private const nuint CkaUnwrap = 0x00000107u;
    private const nuint CkaSign = 0x00000108u;
    private const nuint CkaVerify = 0x0000010au;
    private const nuint CkaDerive = 0x0000010cu;
    private const nuint CkaModulus = 0x00000120u;
    private const nuint CkaModulusBits = 0x00000121u;
    private const nuint CkaPublicExponent = 0x00000122u;
    private const nuint CkaPrivateExponent = 0x00000123u;
    private const nuint CkaPrime1 = 0x00000124u;
    private const nuint CkaPrime2 = 0x00000125u;
    private const nuint CkaExponent1 = 0x00000126u;
    private const nuint CkaExponent2 = 0x00000127u;
    private const nuint CkaCoefficient = 0x00000128u;
    private const nuint CkaPrime = 0x00000130u;
    private const nuint CkaSubprime = 0x00000131u;
    private const nuint CkaBase = 0x00000132u;
    private const nuint CkaValueBits = 0x00000160u;
    private const nuint CkaValueLen = 0x00000161u;
    private const nuint CkaExtractable = 0x00000162u;
    private const nuint CkaModifiable = 0x00000170u;
    private const nuint CkaEcParams = 0x00000180u;
    private const nuint CkaEcPoint = 0x00000181u;

    private const nuint CkmEcdh1Derive = 0x00001050u;
    private const nuint CkmAesCtr = 0x00001086u;
    private const nuint CkmAesGcm = 0x00001087u;
    private const nuint CkmAesCcm = 0x00001088u;
    private const nuint CkmRsaPkcsOaep = 0x00000009u;
    private const nuint CkmRsaPkcsPss = 0x0000000du;
    private const nuint CkmSha1RsaPkcsPss = 0x0000000eu;
    private const nuint CkmSha224RsaPkcsPss = 0x00000047u;
    private const nuint CkmSha256RsaPkcsPss = 0x00000043u;
    private const nuint CkmSha384RsaPkcsPss = 0x00000044u;
    private const nuint CkmSha512RsaPkcsPss = 0x00000045u;

    internal static Pkcs11OperationTelemetryField Safe(string name, string value)
        => new(name, Pkcs11TelemetryFieldClassification.SafeMetadata, value);

    internal static Pkcs11OperationTelemetryField Safe(string name, bool value)
        => Safe(name, value ? "true" : "false");

    internal static Pkcs11OperationTelemetryField Safe(string name, int value)
        => Safe(name, value.ToString());

    internal static Pkcs11OperationTelemetryField Safe(string name, nuint value)
        => Safe(name, value.ToString());

    internal static Pkcs11OperationTelemetryField SafeHex(string name, nuint value)
        => Safe(name, $"0x{value:x}");

    internal static Pkcs11OperationTelemetryField LengthOnly(string name, ReadOnlySpan<byte> value)
        => LengthOnly(name, value.Length);

    internal static Pkcs11OperationTelemetryField LengthOnly(string name, int length)
        => new(name, Pkcs11TelemetryFieldClassification.LengthOnly, $"len={length}");

    internal static Pkcs11OperationTelemetryField MaskedSecret(string name, ReadOnlySpan<byte> value)
        => new(
            name,
            Pkcs11TelemetryFieldClassification.Masked,
            value.IsEmpty ? "empty" : $"set(len={value.Length})");

    internal static Pkcs11OperationTelemetryField HashedBytes(string name, ReadOnlySpan<byte> value)
        => new(
            name,
            Pkcs11TelemetryFieldClassification.Hashed,
            $"sha256:{Convert.ToHexString(SHA256.HashData(value))[..24]} len={value.Length}");

    internal static Pkcs11OperationTelemetryField NeverLog(string name, int? length = null)
        => new(
            name,
            Pkcs11TelemetryFieldClassification.NeverLog,
            length.HasValue ? $"suppressed(len={length.Value})" : "suppressed");

    internal static Pkcs11OperationTelemetryField[] Credentials(CK_USER_TYPE userType, ReadOnlySpan<byte> pinUtf8)
        =>
        [
            Safe("credential.userType", FormatUserType(userType.Value)),
            MaskedSecret("credential.pin", pinUtf8),
        ];

    internal static Pkcs11OperationTelemetryField[] Credentials(CK_USER_TYPE userType, ReadOnlySpan<byte> pinUtf8, ReadOnlySpan<byte> usernameUtf8)
    {
        List<Pkcs11OperationTelemetryField> fields =
        [
            Safe("credential.userType", FormatUserType(userType.Value)),
            MaskedSecret("credential.pin", pinUtf8),
        ];

        fields.Add(usernameUtf8.IsEmpty
            ? MaskedSecret("credential.username", usernameUtf8)
            : HashedBytes("credential.username", usernameUtf8));

        return fields.ToArray();
    }

    internal static Pkcs11OperationTelemetryField[] InitToken(ReadOnlySpan<byte> pinUtf8, ReadOnlySpan<byte> labelUtf8)
        =>
        [
            MaskedSecret("token.soPin", pinUtf8),
            labelUtf8.IsEmpty
                ? MaskedSecret("token.label", labelUtf8)
                : HashedBytes("token.label", labelUtf8),
        ];

    internal static Pkcs11OperationTelemetryField[] PinChange(ReadOnlySpan<byte> oldPinUtf8, ReadOnlySpan<byte> newPinUtf8)
        =>
        [
            MaskedSecret("credential.oldPin", oldPinUtf8),
            MaskedSecret("credential.newPin", newPinUtf8),
        ];

    internal static Pkcs11OperationTelemetryField[] AttributeType(string name, CK_ATTRIBUTE_TYPE attributeType)
        => [Safe(name, GetAttributeName(attributeType.Value))];

    internal static Pkcs11OperationTelemetryField[] Template(string prefix, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        List<Pkcs11OperationTelemetryField> fields = [Safe($"{prefix}.count", template.Length)];
        Dictionary<string, int> nameCounts = new(StringComparer.Ordinal);

        for (int i = 0; i < template.Length; i++)
        {
            ref readonly CK_ATTRIBUTE attribute = ref template[i];
            string attributeName = GetAttributeName(attribute.Type.Value);
            string uniqueName = BuildUniqueFieldName(prefix, attributeName, nameCounts);
            nuint rawLength = attribute.ValueLength.Value;
            int? length = TryToInt32(rawLength);
            bool canRead = attribute.Value is not null && length.HasValue;
            ReadOnlySpan<byte> value = canRead ? new ReadOnlySpan<byte>(attribute.Value, length!.Value) : default;

            switch (ClassifyAttribute(attribute.Type.Value))
            {
                case AttributeClassification.SafeBoolean when canRead && value.Length > 0:
                    fields.Add(Safe(uniqueName, value[0] != 0));
                    break;
                case AttributeClassification.SafeNuint when canRead && value.Length >= IntPtr.Size:
                    fields.Add(Safe(uniqueName, ReadPackedNuint(value)));
                    break;
                case AttributeClassification.SafeObjectClass when canRead && value.Length >= IntPtr.Size:
                    fields.Add(Safe(uniqueName, FormatObjectClass(ReadPackedNuint(value))));
                    break;
                case AttributeClassification.SafeKeyType when canRead && value.Length >= IntPtr.Size:
                    fields.Add(Safe(uniqueName, FormatKeyType(ReadPackedNuint(value))));
                    break;
                case AttributeClassification.HashedBytes when canRead:
                    fields.Add(HashedBytes(uniqueName, value));
                    break;
                case AttributeClassification.NeverLog:
                    fields.Add(NeverLog(uniqueName, length));
                    break;
                default:
                    fields.Add(length.HasValue ? LengthOnly(uniqueName, length.Value) : NeverLog(uniqueName));
                    break;
            }
        }

        return fields.ToArray();
    }

    internal static Pkcs11OperationTelemetryField[] MechanismParameters(CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter)
    {
        List<Pkcs11OperationTelemetryField> fields = [LengthOnly("mechanism.parameter", mechanismParameter)];

        try
        {
            switch (mechanismType.Value)
            {
                case CkmAesCtr:
                    if (mechanismParameter.Length >= IntPtr.Size + 16)
                    {
                        fields.Add(Safe("mechanism.counterBits", ReadPackedNuint(mechanismParameter)));
                        fields.Add(LengthOnly("mechanism.counterBlock", 16));
                    }

                    break;
                case CkmAesGcm:
                    if (mechanismParameter.Length >= IntPtr.Size * 4)
                    {
                        nuint ivLength = ReadPackedNuint(mechanismParameter);
                        nuint ivBits = ReadPackedNuint(mechanismParameter[IntPtr.Size..]);
                        nuint aadLength = ReadPackedNuint(mechanismParameter[(IntPtr.Size * 2)..]);
                        nuint tagBits = ReadPackedNuint(mechanismParameter[(IntPtr.Size * 3)..]);

                        fields.Add(Safe("mechanism.ivBits", ivBits));
                        fields.Add(Safe("mechanism.tagBits", tagBits));

                        if (TryToInt32(ivLength) is int ivLengthValue)
                        {
                            fields.Add(LengthOnly("mechanism.iv", ivLengthValue));
                        }

                        if (TryToInt32(aadLength) is int aadLengthValue)
                        {
                            fields.Add(LengthOnly("mechanism.aad", aadLengthValue));
                        }
                    }

                    break;
                case CkmAesCcm:
                    if (mechanismParameter.Length >= IntPtr.Size * 4)
                    {
                        nuint dataLength = ReadPackedNuint(mechanismParameter);
                        nuint nonceLength = ReadPackedNuint(mechanismParameter[IntPtr.Size..]);
                        nuint aadLength = ReadPackedNuint(mechanismParameter[(IntPtr.Size * 2)..]);
                        nuint macLength = ReadPackedNuint(mechanismParameter[(IntPtr.Size * 3)..]);

                        fields.Add(Safe("mechanism.dataLength", dataLength));
                        fields.Add(Safe("mechanism.macLength", macLength));

                        if (TryToInt32(nonceLength) is int nonceLengthValue)
                        {
                            fields.Add(LengthOnly("mechanism.nonce", nonceLengthValue));
                        }

                        if (TryToInt32(aadLength) is int aadLengthValue)
                        {
                            fields.Add(LengthOnly("mechanism.aad", aadLengthValue));
                        }
                    }

                    break;
                case CkmRsaPkcsOaep:
                    if (mechanismParameter.Length >= IntPtr.Size * 4)
                    {
                        nuint hashAlg = ReadPackedNuint(mechanismParameter);
                        nuint mgf = ReadPackedNuint(mechanismParameter[IntPtr.Size..]);
                        nuint source = ReadPackedNuint(mechanismParameter[(IntPtr.Size * 2)..]);
                        nuint sourceDataLength = ReadPackedNuint(mechanismParameter[(IntPtr.Size * 3)..]);

                        fields.Add(SafeHex("mechanism.hashAlg", hashAlg));
                        fields.Add(SafeHex("mechanism.mgf", mgf));
                        fields.Add(SafeHex("mechanism.source", source));

                        if (TryToInt32(sourceDataLength) is int sourceDataLengthValue
                            && mechanismParameter.Length >= (IntPtr.Size * 4) + sourceDataLengthValue)
                        {
                            fields.Add(HashedBytes("mechanism.sourceData", mechanismParameter[(IntPtr.Size * 4)..(IntPtr.Size * 4 + sourceDataLengthValue)]));
                        }
                    }

                    break;
                case CkmRsaPkcsPss:
                case CkmSha1RsaPkcsPss:
                case CkmSha224RsaPkcsPss:
                case CkmSha256RsaPkcsPss:
                case CkmSha384RsaPkcsPss:
                case CkmSha512RsaPkcsPss:
                    if (mechanismParameter.Length >= IntPtr.Size * 3)
                    {
                        fields.Add(SafeHex("mechanism.hashAlg", ReadPackedNuint(mechanismParameter)));
                        fields.Add(SafeHex("mechanism.mgf", ReadPackedNuint(mechanismParameter[IntPtr.Size..])));
                        fields.Add(Safe("mechanism.saltLength", ReadPackedNuint(mechanismParameter[(IntPtr.Size * 2)..])));
                    }

                    break;
                case CkmEcdh1Derive:
                    if (mechanismParameter.Length >= IntPtr.Size * 3)
                    {
                        nuint kdf = ReadPackedNuint(mechanismParameter);
                        nuint sharedDataLength = ReadPackedNuint(mechanismParameter[IntPtr.Size..]);
                        nuint publicDataLength = ReadPackedNuint(mechanismParameter[(IntPtr.Size * 2)..]);
                        int headerLength = IntPtr.Size * 3;

                        fields.Add(SafeHex("mechanism.kdf", kdf));

                        if (TryToInt32(sharedDataLength) is int sharedDataLengthValue)
                        {
                            fields.Add(LengthOnly("mechanism.sharedData", sharedDataLengthValue));
                        }

                        if (TryToInt32(sharedDataLength + publicDataLength) is int payloadLength
                            && mechanismParameter.Length >= headerLength + payloadLength
                            && TryToInt32(sharedDataLength) is int sharedLength
                            && TryToInt32(publicDataLength) is int publicLength)
                        {
                            fields.Add(HashedBytes("mechanism.publicData", mechanismParameter[(headerLength + sharedLength)..(headerLength + sharedLength + publicLength)]));
                        }
                    }

                    break;
            }
        }
        catch
        {
        }

        return fields.ToArray();
    }

    private static string BuildUniqueFieldName(string prefix, string attributeName, Dictionary<string, int> nameCounts)
    {
        if (!nameCounts.TryGetValue(attributeName, out int count))
        {
            nameCounts[attributeName] = 1;
            return $"{prefix}.{attributeName}";
        }

        count++;
        nameCounts[attributeName] = count;
        return $"{prefix}.{attributeName}#{count}";
    }

    private static int? TryToInt32(nuint value)
        => value > int.MaxValue ? null : (int)value;

    private static nuint ReadPackedNuint(ReadOnlySpan<byte> bytes)
        => MemoryMarshal.Read<nuint>(bytes[..IntPtr.Size]);

    private static AttributeClassification ClassifyAttribute(nuint attributeType)
        => attributeType switch
        {
            CkaClass => AttributeClassification.SafeObjectClass,
            CkaToken or CkaPrivate or CkaSensitive or CkaEncrypt or CkaDecrypt or CkaWrap or CkaUnwrap or CkaSign or CkaVerify or CkaDerive or CkaExtractable or CkaModifiable
                => AttributeClassification.SafeBoolean,
            CkaKeyType => AttributeClassification.SafeKeyType,
            CkaCertificateType or CkaModulusBits or CkaValueBits or CkaValueLen => AttributeClassification.SafeNuint,
            CkaLabel or CkaApplication or CkaObjectId or CkaId or CkaEcParams or CkaEcPoint or CkaModulus or CkaPublicExponent
                => AttributeClassification.HashedBytes,
            CkaValue or CkaPrivateExponent or CkaPrime1 or CkaPrime2 or CkaExponent1 or CkaExponent2 or CkaCoefficient or CkaPrime or CkaSubprime or CkaBase
                => AttributeClassification.NeverLog,
            _ => AttributeClassification.LengthOnly,
        };

    private static string GetAttributeName(nuint attributeType)
        => attributeType switch
        {
            CkaClass => "CKA_CLASS",
            CkaToken => "CKA_TOKEN",
            CkaPrivate => "CKA_PRIVATE",
            CkaLabel => "CKA_LABEL",
            CkaApplication => "CKA_APPLICATION",
            CkaValue => "CKA_VALUE",
            CkaObjectId => "CKA_OBJECT_ID",
            CkaCertificateType => "CKA_CERTIFICATE_TYPE",
            CkaKeyType => "CKA_KEY_TYPE",
            CkaId => "CKA_ID",
            CkaSensitive => "CKA_SENSITIVE",
            CkaEncrypt => "CKA_ENCRYPT",
            CkaDecrypt => "CKA_DECRYPT",
            CkaWrap => "CKA_WRAP",
            CkaUnwrap => "CKA_UNWRAP",
            CkaSign => "CKA_SIGN",
            CkaVerify => "CKA_VERIFY",
            CkaDerive => "CKA_DERIVE",
            CkaModulus => "CKA_MODULUS",
            CkaModulusBits => "CKA_MODULUS_BITS",
            CkaPublicExponent => "CKA_PUBLIC_EXPONENT",
            CkaPrivateExponent => "CKA_PRIVATE_EXPONENT",
            CkaPrime1 => "CKA_PRIME_1",
            CkaPrime2 => "CKA_PRIME_2",
            CkaExponent1 => "CKA_EXPONENT_1",
            CkaExponent2 => "CKA_EXPONENT_2",
            CkaCoefficient => "CKA_COEFFICIENT",
            CkaPrime => "CKA_PRIME",
            CkaSubprime => "CKA_SUBPRIME",
            CkaBase => "CKA_BASE",
            CkaValueBits => "CKA_VALUE_BITS",
            CkaValueLen => "CKA_VALUE_LEN",
            CkaExtractable => "CKA_EXTRACTABLE",
            CkaModifiable => "CKA_MODIFIABLE",
            CkaEcParams => "CKA_EC_PARAMS",
            CkaEcPoint => "CKA_EC_POINT",
            _ => $"0x{attributeType:x}",
        };

    private static string FormatUserType(nuint userType)
        => userType switch
        {
            0u => "CKU_SO",
            1u => "CKU_USER",
            2u => "CKU_CONTEXT_SPECIFIC",
            _ => $"0x{userType:x}",
        };

    private static string FormatObjectClass(nuint objectClass)
        => objectClass switch
        {
            0u => "CKO_DATA",
            1u => "CKO_CERTIFICATE",
            2u => "CKO_PUBLIC_KEY",
            3u => "CKO_PRIVATE_KEY",
            4u => "CKO_SECRET_KEY",
            _ => $"0x{objectClass:x}",
        };

    private static string FormatKeyType(nuint keyType)
        => keyType switch
        {
            0u => "CKK_RSA",
            1u => "CKK_DSA",
            2u => "CKK_DH",
            3u => "CKK_EC",
            0x10u => "CKK_GENERIC_SECRET",
            0x1fu => "CKK_AES",
            _ => $"0x{keyType:x}",
        };

    private enum AttributeClassification
    {
        SafeBoolean,
        SafeNuint,
        SafeObjectClass,
        SafeKeyType,
        HashedBytes,
        LengthOnly,
        NeverLog,
    }
}
