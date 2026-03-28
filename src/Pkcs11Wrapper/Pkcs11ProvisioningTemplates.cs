namespace Pkcs11Wrapper;

public readonly record struct Pkcs11KeyPairTemplate(Pkcs11ObjectAttribute[] PublicKeyAttributes, Pkcs11ObjectAttribute[] PrivateKeyAttributes);

public static class Pkcs11ProvisioningTemplates
{
    public static Pkcs11ObjectAttribute[] CreateAesEncryptDecryptSecretKey(
        ReadOnlySpan<byte> label = default,
        ReadOnlySpan<byte> id = default,
        bool token = true,
        bool @private = true,
        bool sensitive = true,
        bool extractable = false,
        nuint valueLength = 32)
        =>
        [
            Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.SecretKey),
            Pkcs11ObjectAttribute.KeyType(Pkcs11AttributeTypes.KeyType, Pkcs11KeyTypes.Aes),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, token),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, @private),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Encrypt, true),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Decrypt, true),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Sensitive, sensitive),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Extractable, extractable),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, label.ToArray()),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Id, id.ToArray()),
            Pkcs11ObjectAttribute.Nuint(Pkcs11AttributeTypes.ValueLen, valueLength)
        ];

    public static Pkcs11ObjectAttribute[] CreateAesWrapUnwrapSecretKey(
        ReadOnlySpan<byte> label = default,
        ReadOnlySpan<byte> id = default,
        bool token = true,
        bool @private = true,
        bool sensitive = true,
        bool extractable = false,
        nuint valueLength = 32)
        =>
        [
            Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.SecretKey),
            Pkcs11ObjectAttribute.KeyType(Pkcs11AttributeTypes.KeyType, Pkcs11KeyTypes.Aes),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, token),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, @private),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Wrap, true),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Unwrap, true),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Sensitive, sensitive),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Extractable, extractable),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, label.ToArray()),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Id, id.ToArray()),
            Pkcs11ObjectAttribute.Nuint(Pkcs11AttributeTypes.ValueLen, valueLength)
        ];

    public static Pkcs11ObjectAttribute[] CreateAesUnwrapTargetSecretKey(
        ReadOnlySpan<byte> label = default,
        ReadOnlySpan<byte> id = default,
        bool token = false,
        bool @private = true,
        bool sensitive = true,
        bool extractable = false,
        bool encrypt = true,
        bool decrypt = true)
        =>
        [
            Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.SecretKey),
            Pkcs11ObjectAttribute.KeyType(Pkcs11AttributeTypes.KeyType, Pkcs11KeyTypes.Aes),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, token),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, @private),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Encrypt, encrypt),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Decrypt, decrypt),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Sensitive, sensitive),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Extractable, extractable),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, label.ToArray()),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Id, id.ToArray())
        ];

    public static Pkcs11KeyPairTemplate CreateRsaSignVerifyKeyPair(
        ReadOnlySpan<byte> label = default,
        ReadOnlySpan<byte> id = default,
        bool token = true,
        nuint modulusBits = 2048,
        ReadOnlySpan<byte> publicExponent = default,
        bool sensitive = true,
        bool extractable = false)
    {
        byte[] exponent = publicExponent.IsEmpty ? [0x01, 0x00, 0x01] : publicExponent.ToArray();
        byte[] labelBytes = label.ToArray();
        byte[] idBytes = id.ToArray();

        return new Pkcs11KeyPairTemplate(
        [
            Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.PublicKey),
            Pkcs11ObjectAttribute.KeyType(Pkcs11AttributeTypes.KeyType, Pkcs11KeyTypes.Rsa),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, token),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, false),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Verify, true),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, labelBytes),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Id, idBytes),
            Pkcs11ObjectAttribute.Nuint(Pkcs11AttributeTypes.ModulusBits, modulusBits),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.PublicExponent, exponent)
        ],
        [
            Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.PrivateKey),
            Pkcs11ObjectAttribute.KeyType(Pkcs11AttributeTypes.KeyType, Pkcs11KeyTypes.Rsa),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, token),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, true),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Sign, true),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Sensitive, sensitive),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Extractable, extractable),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, labelBytes),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Id, idBytes)
        ]);
    }

    public static Pkcs11KeyPairTemplate CreateEcSignVerifyKeyPair(
        ReadOnlySpan<byte> curveParameters,
        ReadOnlySpan<byte> label = default,
        ReadOnlySpan<byte> id = default,
        bool token = true,
        bool sensitive = true,
        bool extractable = false)
        => CreateEcKeyPair(curveParameters, label, id, token, sign: true, verify: true, derive: false, sensitive: sensitive, extractable: extractable);

    public static Pkcs11KeyPairTemplate CreateEcDeriveKeyPair(
        ReadOnlySpan<byte> curveParameters,
        ReadOnlySpan<byte> label = default,
        ReadOnlySpan<byte> id = default,
        bool token = true,
        bool sensitive = true,
        bool extractable = false)
        => CreateEcKeyPair(curveParameters, label, id, token, sign: false, verify: false, derive: true, sensitive: sensitive, extractable: extractable);

    private static Pkcs11KeyPairTemplate CreateEcKeyPair(
        ReadOnlySpan<byte> curveParameters,
        ReadOnlySpan<byte> label,
        ReadOnlySpan<byte> id,
        bool token,
        bool sign,
        bool verify,
        bool derive,
        bool sensitive,
        bool extractable)
    {
        byte[] labelBytes = label.ToArray();
        byte[] idBytes = id.ToArray();
        byte[] curveBytes = curveParameters.ToArray();

        return new Pkcs11KeyPairTemplate(
        [
            Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.PublicKey),
            Pkcs11ObjectAttribute.KeyType(Pkcs11AttributeTypes.KeyType, Pkcs11KeyTypes.Ec),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, token),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, false),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Verify, verify),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, labelBytes),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Id, idBytes),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.EcParams, curveBytes)
        ],
        [
            Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.PrivateKey),
            Pkcs11ObjectAttribute.KeyType(Pkcs11AttributeTypes.KeyType, Pkcs11KeyTypes.Ec),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, token),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, true),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Sign, sign),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Derive, derive),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Sensitive, sensitive),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Extractable, extractable),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, labelBytes),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Id, idBytes)
        ]);
    }
}
