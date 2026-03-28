using Pkcs11Wrapper;

namespace Pkcs11Wrapper.Native.Tests;

public sealed class ManagedApiSurfaceTests
{
    [Fact]
    public void SessionEnumsMatchPkcs11Constants()
    {
        Assert.Equal(0x00000002ul, (ulong)Pkcs11SessionFlags.ReadWrite);
        Assert.Equal(0x00000004ul, (ulong)Pkcs11SessionFlags.SerialSession);
        Assert.Equal(0ul, (ulong)Pkcs11SessionState.ReadOnlyPublic);
        Assert.Equal(4ul, (ulong)Pkcs11SessionState.ReadWriteSecurityOfficer);
        Assert.Equal(0ul, (ulong)Pkcs11UserType.SecurityOfficer);
        Assert.Equal(1ul, (ulong)Pkcs11UserType.User);
        Assert.Equal(2ul, (ulong)Pkcs11UserType.ContextSpecific);
    }

    [Fact]
    public void SlotIdExposesPointerSizedValue()
    {
        nuint nativeValue = (nuint)IntPtr.Size;
        Pkcs11SlotId slotId = new(nativeValue);

        Assert.Equal(nativeValue, slotId.Value);
        Assert.Equal(nativeValue.ToString(), slotId.ToString());
    }

    [Fact]
    public void MechanismAndObjectValueTypesExposePointerSizedValues()
    {
        nuint nativeValue = (nuint)(IntPtr.Size + 7);
        Pkcs11MechanismType mechanismType = new(nativeValue);
        Pkcs11ObjectHandle objectHandle = new(nativeValue);
        Pkcs11AttributeType attributeType = new(nativeValue);
        Pkcs11ObjectClass objectClass = new(nativeValue);
        Pkcs11KeyType keyType = new(nativeValue);

        Assert.Equal(nativeValue, mechanismType.Value);
        Assert.Equal($"0x{nativeValue:x}", mechanismType.ToString());
        Assert.Equal(nativeValue, objectHandle.Value);
        Assert.Equal(nativeValue.ToString(), objectHandle.ToString());
        Assert.Equal(nativeValue, attributeType.Value);
        Assert.Equal($"0x{nativeValue:x}", attributeType.ToString());
        Assert.Equal(nativeValue, objectClass.Value);
        Assert.Equal(nativeValue, keyType.Value);
    }

    [Fact]
    public void MechanismFlagsMatchPkcs11Constants()
    {
        Assert.Equal(0x00000001ul, (ulong)Pkcs11MechanismFlags.Hardware);
        Assert.Equal(0x00000100ul, (ulong)Pkcs11MechanismFlags.Encrypt);
        Assert.Equal(0x00000200ul, (ulong)Pkcs11MechanismFlags.Decrypt);
        Assert.Equal(0x00008000ul, (ulong)Pkcs11MechanismFlags.Generate);
        Assert.Equal(0x00010000ul, (ulong)Pkcs11MechanismFlags.GenerateKeyPair);
        Assert.Equal(0x80000000ul, (ulong)Pkcs11MechanismFlags.Extension);
    }

    [Fact]
    public void ObjectAndAttributeConstantsMatchPkcs11Constants()
    {
        Assert.Equal((nuint)0x00000000u, Pkcs11AttributeTypes.Class.Value);
        Assert.Equal((nuint)0x00000002u, Pkcs11AttributeTypes.Private.Value);
        Assert.Equal((nuint)0x00000003u, Pkcs11AttributeTypes.Label.Value);
        Assert.Equal((nuint)0x00000010u, Pkcs11AttributeTypes.Application.Value);
        Assert.Equal((nuint)0x00000102u, Pkcs11AttributeTypes.Id.Value);
        Assert.Equal((nuint)0x00000103u, Pkcs11AttributeTypes.Sensitive.Value);
        Assert.Equal((nuint)0x00000104u, Pkcs11AttributeTypes.Encrypt.Value);
        Assert.Equal((nuint)0x00000105u, Pkcs11AttributeTypes.Decrypt.Value);
        Assert.Equal((nuint)0x00000106u, Pkcs11AttributeTypes.Wrap.Value);
        Assert.Equal((nuint)0x00000107u, Pkcs11AttributeTypes.Unwrap.Value);
        Assert.Equal((nuint)0x00000108u, Pkcs11AttributeTypes.Sign.Value);
        Assert.Equal((nuint)0x0000010au, Pkcs11AttributeTypes.Verify.Value);
        Assert.Equal((nuint)0x0000010cu, Pkcs11AttributeTypes.Derive.Value);
        Assert.Equal((nuint)0x00000121u, Pkcs11AttributeTypes.ModulusBits.Value);
        Assert.Equal((nuint)0x00000122u, Pkcs11AttributeTypes.PublicExponent.Value);
        Assert.Equal((nuint)0x00000161u, Pkcs11AttributeTypes.ValueLen.Value);
        Assert.Equal((nuint)0x00000162u, Pkcs11AttributeTypes.Extractable.Value);
        Assert.Equal((nuint)0x00000170u, Pkcs11AttributeTypes.Modifiable.Value);
        Assert.Equal((nuint)0x00000180u, Pkcs11AttributeTypes.EcParams.Value);
        Assert.Equal((nuint)0x00000181u, Pkcs11AttributeTypes.EcPoint.Value);
        Assert.Equal((nuint)0x00000002u, Pkcs11ObjectClasses.PublicKey.Value);
        Assert.Equal((nuint)0x00000003u, Pkcs11ObjectClasses.PrivateKey.Value);
        Assert.Equal((nuint)0x00000004u, Pkcs11ObjectClasses.SecretKey.Value);
        Assert.Equal((nuint)0x0000001fu, Pkcs11KeyTypes.Aes.Value);
        Assert.Equal((nuint)0x00000000u, Pkcs11MechanismTypes.RsaPkcsKeyPairGen.Value);
        Assert.Equal((nuint)0x00001040u, Pkcs11MechanismTypes.EcKeyPairGen.Value);
        Assert.Equal((nuint)0x00001050u, Pkcs11MechanismTypes.Ecdh1Derive.Value);
        Assert.Equal((nuint)0x00001080u, Pkcs11MechanismTypes.AesKeyGen.Value);
        Assert.Equal((nuint)0x00000220u, Pkcs11MechanismTypes.Sha1.Value);
        Assert.Equal((nuint)0x00000255u, Pkcs11MechanismTypes.Sha224.Value);
        Assert.Equal((nuint)0x00000250u, Pkcs11MechanismTypes.Sha256.Value);
        Assert.Equal((nuint)0x00000260u, Pkcs11MechanismTypes.Sha384.Value);
        Assert.Equal((nuint)0x00000270u, Pkcs11MechanismTypes.Sha512.Value);
        Assert.Equal((nuint)0x00001082u, Pkcs11MechanismTypes.AesCbc.Value);
        Assert.Equal((nuint)0x0000210au, Pkcs11MechanismTypes.AesKeyWrapPad.Value);
        Assert.Equal((nuint)0x00000040u, Pkcs11MechanismTypes.Sha256RsaPkcs.Value);
    }

    [Fact]
    public void ObjectAttributeFactoriesProduceExpectedByteLayout()
    {
        byte[] value = [0x10, 0x20, 0x30];

        Assert.Equal(value, Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Value, value).Value.ToArray());
        Assert.Equal([1], Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, true).Value.ToArray());
        Assert.Equal([0], Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, false).Value.ToArray());
        Assert.Equal(IntPtr.Size, Pkcs11ObjectAttribute.Nuint(Pkcs11AttributeTypes.Class, 7).Value.Length);
        Assert.Equal(IntPtr.Size, Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.Data).Value.Length);
        Assert.Equal(IntPtr.Size, Pkcs11ObjectAttribute.KeyType(Pkcs11AttributeTypes.KeyType, Pkcs11KeyTypes.Aes).Value.Length);
    }

    [Fact]
    public void AttributeReadResultReflectsReadableState()
    {
        Pkcs11AttributeReadResult success = new(Pkcs11AttributeReadStatus.Success, 8);
        Pkcs11AttributeReadResult unavailable = new(Pkcs11AttributeReadStatus.UnavailableInformation, nuint.MaxValue);

        Assert.True(success.IsSuccess);
        Assert.True(success.IsReadable);
        Assert.False(unavailable.IsSuccess);
        Assert.False(unavailable.IsReadable);
    }

    [Fact]
    public void Phase9AdminApisRemainSpanFirst()
    {
        Assert.NotNull(typeof(Pkcs11Module).GetMethod(nameof(Pkcs11Module.CloseAllSessions), [typeof(Pkcs11SlotId)]));
        Assert.NotNull(typeof(Pkcs11Module).GetMethod(nameof(Pkcs11Module.InitToken), [typeof(Pkcs11SlotId), typeof(ReadOnlySpan<byte>), typeof(ReadOnlySpan<byte>)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.InitPin), [typeof(ReadOnlySpan<byte>)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.SetPin), [typeof(ReadOnlySpan<byte>), typeof(ReadOnlySpan<byte>)]));
    }

    [Fact]
    public void Phase10DigestAndRandomApisRemainSpanFirst()
    {
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.GetDigestOutputLength), [typeof(Pkcs11Mechanism), typeof(ReadOnlySpan<byte>)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.TryDigest), [typeof(Pkcs11Mechanism), typeof(ReadOnlySpan<byte>), typeof(Span<byte>), typeof(int).MakeByRefType()]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.DigestInit), [typeof(Pkcs11Mechanism)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.DigestUpdate), [typeof(ReadOnlySpan<byte>)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.TryDigestFinal), [typeof(Span<byte>), typeof(int).MakeByRefType()]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.GenerateRandom), [typeof(Span<byte>)]));
    }

    [Fact]
    public void Phase11MultipartSignAndVerifyApisRemainSpanFirst()
    {
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.SignInit), [typeof(Pkcs11ObjectHandle), typeof(Pkcs11Mechanism)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.SignInit), [typeof(Pkcs11ObjectSearchParameters), typeof(Pkcs11Mechanism)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.SignUpdate), [typeof(ReadOnlySpan<byte>)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.TrySignFinal), [typeof(Span<byte>), typeof(int).MakeByRefType()]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.VerifyInit), [typeof(Pkcs11ObjectHandle), typeof(Pkcs11Mechanism)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.VerifyInit), [typeof(Pkcs11ObjectSearchParameters), typeof(Pkcs11Mechanism)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.VerifyUpdate), [typeof(ReadOnlySpan<byte>)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.VerifyFinal), [typeof(ReadOnlySpan<byte>)]));
    }

    [Fact]
    public void Phase12KeyGenerationApisRemainSpanFirst()
    {
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.GenerateKey), [typeof(Pkcs11Mechanism), typeof(ReadOnlySpan<Pkcs11ObjectAttribute>)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.GenerateKeyPair), [typeof(Pkcs11Mechanism), typeof(ReadOnlySpan<Pkcs11ObjectAttribute>), typeof(ReadOnlySpan<Pkcs11ObjectAttribute>)]));

        Assert.Equal(typeof(Pkcs11ObjectHandle), typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.GenerateKey), [typeof(Pkcs11Mechanism), typeof(ReadOnlySpan<Pkcs11ObjectAttribute>)])!.ReturnType);
        Assert.Equal(typeof(Pkcs11GeneratedKeyPair), typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.GenerateKeyPair), [typeof(Pkcs11Mechanism), typeof(ReadOnlySpan<Pkcs11ObjectAttribute>), typeof(ReadOnlySpan<Pkcs11ObjectAttribute>)])!.ReturnType);
    }

    [Fact]
    public void Phase13WrapUnwrapDeriveApisRemainSpanFirst()
    {
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.GetWrapOutputLength), [typeof(Pkcs11ObjectHandle), typeof(Pkcs11Mechanism), typeof(Pkcs11ObjectHandle)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.TryWrapKey), [typeof(Pkcs11ObjectHandle), typeof(Pkcs11Mechanism), typeof(Pkcs11ObjectHandle), typeof(Span<byte>), typeof(int).MakeByRefType()]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.UnwrapKey), [typeof(Pkcs11ObjectHandle), typeof(Pkcs11Mechanism), typeof(ReadOnlySpan<byte>), typeof(ReadOnlySpan<Pkcs11ObjectAttribute>)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.DeriveKey), [typeof(Pkcs11ObjectHandle), typeof(Pkcs11Mechanism), typeof(ReadOnlySpan<Pkcs11ObjectAttribute>)]));

        Assert.Equal(typeof(int), typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.GetWrapOutputLength), [typeof(Pkcs11ObjectHandle), typeof(Pkcs11Mechanism), typeof(Pkcs11ObjectHandle)])!.ReturnType);
        Assert.Equal(typeof(bool), typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.TryWrapKey), [typeof(Pkcs11ObjectHandle), typeof(Pkcs11Mechanism), typeof(Pkcs11ObjectHandle), typeof(Span<byte>), typeof(int).MakeByRefType()])!.ReturnType);
        Assert.Equal(typeof(Pkcs11ObjectHandle), typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.UnwrapKey), [typeof(Pkcs11ObjectHandle), typeof(Pkcs11Mechanism), typeof(ReadOnlySpan<byte>), typeof(ReadOnlySpan<Pkcs11ObjectAttribute>)])!.ReturnType);
        Assert.Equal(typeof(Pkcs11ObjectHandle), typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.DeriveKey), [typeof(Pkcs11ObjectHandle), typeof(Pkcs11Mechanism), typeof(ReadOnlySpan<Pkcs11ObjectAttribute>)])!.ReturnType);
    }

    [Fact]
    public void ProvisioningHelpersExposeExpectedDefaults()
    {
        Pkcs11ObjectAttribute[] aes = Pkcs11ProvisioningTemplates.CreateAesEncryptDecryptSecretKey("aes"u8, [0xA1], token: false, extractable: true, valueLength: 24);
        Pkcs11ObjectAttribute[] unwrapTarget = Pkcs11ProvisioningTemplates.CreateAesUnwrapTargetSecretKey("dst"u8, [0xB2], token: false);
        Pkcs11KeyPairTemplate rsa = Pkcs11ProvisioningTemplates.CreateRsaSignVerifyKeyPair("rsa"u8, [0xC3]);
        Pkcs11KeyPairTemplate ec = Pkcs11ProvisioningTemplates.CreateEcDeriveKeyPair(Pkcs11EcNamedCurves.Prime256v1Parameters, "ec"u8, [0xD4], token: false);

        Assert.Equal(11, aes.Length);
        Assert.Equal(Pkcs11AttributeTypes.ValueLen, aes[^1].Type);
        Assert.Equal(10, unwrapTarget.Length);
        Assert.Equal(9, rsa.PublicKeyAttributes.Length);
        Assert.Equal(9, rsa.PrivateKeyAttributes.Length);
        Assert.Equal(8, ec.PublicKeyAttributes.Length);
        Assert.Equal(10, ec.PrivateKeyAttributes.Length);
        Assert.Equal([0x01, 0x00, 0x01], rsa.PublicKeyAttributes[^1].Value.ToArray());
        Assert.Equal(Pkcs11AttributeTypes.EcParams, ec.PublicKeyAttributes[^1].Type);
    }

    [Fact]
    public void EcHelpersExposeNamedCurveAndEcdhParameterPacking()
    {
        byte[] ecPointAttribute = [0x04, 0x03, 0x04, 0xAA, 0xBB];
        byte[] decodedPoint = Pkcs11EcNamedCurves.DecodeEcPointAttribute(ecPointAttribute);
        byte[] packed = Pkcs11MechanismParameters.Ecdh1Derive(Pkcs11EcKdfTypes.Null, decodedPoint, [0x11, 0x22]);

        Assert.Equal([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07], Pkcs11EcNamedCurves.Prime256v1Parameters);
        Assert.Equal([0x04, 0xAA, 0xBB], decodedPoint);
        Assert.Equal(IntPtr.Size * 3 + 5, packed.Length);
        Assert.Equal((nuint)0x00000001u, Pkcs11EcKdfTypes.Null.Value);
    }
}
