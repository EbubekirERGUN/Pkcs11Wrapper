using Pkcs11Wrapper;
using Pkcs11Wrapper.Native;
using Pkcs11Wrapper.Native.Interop;

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
    public void InitializeFlagsAndModuleOverloadMatchPkcs11Constants()
    {
        Assert.Equal(0x00000001ul, (ulong)Pkcs11InitializeFlags.LibraryCannotCreateOsThreads);
        Assert.Equal(0x00000002ul, (ulong)Pkcs11InitializeFlags.UseOperatingSystemLocking);
        Assert.NotNull(typeof(Pkcs11Module).GetMethod(nameof(Pkcs11Module.Initialize), [typeof(Pkcs11InitializeOptions)]));
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
        Assert.Equal((nuint)0x00000001u, Pkcs11MechanismTypes.RsaPkcs.Value);
        Assert.Equal((nuint)0x00000003u, Pkcs11MechanismTypes.RsaX509.Value);
        Assert.Equal((nuint)0x00000006u, Pkcs11MechanismTypes.Sha1RsaPkcs.Value);
        Assert.Equal((nuint)0x00000009u, Pkcs11MechanismTypes.RsaPkcsOaep.Value);
        Assert.Equal((nuint)0x0000000du, Pkcs11MechanismTypes.RsaPkcsPss.Value);
        Assert.Equal((nuint)0x0000000eu, Pkcs11MechanismTypes.Sha1RsaPkcsPss.Value);
        Assert.Equal((nuint)0x00000046u, Pkcs11MechanismTypes.Sha224RsaPkcs.Value);
        Assert.Equal((nuint)0x00000047u, Pkcs11MechanismTypes.Sha224RsaPkcsPss.Value);
        Assert.Equal((nuint)0x00001040u, Pkcs11MechanismTypes.EcKeyPairGen.Value);
        Assert.Equal((nuint)0x00001041u, Pkcs11MechanismTypes.Ecdsa.Value);
        Assert.Equal((nuint)0x00001042u, Pkcs11MechanismTypes.EcdsaSha1.Value);
        Assert.Equal((nuint)0x00001045u, Pkcs11MechanismTypes.EcdsaSha224.Value);
        Assert.Equal((nuint)0x00001046u, Pkcs11MechanismTypes.EcdsaSha256.Value);
        Assert.Equal((nuint)0x00001047u, Pkcs11MechanismTypes.EcdsaSha384.Value);
        Assert.Equal((nuint)0x00001048u, Pkcs11MechanismTypes.EcdsaSha512.Value);
        Assert.Equal((nuint)0x00001050u, Pkcs11MechanismTypes.Ecdh1Derive.Value);
        Assert.Equal((nuint)0x00000350u, Pkcs11MechanismTypes.GenericSecretKeyGen.Value);
        Assert.Equal((nuint)0x00001080u, Pkcs11MechanismTypes.AesKeyGen.Value);
        Assert.Equal((nuint)0x00001081u, Pkcs11MechanismTypes.AesEcb.Value);
        Assert.Equal((nuint)0x00001087u, Pkcs11MechanismTypes.AesGcm.Value);
        Assert.Equal((nuint)0x00001088u, Pkcs11MechanismTypes.AesCcm.Value);
        Assert.Equal((nuint)0x00000220u, Pkcs11MechanismTypes.Sha1.Value);
        Assert.Equal((nuint)0x00000221u, Pkcs11MechanismTypes.Sha1Hmac.Value);
        Assert.Equal((nuint)0x00000255u, Pkcs11MechanismTypes.Sha224.Value);
        Assert.Equal((nuint)0x00000256u, Pkcs11MechanismTypes.Sha224Hmac.Value);
        Assert.Equal((nuint)0x00000250u, Pkcs11MechanismTypes.Sha256.Value);
        Assert.Equal((nuint)0x00000251u, Pkcs11MechanismTypes.Sha256Hmac.Value);
        Assert.Equal((nuint)0x00000260u, Pkcs11MechanismTypes.Sha384.Value);
        Assert.Equal((nuint)0x00000261u, Pkcs11MechanismTypes.Sha384Hmac.Value);
        Assert.Equal((nuint)0x00000270u, Pkcs11MechanismTypes.Sha512.Value);
        Assert.Equal((nuint)0x00000271u, Pkcs11MechanismTypes.Sha512Hmac.Value);
        Assert.Equal((nuint)0x00001082u, Pkcs11MechanismTypes.AesCbc.Value);
        Assert.Equal((nuint)0x00001086u, Pkcs11MechanismTypes.AesCtr.Value);
        Assert.Equal((nuint)0x0000210au, Pkcs11MechanismTypes.AesKeyWrapPad.Value);
        Assert.Equal((nuint)0x00000041u, Pkcs11MechanismTypes.Sha384RsaPkcs.Value);
        Assert.Equal((nuint)0x00000042u, Pkcs11MechanismTypes.Sha512RsaPkcs.Value);
        Assert.Equal((nuint)0x00000040u, Pkcs11MechanismTypes.Sha256RsaPkcs.Value);
        Assert.Equal((nuint)0x00000043u, Pkcs11MechanismTypes.Sha256RsaPkcsPss.Value);
        Assert.Equal((nuint)0x00000044u, Pkcs11MechanismTypes.Sha384RsaPkcsPss.Value);
        Assert.Equal((nuint)0x00000045u, Pkcs11MechanismTypes.Sha512RsaPkcsPss.Value);
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
    public void ObjectSearchBuilderBuildsExpectedFilters()
    {
        byte[] label = [0x01, 0x02, 0x03];
        byte[] id = [0x10, 0x11];

        Pkcs11ObjectSearchParameters search = Pkcs11ObjectSearchParameters.CreateBuilder()
            .WithLabel(label)
            .WithId(id)
            .WithObjectClass(Pkcs11ObjectClasses.SecretKey)
            .WithKeyType(Pkcs11KeyTypes.Aes)
            .RequireEncrypt()
            .RequireDecrypt()
            .Build();

        Assert.Equal(label, search.Label.ToArray());
        Assert.Equal(id, search.Id.ToArray());
        Assert.Equal(Pkcs11ObjectClasses.SecretKey, search.ObjectClass);
        Assert.Equal(Pkcs11KeyTypes.Aes, search.KeyType);
        Assert.Equal(true, search.RequireEncrypt);
        Assert.Equal(true, search.RequireDecrypt);
        Assert.Null(search.RequireSign);
        Assert.Null(search.RequireVerify);
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
    public void Phase14CopySeedAndSlotEventApisRemainSpanFirst()
    {
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.CopyObject), [typeof(Pkcs11ObjectHandle), typeof(ReadOnlySpan<Pkcs11ObjectAttribute>)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.SeedRandom), [typeof(ReadOnlySpan<byte>)]));
        Assert.NotNull(typeof(Pkcs11Module).GetMethod(nameof(Pkcs11Module.WaitForSlotEvent), Type.EmptyTypes));
        Assert.NotNull(typeof(Pkcs11Module).GetMethod(nameof(Pkcs11Module.TryWaitForSlotEvent), [typeof(Pkcs11SlotId).MakeByRefType()]));

        Assert.Equal(typeof(Pkcs11ObjectHandle), typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.CopyObject), [typeof(Pkcs11ObjectHandle), typeof(ReadOnlySpan<Pkcs11ObjectAttribute>)])!.ReturnType);
        Assert.Equal(typeof(void), typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.SeedRandom), [typeof(ReadOnlySpan<byte>)])!.ReturnType);
        Assert.Equal(typeof(Pkcs11SlotId), typeof(Pkcs11Module).GetMethod(nameof(Pkcs11Module.WaitForSlotEvent), Type.EmptyTypes)!.ReturnType);
        Assert.Equal(typeof(bool), typeof(Pkcs11Module).GetMethod(nameof(Pkcs11Module.TryWaitForSlotEvent), [typeof(Pkcs11SlotId).MakeByRefType()])!.ReturnType);
    }

    [Fact]
    public void Phase15RecoverAndCombinedUpdateApisRemainSpanFirst()
    {
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.DigestKey), [typeof(Pkcs11ObjectHandle)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.DigestKey), [typeof(Pkcs11ObjectSearchParameters)]));

        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.SignRecoverInit), [typeof(Pkcs11ObjectHandle), typeof(Pkcs11Mechanism)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.SignRecoverInit), [typeof(Pkcs11ObjectSearchParameters), typeof(Pkcs11Mechanism)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.GetSignRecoverOutputLength), [typeof(ReadOnlySpan<byte>)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.TrySignRecover), [typeof(ReadOnlySpan<byte>), typeof(Span<byte>), typeof(int).MakeByRefType()]));

        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.VerifyRecoverInit), [typeof(Pkcs11ObjectHandle), typeof(Pkcs11Mechanism)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.VerifyRecoverInit), [typeof(Pkcs11ObjectSearchParameters), typeof(Pkcs11Mechanism)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.GetVerifyRecoverOutputLength), [typeof(ReadOnlySpan<byte>)]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.TryVerifyRecover), [typeof(ReadOnlySpan<byte>), typeof(Span<byte>), typeof(int).MakeByRefType()]));

        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.TryDigestEncryptUpdate), [typeof(ReadOnlySpan<byte>), typeof(Span<byte>), typeof(int).MakeByRefType()]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.TryDecryptDigestUpdate), [typeof(ReadOnlySpan<byte>), typeof(Span<byte>), typeof(int).MakeByRefType()]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.TrySignEncryptUpdate), [typeof(ReadOnlySpan<byte>), typeof(Span<byte>), typeof(int).MakeByRefType()]));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.TryDecryptVerifyUpdate), [typeof(ReadOnlySpan<byte>), typeof(Span<byte>), typeof(int).MakeByRefType()]));

        Assert.Equal(typeof(void), typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.DigestKey), [typeof(Pkcs11ObjectHandle)])!.ReturnType);
        Assert.Equal(typeof(int), typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.GetSignRecoverOutputLength), [typeof(ReadOnlySpan<byte>)])!.ReturnType);
        Assert.Equal(typeof(bool), typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.TrySignRecover), [typeof(ReadOnlySpan<byte>), typeof(Span<byte>), typeof(int).MakeByRefType()])!.ReturnType);
        Assert.Equal(typeof(int), typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.GetVerifyRecoverOutputLength), [typeof(ReadOnlySpan<byte>)])!.ReturnType);
        Assert.Equal(typeof(bool), typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.TryVerifyRecover), [typeof(ReadOnlySpan<byte>), typeof(Span<byte>), typeof(int).MakeByRefType()])!.ReturnType);
    }

    [Fact]
    public void Phase16FunctionStatusAndCancelApisAreExposed()
    {
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.TryGetFunctionStatus), Type.EmptyTypes));
        Assert.NotNull(typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.TryCancelFunction), Type.EmptyTypes));
        Assert.NotNull(typeof(Pkcs11Module).GetProperty(nameof(Pkcs11Module.FunctionListVersion)));

        Assert.Equal(typeof(bool), typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.TryGetFunctionStatus), Type.EmptyTypes)!.ReturnType);
        Assert.Equal(typeof(bool), typeof(Pkcs11Session).GetMethod(nameof(Pkcs11Session.TryCancelFunction), Type.EmptyTypes)!.ReturnType);
        Assert.Equal(typeof(CK_VERSION), typeof(Pkcs11Module).GetProperty(nameof(Pkcs11Module.FunctionListVersion))!.PropertyType);
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

    [Fact]
    public void MechanismParameterHelpersExposeExpectedPackingAndDefaults()
    {
        byte[] ctr = Pkcs11MechanismParameters.AesCtr([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01], counterBits: 32);
        byte[] ccm = Pkcs11MechanismParameters.AesCcm(64, [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5], [0x01, 0x02], macLength: 16);
        byte[] gcm = Pkcs11MechanismParameters.AesGcm([0x01, 0x02, 0x03, 0x04], [0xAA, 0xBB], tagBits: 96);
        byte[] oaep = Pkcs11MechanismParameters.RsaOaep(Pkcs11MechanismTypes.Sha256, Pkcs11RsaMgfTypes.Mgf1Sha256, [0x10, 0x20]);
        byte[] pss = Pkcs11MechanismParameters.RsaPss(Pkcs11MechanismTypes.Sha384, Pkcs11RsaMgfTypes.Mgf1Sha384, 48);

        Assert.Equal(IntPtr.Size + 16, ctr.Length);
        Assert.Equal(IntPtr.Size * 4 + 8, ccm.Length);
        Assert.Equal(IntPtr.Size * 4 + 6, gcm.Length);
        Assert.Equal(IntPtr.Size * 4 + 2, oaep.Length);
        Assert.Equal(IntPtr.Size * 3, pss.Length);
        Assert.Equal((nuint)0x00000002u, Pkcs11RsaMgfTypes.Mgf1Sha256.Value);
        Assert.Equal((nuint)0x00000001u, Pkcs11RsaOaepSourceTypes.DataSpecified.Value);
    }

    [Fact]
    public void ReturnValueTaxonomyClassifiesKnownAndUnknownCodes()
    {
        Pkcs11ErrorMetadata success = Pkcs11ReturnValueTaxonomy.Classify(CK_RV.Ok);
        Pkcs11ErrorMetadata pinIncorrect = Pkcs11ReturnValueTaxonomy.Classify(new CK_RV(0x000000a0u));
        Pkcs11ErrorMetadata unknown = Pkcs11ReturnValueTaxonomy.Classify(new CK_RV(0xf00dbabEu));

        Assert.Equal(Pkcs11ErrorCategory.Success, success.Category);
        Assert.False(success.IsRetryable);
        Assert.Equal(Pkcs11ErrorCategory.Authentication, pinIncorrect.Category);
        Assert.False(pinIncorrect.IsRetryable);
        Assert.Equal(Pkcs11ErrorMetadata.Unknown, unknown);
    }

    [Theory]
    [InlineData(0x00000190u, Pkcs11ErrorCategory.Lifecycle, true)]
    [InlineData(0x00000191u, Pkcs11ErrorCategory.StateConflict, false)]
    [InlineData(0x00000150u, Pkcs11ErrorCategory.InputValidation, true)]
    [InlineData(0x00000101u, Pkcs11ErrorCategory.Authentication, true)]
    [InlineData(0x00000082u, Pkcs11ErrorCategory.ObjectHandle, false)]
    [InlineData(0x00000051u, Pkcs11ErrorCategory.Capability, false)]
    [InlineData(0x00000070u, Pkcs11ErrorCategory.Capability, false)]
    [InlineData(0x000000b1u, Pkcs11ErrorCategory.Resource, true)]
    [InlineData(0x000000e0u, Pkcs11ErrorCategory.Device, true)]
    [InlineData(0x000000b0u, Pkcs11ErrorCategory.Session, true)]
    [InlineData(0x000000c0u, Pkcs11ErrorCategory.Integrity, false)]
    public void ReturnValueTaxonomyClassifiesRepresentativeCodes(uint rawResult, Pkcs11ErrorCategory expectedCategory, bool expectedRetryable)
    {
        Pkcs11ErrorMetadata metadata = Pkcs11ReturnValueTaxonomy.Classify(new CK_RV((nuint)rawResult));

        Assert.Equal(expectedCategory, metadata.Category);
        Assert.Equal(expectedRetryable, metadata.IsRetryable);
    }

    [Fact]
    public void Pkcs11ExceptionExposesRawResultAndTaxonomyMetadata()
    {
        Pkcs11Exception exception = new("C_Login", new CK_RV(0x000000a0u));

        Assert.Equal("C_Login", exception.Operation);
        Assert.Equal(0x000000a0u, exception.Result.Value);
        Assert.Equal(exception.Result, exception.RawResult);
        Assert.Equal(Pkcs11ErrorCategory.Authentication, exception.ErrorCategory);
        Assert.False(exception.IsRetryable);
        Assert.Equal(Pkcs11ErrorCategory.Authentication, exception.ErrorMetadata.Category);
    }

    [Fact]
    public void Pkcs11ExceptionUsesUnknownMetadataForUnknownReturnValues()
    {
        Pkcs11Exception exception = new("C_VendorExtension", new CK_RV(0xf00dbabEu));

        Assert.Equal(Pkcs11ErrorCategory.Unknown, exception.ErrorCategory);
        Assert.False(exception.IsRetryable);
        Assert.Equal(Pkcs11ErrorMetadata.Unknown, exception.ErrorMetadata);
        Assert.Equal((nuint)0xf00dbabEu, exception.RawResult.Value);
    }
}
