using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Pkcs11Wrapper;
using Pkcs11Wrapper.Native;

namespace Pkcs11Wrapper.Native.Tests;

public sealed class SoftHsmCryptRegressionTests
{
    [Fact]
    public void SinglePartSha256DigestMatchesManagedHash()
    {
        if (!TryCreateCryptContext(out TestContext? context))
        {
            return;
        }

        using TestContext activeContext = context!;
        byte[] data = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("PKCS11_DIGEST_DATA") ?? "pkcs11-wrapper-digest-regression");
        Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.Sha256, ParseHex(Environment.GetEnvironmentVariable("PKCS11_DIGEST_MECHANISM_PARAM_HEX"), Convert.FromHexString));

        byte[] digest = new byte[activeContext.Session.GetDigestOutputLength(mechanism, data)];
        Assert.True(activeContext.Session.TryDigest(mechanism, data, digest, out int written));
        Assert.Equal(SHA256.HashData(data), digest.AsSpan(0, written).ToArray());
    }

    [Fact]
    public void MultipartDigestMatchesSinglePartDigest()
    {
        if (!TryCreateCryptContext(out TestContext? context))
        {
            return;
        }

        using TestContext activeContext = context!;
        byte[] data = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("PKCS11_DIGEST_DATA") ?? "pkcs11-wrapper-digest-regression");
        int splitIndex = Math.Max(1, data.Length / 2);
        Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.Sha256, ParseHex(Environment.GetEnvironmentVariable("PKCS11_DIGEST_MECHANISM_PARAM_HEX"), Convert.FromHexString));

        byte[] singlePart = new byte[activeContext.Session.GetDigestOutputLength(mechanism, data)];
        Assert.True(activeContext.Session.TryDigest(mechanism, data, singlePart, out int singlePartWritten));

        activeContext.Session.DigestInit(mechanism);
        activeContext.Session.DigestUpdate(data.AsSpan(0, splitIndex));
        activeContext.Session.DigestUpdate(ReadOnlySpan<byte>.Empty);
        activeContext.Session.DigestUpdate(data.AsSpan(splitIndex));

        Span<byte> tooSmall = stackalloc byte[Math.Max(singlePartWritten - 1, 0)];
        if (singlePartWritten > 0)
        {
            Assert.False(activeContext.Session.TryDigestFinal(tooSmall, out int requiredLength));
            Assert.Equal(singlePartWritten, requiredLength);
        }

        byte[] multipart = new byte[singlePartWritten];
        Assert.True(activeContext.Session.TryDigestFinal(multipart, out int multipartWritten));
        Assert.Equal(singlePartWritten, multipartWritten);
        Assert.True(singlePart.AsSpan(0, singlePartWritten).SequenceEqual(multipart));
    }

    [Fact]
    public void GenerateRandomProducesRequestedLengthAndDistinctNonZeroOutput()
    {
        if (!TryCreateCryptContext(out TestContext? context))
        {
            return;
        }

        using TestContext activeContext = context!;
        int length = int.TryParse(Environment.GetEnvironmentVariable("PKCS11_RANDOM_LENGTH"), out int parsedLength) && parsedLength > 0
            ? parsedLength
            : 32;

        byte[] first = new byte[length];
        byte[] second = new byte[length];
        activeContext.Session.GenerateRandom(first);
        activeContext.Session.GenerateRandom(second);

        Assert.Equal(length, first.Length);
        Assert.Equal(length, second.Length);
        Assert.Contains(first, static value => value != 0);
        Assert.Contains(second, static value => value != 0);
        Assert.False(first.AsSpan().SequenceEqual(second));
    }

    [Fact]
    public void MultipartEncryptDecryptAndOperationStateRoundTripWithAesCbc()
    {
        if (!TryCreateCryptContext(out TestContext? context))
        {
            return;
        }

        using TestContext activeContext = context!;
        {
            byte[] iv = ParseExactHex(Environment.GetEnvironmentVariable("PKCS11_MULTIPART_IV_HEX") ?? "00112233445566778899AABBCCDDEEFF", 16);
            byte[] plaintext = ParseExactHex(Environment.GetEnvironmentVariable("PKCS11_MULTIPART_PLAINTEXT_HEX") ?? "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", 32);
            Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.AesCbc, iv);

            byte[] baselineCiphertext = EncryptMultipart(activeContext.Session, activeContext.KeyHandle, mechanism, plaintext.AsSpan(0, 16), plaintext.AsSpan(16, 16));

            activeContext.Session.EncryptInit(activeContext.KeyHandle, mechanism);
            Span<byte> firstChunkOutput = stackalloc byte[16];
            Assert.True(activeContext.Session.TryEncryptUpdate(plaintext.AsSpan(0, 16), firstChunkOutput, out int firstChunkWritten));
            Assert.Equal(16, firstChunkWritten);

            int stateLength;
            try
            {
                stateLength = activeContext.Session.GetOperationStateLength();
            }
            catch (Pkcs11Exception ex) when (IsOperationStateUnavailable(ex))
            {
                return;
            }

            Assert.True(stateLength > 0);

            Assert.False(activeContext.Session.TryGetOperationState(Span<byte>.Empty, out int requiredStateLength));
            Assert.Equal(stateLength, requiredStateLength);

            byte[] operationState = new byte[stateLength];
            Assert.True(activeContext.Session.TryGetOperationState(operationState, out int stateWritten));
            Assert.Equal(stateLength, stateWritten);

            using Pkcs11Session resumedSession = activeContext.Module.OpenSession(activeContext.SlotId);
            LoginUser(resumedSession, activeContext.PinUtf8);

            resumedSession.SetOperationState(operationState, encryptionKeyHandle: activeContext.KeyHandle);

            byte[] resumedCiphertext = new byte[32];
            firstChunkOutput[..firstChunkWritten].CopyTo(resumedCiphertext);
            Assert.True(resumedSession.TryEncryptUpdate(plaintext.AsSpan(16, 16), resumedCiphertext.AsSpan(firstChunkWritten), out int secondChunkWritten));
            Assert.Equal(16, secondChunkWritten);
            Assert.True(resumedSession.TryEncryptFinal(Span<byte>.Empty, out int finalWritten));
            Assert.Equal(0, finalWritten);
            resumedSession.Logout();

            Assert.True(baselineCiphertext.AsSpan().SequenceEqual(resumedCiphertext.AsSpan(0, firstChunkWritten + secondChunkWritten + finalWritten)));

            byte[] decrypted = DecryptMultipart(activeContext.Session, activeContext.KeyHandle, mechanism, baselineCiphertext.AsSpan(0, 16), baselineCiphertext.AsSpan(16, 16));
            Assert.True(plaintext.AsSpan().SequenceEqual(decrypted));
        }
    }

    [Fact]
    public void MultipartUpdateAndFinalPreserveBufferTooSmallSemantics()
    {
        if (!TryCreateCryptContext(out TestContext? context))
        {
            return;
        }

        using TestContext activeContext = context!;
        {
            byte[] iv = ParseExactHex(Environment.GetEnvironmentVariable("PKCS11_MULTIPART_IV_HEX") ?? "00112233445566778899AABBCCDDEEFF", 16);
            Pkcs11Mechanism aesCbc = new(Pkcs11MechanismTypes.AesCbc, iv);
            byte[] block = ParseExactHex(Environment.GetEnvironmentVariable("PKCS11_MULTIPART_BUFFER_BLOCK_HEX") ?? "202122232425262728292A2B2C2D2E2F", 16);

            activeContext.Session.EncryptInit(activeContext.KeyHandle, aesCbc);
            Span<byte> tooSmallUpdateBuffer = stackalloc byte[15];
            Assert.False(activeContext.Session.TryEncryptUpdate(block, tooSmallUpdateBuffer, out int requiredUpdateLength));
            Assert.Equal(16, requiredUpdateLength);

            Span<byte> exactUpdateBuffer = stackalloc byte[16];
            Assert.True(activeContext.Session.TryEncryptUpdate(block, exactUpdateBuffer, out int updateWritten));
            Assert.Equal(16, updateWritten);
            Assert.True(activeContext.Session.TryEncryptFinal(Span<byte>.Empty, out int encryptFinalWritten));
            Assert.Equal(0, encryptFinalWritten);

            Pkcs11Mechanism aesCbcPad = new(Pkcs11MechanismTypes.AesCbcPad, iv);
            byte[] padPlaintext = ParseExactHex(Environment.GetEnvironmentVariable("PKCS11_MULTIPART_PAD_PLAINTEXT_HEX") ?? "30313233343536373839414243444546", 16);

            using Pkcs11Session finalSession = activeContext.Module.OpenSession(activeContext.SlotId);
            LoginUser(finalSession, activeContext.PinUtf8);

            finalSession.EncryptInit(activeContext.KeyHandle, aesCbcPad);
            byte[] padUpdateCiphertext = new byte[16];
            Assert.True(finalSession.TryEncryptUpdate(padPlaintext, padUpdateCiphertext, out int padUpdateWritten));
            Assert.Equal(16, padUpdateWritten);

            Span<byte> tooSmallFinalBuffer = stackalloc byte[15];
            Assert.False(finalSession.TryEncryptFinal(tooSmallFinalBuffer, out int requiredFinalLength));
            Assert.Equal(16, requiredFinalLength);

            byte[] finalCiphertext = new byte[requiredFinalLength];
            Assert.True(finalSession.TryEncryptFinal(finalCiphertext, out int finalWritten));
            Assert.Equal(requiredFinalLength, finalWritten);
            finalSession.Logout();
        }
    }

    [Fact]
    public void LengthProbeDoesNotLeaveEncryptOrDecryptOperationActive()
    {
        string? mechanismText = Environment.GetEnvironmentVariable("PKCS11_MECHANISM");
        if (string.IsNullOrWhiteSpace(mechanismText) || !TryCreateCryptContext(out TestContext? context))
        {
            return;
        }

        using TestContext activeContext = context!;
        {
            Pkcs11ObjectSearchParameters search = new(
                label: ParseHex(Environment.GetEnvironmentVariable("PKCS11_FIND_LABEL"), Encoding.UTF8.GetBytes),
                id: ParseHex(Environment.GetEnvironmentVariable("PKCS11_FIND_ID_HEX"), Convert.FromHexString),
                objectClass: ParseObjectClass(Environment.GetEnvironmentVariable("PKCS11_FIND_CLASS")!),
                keyType: ParseKeyType(Environment.GetEnvironmentVariable("PKCS11_FIND_KEY_TYPE")!),
                requireEncrypt: ParseNullableBoolean(Environment.GetEnvironmentVariable("PKCS11_REQUIRE_ENCRYPT")),
                requireDecrypt: ParseNullableBoolean(Environment.GetEnvironmentVariable("PKCS11_REQUIRE_DECRYPT")));

            Assert.True(activeContext.Session.TryFindObject(search, out Pkcs11ObjectHandle keyHandle));

            Pkcs11Mechanism mechanism = new(
                new Pkcs11MechanismType(ParseNuint(mechanismText)),
                ParseHex(Environment.GetEnvironmentVariable("PKCS11_MECHANISM_PARAM_HEX"), Convert.FromHexString));

            byte[] plaintext = Encoding.UTF8.GetBytes("pkcs11-wrapper-regression");

            byte[] ciphertext = new byte[activeContext.Session.GetEncryptOutputLength(keyHandle, mechanism, plaintext)];
            Assert.True(activeContext.Session.TryEncrypt(keyHandle, mechanism, plaintext, ciphertext, out int ciphertextWritten));

            byte[] decrypted = new byte[activeContext.Session.GetDecryptOutputLength(keyHandle, mechanism, ciphertext.AsSpan(0, ciphertextWritten))];
            Assert.True(activeContext.Session.TryDecrypt(keyHandle, mechanism, ciphertext.AsSpan(0, ciphertextWritten), decrypted, out int decryptedWritten));
            Assert.True(plaintext.AsSpan().SequenceEqual(decrypted.AsSpan(0, decryptedWritten)));
        }
    }

    [Fact]
    public void LengthProbeDoesNotLeaveSignOperationActiveAndVerifyReturnsFalseForInvalidSignature()
    {
        string? modulePath = Environment.GetEnvironmentVariable("PKCS11_MODULE_PATH");
        string? tokenLabel = Environment.GetEnvironmentVariable("PKCS11_TOKEN_LABEL");
        string? userPin = Environment.GetEnvironmentVariable("PKCS11_USER_PIN");
        string? signMechanismText = Environment.GetEnvironmentVariable("PKCS11_SIGN_MECHANISM");
        string? signClass = Environment.GetEnvironmentVariable("PKCS11_SIGN_FIND_CLASS");
        string? signKeyType = Environment.GetEnvironmentVariable("PKCS11_SIGN_FIND_KEY_TYPE");
        string? verifyClass = Environment.GetEnvironmentVariable("PKCS11_VERIFY_FIND_CLASS");
        string? verifyKeyType = Environment.GetEnvironmentVariable("PKCS11_VERIFY_FIND_KEY_TYPE");

        if (string.IsNullOrWhiteSpace(modulePath) ||
            string.IsNullOrWhiteSpace(tokenLabel) ||
            string.IsNullOrWhiteSpace(userPin) ||
            string.IsNullOrWhiteSpace(signMechanismText) ||
            string.IsNullOrWhiteSpace(signClass) ||
            string.IsNullOrWhiteSpace(signKeyType) ||
            string.IsNullOrWhiteSpace(verifyClass) ||
            string.IsNullOrWhiteSpace(verifyKeyType))
        {
            return;
        }

        using var module = Pkcs11Module.Load(modulePath);
        module.Initialize();

        Pkcs11SlotId slotId = FindSlotByTokenLabel(module, tokenLabel);
        using Pkcs11Session session = module.OpenSession(slotId);
        session.Login(Pkcs11UserType.User, Encoding.UTF8.GetBytes(userPin));

        try
        {
            Pkcs11ObjectSearchParameters signSearch = new(
                label: ParseHex(Environment.GetEnvironmentVariable("PKCS11_SIGN_FIND_LABEL"), Encoding.UTF8.GetBytes),
                id: ParseHex(Environment.GetEnvironmentVariable("PKCS11_SIGN_FIND_ID_HEX"), Convert.FromHexString),
                objectClass: ParseObjectClass(signClass),
                keyType: ParseKeyType(signKeyType),
                requireSign: ParseNullableBoolean(Environment.GetEnvironmentVariable("PKCS11_SIGN_REQUIRE_SIGN")));

            Pkcs11ObjectSearchParameters verifySearch = new(
                label: ParseHex(Environment.GetEnvironmentVariable("PKCS11_VERIFY_FIND_LABEL"), Encoding.UTF8.GetBytes),
                id: ParseHex(Environment.GetEnvironmentVariable("PKCS11_VERIFY_FIND_ID_HEX"), Convert.FromHexString),
                objectClass: ParseObjectClass(verifyClass),
                keyType: ParseKeyType(verifyKeyType),
                requireVerify: ParseNullableBoolean(Environment.GetEnvironmentVariable("PKCS11_VERIFY_REQUIRE_VERIFY")));

            Assert.True(session.TryFindObject(signSearch, out Pkcs11ObjectHandle signKeyHandle));
            Assert.True(session.TryFindObject(verifySearch, out Pkcs11ObjectHandle verifyKeyHandle));

            Pkcs11Mechanism mechanism = new(
                new Pkcs11MechanismType(ParseNuint(signMechanismText)),
                ParseHex(Environment.GetEnvironmentVariable("PKCS11_SIGN_MECHANISM_PARAM_HEX"), Convert.FromHexString));

            byte[] data = Encoding.UTF8.GetBytes("pkcs11-wrapper-sign-regression");
            byte[] signature = new byte[session.GetSignOutputLength(signKeyHandle, mechanism, data)];
            Assert.True(session.TrySign(signKeyHandle, mechanism, data, signature, out int signatureWritten));
            Assert.True(session.Verify(verifyKeyHandle, mechanism, data, signature.AsSpan(0, signatureWritten)));

            signature[0] ^= 0x5a;
            Assert.False(session.Verify(verifyKeyHandle, mechanism, data, signature.AsSpan(0, signatureWritten)));
            Assert.False(session.Verify(verifyKeyHandle, mechanism, data, signature.AsSpan(0, signatureWritten - 1)));
        }
        finally
        {
            session.Logout();
        }
    }

    [Fact]
    public void MultipartSignVerifyMatchesSinglePartAndRejectsInvalidSignatures()
    {
        if (!TryCreateSignVerifyContext(out SignVerifyContext? context))
        {
            return;
        }

        using SignVerifyContext activeContext = context!;
        byte[] data = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("PKCS11_SIGN_DATA") ?? "pkcs11-wrapper-sign-regression");
        int splitIndex = Math.Max(1, data.Length / 2);

        byte[] singlePartSignature = new byte[activeContext.Session.GetSignOutputLength(activeContext.SignKeyHandle, activeContext.Mechanism, data)];
        Assert.True(activeContext.Session.TrySign(activeContext.SignKeyHandle, activeContext.Mechanism, data, singlePartSignature, out int singlePartWritten));

        activeContext.Session.SignInit(activeContext.SignKeyHandle, activeContext.Mechanism);
        activeContext.Session.SignUpdate(data.AsSpan(0, splitIndex));
        activeContext.Session.SignUpdate(ReadOnlySpan<byte>.Empty);
        activeContext.Session.SignUpdate(data.AsSpan(splitIndex));

        Span<byte> tooSmall = stackalloc byte[Math.Max(singlePartWritten - 1, 0)];
        if (singlePartWritten > 0)
        {
            Assert.False(activeContext.Session.TrySignFinal(tooSmall, out int requiredLength));
            Assert.Equal(singlePartWritten, requiredLength);
        }

        byte[] multipartSignature = new byte[singlePartWritten];
        Assert.True(activeContext.Session.TrySignFinal(multipartSignature, out int multipartWritten));
        Assert.Equal(singlePartWritten, multipartWritten);
        Assert.True(singlePartSignature.AsSpan(0, singlePartWritten).SequenceEqual(multipartSignature));

        activeContext.Session.VerifyInit(activeContext.VerifyKeyHandle, activeContext.Mechanism);
        activeContext.Session.VerifyUpdate(data.AsSpan(0, splitIndex));
        activeContext.Session.VerifyUpdate(ReadOnlySpan<byte>.Empty);
        activeContext.Session.VerifyUpdate(data.AsSpan(splitIndex));
        Assert.True(activeContext.Session.VerifyFinal(multipartSignature));

        byte[] invalidSignature = multipartSignature.ToArray();
        invalidSignature[0] ^= 0x5a;

        activeContext.Session.VerifyInit(activeContext.VerifyKeyHandle, activeContext.Mechanism);
        activeContext.Session.VerifyUpdate(data.AsSpan(0, splitIndex));
        activeContext.Session.VerifyUpdate(data.AsSpan(splitIndex));
        Assert.False(activeContext.Session.VerifyFinal(invalidSignature));

        activeContext.Session.VerifyInit(activeContext.VerifyKeyHandle, activeContext.Mechanism);
        activeContext.Session.VerifyUpdate(data.AsSpan(0, splitIndex));
        activeContext.Session.VerifyUpdate(data.AsSpan(splitIndex));
        Assert.False(activeContext.Session.VerifyFinal(multipartSignature.AsSpan(0, multipartWritten - 1)));
    }

    [Fact]
    public void GenerateKeyCreatesSearchableAesTokenKeyAndEncryptDecryptRoundTrips()
    {
        if (!TryCreateGenerateContext(out GenerateContext? context))
        {
            return;
        }

        using GenerateContext activeContext = context!;
        string label = $"phase12-aes-{Guid.NewGuid():N}";
        byte[] labelUtf8 = Encoding.ASCII.GetBytes(label);
        byte[] id = Guid.NewGuid().ToByteArray();
        byte[] iv = ParseExactHex(Environment.GetEnvironmentVariable("PKCS11_GENERATE_AES_IV_HEX") ?? "00112233445566778899AABBCCDDEEFF", 16);
        byte[] plaintext = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("PKCS11_GENERATE_AES_PLAINTEXT") ?? "phase12-generate-aes-smoke");
        Pkcs11Mechanism generationMechanism = new(Pkcs11MechanismTypes.AesKeyGen);
        Pkcs11Mechanism cryptMechanism = new(Pkcs11MechanismTypes.AesCbcPad, iv);
        Pkcs11ObjectHandle generatedHandle = default;
        bool created = false;

        try
        {
            generatedHandle = activeContext.Session.GenerateKey(
                generationMechanism,
                Pkcs11ProvisioningTemplates.CreateAesEncryptDecryptSecretKey(labelUtf8, id, token: true, extractable: false, valueLength: 32));

            created = true;
            Assert.True(generatedHandle.Value != 0);

            Pkcs11ObjectSearchParameters search = new(
                label: labelUtf8,
                id: id,
                objectClass: Pkcs11ObjectClasses.SecretKey,
                keyType: Pkcs11KeyTypes.Aes,
                requireEncrypt: true,
                requireDecrypt: true);

            Assert.True(activeContext.Session.TryFindObject(search, out Pkcs11ObjectHandle locatedHandle));
            Assert.Equal(generatedHandle, locatedHandle);
            Assert.True(activeContext.Session.TryGetAttributeBoolean(generatedHandle, Pkcs11AttributeTypes.Sensitive, out bool sensitive, out Pkcs11AttributeReadResult sensitiveResult));
            Assert.True(sensitiveResult.IsReadable);
            Assert.True(sensitive);
            Assert.True(activeContext.Session.TryGetAttributeBoolean(generatedHandle, Pkcs11AttributeTypes.Extractable, out bool extractable, out Pkcs11AttributeReadResult extractableResult));
            Assert.True(extractableResult.IsReadable);
            Assert.False(extractable);

            byte[] ciphertext = new byte[activeContext.Session.GetEncryptOutputLength(generatedHandle, cryptMechanism, plaintext)];
            Assert.True(activeContext.Session.TryEncrypt(generatedHandle, cryptMechanism, plaintext, ciphertext, out int ciphertextWritten));

            byte[] decrypted = new byte[activeContext.Session.GetDecryptOutputLength(generatedHandle, cryptMechanism, ciphertext.AsSpan(0, ciphertextWritten))];
            Assert.True(activeContext.Session.TryDecrypt(generatedHandle, cryptMechanism, ciphertext.AsSpan(0, ciphertextWritten), decrypted, out int decryptedWritten));
            Assert.True(plaintext.AsSpan().SequenceEqual(decrypted.AsSpan(0, decryptedWritten)));

            activeContext.Session.DestroyObject(generatedHandle);
            created = false;
            Assert.False(activeContext.Session.TryFindObject(search, out _));
        }
        finally
        {
            if (created)
            {
                TryDestroyObject(activeContext.Session, generatedHandle);
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: labelUtf8, id: id, objectClass: Pkcs11ObjectClasses.SecretKey, keyType: Pkcs11KeyTypes.Aes));
            }
        }
    }

    [Fact]
    public void GenerateKeyPairCreatesSearchableRsaTokenKeysAndSignVerifyRoundTrips()
    {
        if (!TryCreateGenerateContext(out GenerateContext? context))
        {
            return;
        }

        using GenerateContext activeContext = context!;
        string label = $"phase12-rsa-{Guid.NewGuid():N}";
        byte[] labelUtf8 = Encoding.ASCII.GetBytes(label);
        byte[] id = Guid.NewGuid().ToByteArray();
        byte[] data = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("PKCS11_GENERATE_RSA_SIGN_DATA") ?? "phase12-generate-rsa-smoke");
        Pkcs11Mechanism generationMechanism = new(Pkcs11MechanismTypes.RsaPkcsKeyPairGen);
        Pkcs11Mechanism signMechanism = new(Pkcs11MechanismTypes.Sha256RsaPkcs);
        Pkcs11GeneratedKeyPair keyPair = default;
        bool created = false;

        try
        {
            Pkcs11KeyPairTemplate templates = Pkcs11ProvisioningTemplates.CreateRsaSignVerifyKeyPair(labelUtf8, id, token: true, modulusBits: 2048);
            keyPair = activeContext.Session.GenerateKeyPair(
                generationMechanism,
                templates.PublicKeyAttributes,
                templates.PrivateKeyAttributes);

            created = true;
            Assert.True(keyPair.PublicKeyHandle.Value != 0);
            Assert.True(keyPair.PrivateKeyHandle.Value != 0);

            Pkcs11ObjectSearchParameters publicSearch = new(
                label: labelUtf8,
                id: id,
                objectClass: Pkcs11ObjectClasses.PublicKey,
                keyType: Pkcs11KeyTypes.Rsa,
                requireVerify: true);

            Pkcs11ObjectSearchParameters privateSearch = new(
                label: labelUtf8,
                id: id,
                objectClass: Pkcs11ObjectClasses.PrivateKey,
                keyType: Pkcs11KeyTypes.Rsa,
                requireSign: true);

            Assert.True(activeContext.Session.TryFindObject(publicSearch, out Pkcs11ObjectHandle locatedPublicKey));
            Assert.True(activeContext.Session.TryFindObject(privateSearch, out Pkcs11ObjectHandle locatedPrivateKey));
            Assert.Equal(keyPair.PublicKeyHandle, locatedPublicKey);
            Assert.Equal(keyPair.PrivateKeyHandle, locatedPrivateKey);

            byte[] signature = new byte[activeContext.Session.GetSignOutputLength(keyPair.PrivateKeyHandle, signMechanism, data)];
            Assert.True(activeContext.Session.TrySign(keyPair.PrivateKeyHandle, signMechanism, data, signature, out int signatureWritten));
            Assert.True(activeContext.Session.Verify(keyPair.PublicKeyHandle, signMechanism, data, signature.AsSpan(0, signatureWritten)));

            activeContext.Session.DestroyObject(keyPair.PrivateKeyHandle);
            activeContext.Session.DestroyObject(keyPair.PublicKeyHandle);
            created = false;
            Assert.False(activeContext.Session.TryFindObject(privateSearch, out _));
            Assert.False(activeContext.Session.TryFindObject(publicSearch, out _));
        }
        finally
        {
            if (created)
            {
                TryDestroyObject(activeContext.Session, keyPair.PrivateKeyHandle);
                TryDestroyObject(activeContext.Session, keyPair.PublicKeyHandle);
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: labelUtf8, id: id, objectClass: Pkcs11ObjectClasses.PrivateKey, keyType: Pkcs11KeyTypes.Rsa));
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: labelUtf8, id: id, objectClass: Pkcs11ObjectClasses.PublicKey, keyType: Pkcs11KeyTypes.Rsa));
            }
        }
    }

    [Fact]
    public void WrapAndUnwrapKeyRoundTripWithAesKeyWrapPad()
    {
        if (!TryCreateGenerateContext(out GenerateContext? context))
        {
            return;
        }

        using GenerateContext activeContext = context!;
        byte[] wrappingLabel = Encoding.ASCII.GetBytes(Environment.GetEnvironmentVariable("PKCS11_WRAP_KEY_LABEL") ?? "ci-aes");
        byte[] wrappingId = ParseHex(Environment.GetEnvironmentVariable("PKCS11_WRAP_KEY_ID_HEX") ?? "A1", Convert.FromHexString);
        Pkcs11ObjectSearchParameters wrappingSearch = new(
            label: wrappingLabel,
            id: wrappingId,
            objectClass: Pkcs11ObjectClasses.SecretKey,
            keyType: Pkcs11KeyTypes.Aes,
            requireWrap: true,
            requireUnwrap: true);

        Assert.True(activeContext.Session.TryFindObject(wrappingSearch, out Pkcs11ObjectHandle wrappingKeyHandle));

        string sourceLabel = $"phase13-wrap-src-{Guid.NewGuid():N}";
        string unwrappedLabel = $"phase13-wrap-dst-{Guid.NewGuid():N}";
        byte[] sourceLabelUtf8 = Encoding.ASCII.GetBytes(sourceLabel);
        byte[] unwrappedLabelUtf8 = Encoding.ASCII.GetBytes(unwrappedLabel);
        byte[] sourceId = Guid.NewGuid().ToByteArray();
        byte[] unwrappedId = Guid.NewGuid().ToByteArray();
        byte[] iv = ParseExactHex(Environment.GetEnvironmentVariable("PKCS11_WRAP_UNWRAP_IV_HEX") ?? "00112233445566778899AABBCCDDEEFF", 16);
        byte[] plaintext = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("PKCS11_WRAP_UNWRAP_PLAINTEXT") ?? "phase13-wrap-unwrap-smoke");
        Pkcs11Mechanism keyGenerationMechanism = new(Pkcs11MechanismTypes.AesKeyGen);
        Pkcs11Mechanism wrapMechanism = new(Pkcs11MechanismTypes.AesKeyWrapPad);
        Pkcs11Mechanism cryptMechanism = new(Pkcs11MechanismTypes.AesCbcPad, iv);

        Pkcs11ObjectHandle sourceKeyHandle = default;
        Pkcs11ObjectHandle unwrappedKeyHandle = default;
        bool sourceCreated = false;
        bool unwrappedCreated = false;

        try
        {
            sourceKeyHandle = activeContext.Session.GenerateKey(
                keyGenerationMechanism,
                Pkcs11ProvisioningTemplates.CreateAesEncryptDecryptSecretKey(sourceLabelUtf8, sourceId, token: false, extractable: true, valueLength: 32));

            sourceCreated = true;

            int wrappedLength = activeContext.Session.GetWrapOutputLength(wrappingKeyHandle, wrapMechanism, sourceKeyHandle);
            Assert.True(wrappedLength > 0);

            Span<byte> tooSmallBuffer = stackalloc byte[Math.Max(wrappedLength - 1, 0)];
            if (wrappedLength > 0)
            {
                Assert.False(activeContext.Session.TryWrapKey(wrappingKeyHandle, wrapMechanism, sourceKeyHandle, tooSmallBuffer, out int requiredLength));
                Assert.Equal(wrappedLength, requiredLength);
            }

            byte[] wrappedKey = new byte[wrappedLength];
            Assert.True(activeContext.Session.TryWrapKey(wrappingKeyHandle, wrapMechanism, sourceKeyHandle, wrappedKey, out int written));
            Assert.Equal(wrappedLength, written);

            unwrappedKeyHandle = activeContext.Session.UnwrapKey(
                wrappingKeyHandle,
                wrapMechanism,
                wrappedKey.AsSpan(0, written),
                Pkcs11ProvisioningTemplates.CreateAesUnwrapTargetSecretKey(unwrappedLabelUtf8, unwrappedId, token: false, extractable: false));

            unwrappedCreated = true;
            Assert.True(unwrappedKeyHandle.Value != 0);

            byte[] ciphertext = new byte[activeContext.Session.GetEncryptOutputLength(unwrappedKeyHandle, cryptMechanism, plaintext)];
            Assert.True(activeContext.Session.TryEncrypt(unwrappedKeyHandle, cryptMechanism, plaintext, ciphertext, out int ciphertextWritten));

            byte[] decrypted = new byte[activeContext.Session.GetDecryptOutputLength(unwrappedKeyHandle, cryptMechanism, ciphertext.AsSpan(0, ciphertextWritten))];
            Assert.True(activeContext.Session.TryDecrypt(unwrappedKeyHandle, cryptMechanism, ciphertext.AsSpan(0, ciphertextWritten), decrypted, out int decryptedWritten));
            Assert.True(plaintext.AsSpan().SequenceEqual(decrypted.AsSpan(0, decryptedWritten)));
        }
        finally
        {
            if (unwrappedCreated)
            {
                TryDestroyObject(activeContext.Session, unwrappedKeyHandle);
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: unwrappedLabelUtf8, id: unwrappedId, objectClass: Pkcs11ObjectClasses.SecretKey, keyType: Pkcs11KeyTypes.Aes));
            }

            if (sourceCreated)
            {
                TryDestroyObject(activeContext.Session, sourceKeyHandle);
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: sourceLabelUtf8, id: sourceId, objectClass: Pkcs11ObjectClasses.SecretKey, keyType: Pkcs11KeyTypes.Aes));
            }
        }
    }

    [Fact]
    public void DeriveKeyWithEcdhP256CreatesMatchingAesKeysForRoundTrip()
    {
        if (!TryCreateGenerateContext(out GenerateContext? context))
        {
            return;
        }

        using GenerateContext activeContext = context!;
        string leftLabel = $"phase13-ecdh-left-{Guid.NewGuid():N}";
        string rightLabel = $"phase13-ecdh-right-{Guid.NewGuid():N}";
        byte[] leftLabelUtf8 = Encoding.ASCII.GetBytes(leftLabel);
        byte[] rightLabelUtf8 = Encoding.ASCII.GetBytes(rightLabel);
        byte[] leftId = Guid.NewGuid().ToByteArray();
        byte[] rightId = Guid.NewGuid().ToByteArray();
        byte[] leftDerivedLabel = Encoding.ASCII.GetBytes($"{leftLabel}-aes");
        byte[] rightDerivedLabel = Encoding.ASCII.GetBytes($"{rightLabel}-aes");
        byte[] leftDerivedId = Guid.NewGuid().ToByteArray();
        byte[] rightDerivedId = Guid.NewGuid().ToByteArray();
        byte[] curveParameters = Pkcs11EcNamedCurves.Prime256v1Parameters;
        byte[] iv = ParseExactHex(Environment.GetEnvironmentVariable("PKCS11_DERIVE_EC_IV_HEX") ?? "00112233445566778899AABBCCDDEEFF", 16);
        byte[] plaintext = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("PKCS11_DERIVE_EC_PLAINTEXT") ?? "phase13-derive-ecdh-smoke");
        Pkcs11GeneratedKeyPair leftKeyPair = default;
        Pkcs11GeneratedKeyPair rightKeyPair = default;
        Pkcs11ObjectHandle leftDerivedKeyHandle = default;
        Pkcs11ObjectHandle rightDerivedKeyHandle = default;
        bool leftPairCreated = false;
        bool rightPairCreated = false;
        bool leftDerivedCreated = false;
        bool rightDerivedCreated = false;

        try
        {
            Pkcs11KeyPairTemplate leftTemplates = Pkcs11ProvisioningTemplates.CreateEcDeriveKeyPair(curveParameters, leftLabelUtf8, leftId, token: false);
            Pkcs11KeyPairTemplate rightTemplates = Pkcs11ProvisioningTemplates.CreateEcDeriveKeyPair(curveParameters, rightLabelUtf8, rightId, token: false);
            leftKeyPair = activeContext.Session.GenerateKeyPair(new Pkcs11Mechanism(Pkcs11MechanismTypes.EcKeyPairGen), leftTemplates.PublicKeyAttributes, leftTemplates.PrivateKeyAttributes);
            rightKeyPair = activeContext.Session.GenerateKeyPair(new Pkcs11Mechanism(Pkcs11MechanismTypes.EcKeyPairGen), rightTemplates.PublicKeyAttributes, rightTemplates.PrivateKeyAttributes);
            leftPairCreated = true;
            rightPairCreated = true;

            byte[] leftPublicPoint = Pkcs11EcNamedCurves.DecodeEcPointAttribute(GetRequiredAttributeBytes(activeContext.Session, leftKeyPair.PublicKeyHandle, Pkcs11AttributeTypes.EcPoint));
            byte[] rightPublicPoint = Pkcs11EcNamedCurves.DecodeEcPointAttribute(GetRequiredAttributeBytes(activeContext.Session, rightKeyPair.PublicKeyHandle, Pkcs11AttributeTypes.EcPoint));

            leftDerivedKeyHandle = activeContext.Session.DeriveKey(
                leftKeyPair.PrivateKeyHandle,
                new Pkcs11Mechanism(Pkcs11MechanismTypes.Ecdh1Derive, Pkcs11MechanismParameters.Ecdh1Derive(rightPublicPoint)),
                Pkcs11ProvisioningTemplates.CreateAesEncryptDecryptSecretKey(leftDerivedLabel, leftDerivedId, token: false, extractable: false, valueLength: 32));
            leftDerivedCreated = true;

            rightDerivedKeyHandle = activeContext.Session.DeriveKey(
                rightKeyPair.PrivateKeyHandle,
                new Pkcs11Mechanism(Pkcs11MechanismTypes.Ecdh1Derive, Pkcs11MechanismParameters.Ecdh1Derive(leftPublicPoint)),
                Pkcs11ProvisioningTemplates.CreateAesEncryptDecryptSecretKey(rightDerivedLabel, rightDerivedId, token: false, extractable: false, valueLength: 32));
            rightDerivedCreated = true;

            Pkcs11Mechanism cryptMechanism = new(Pkcs11MechanismTypes.AesCbcPad, iv);
            byte[] ciphertext = new byte[activeContext.Session.GetEncryptOutputLength(leftDerivedKeyHandle, cryptMechanism, plaintext)];
            Assert.True(activeContext.Session.TryEncrypt(leftDerivedKeyHandle, cryptMechanism, plaintext, ciphertext, out int ciphertextWritten));

            byte[] decrypted = new byte[activeContext.Session.GetDecryptOutputLength(rightDerivedKeyHandle, cryptMechanism, ciphertext.AsSpan(0, ciphertextWritten))];
            Assert.True(activeContext.Session.TryDecrypt(rightDerivedKeyHandle, cryptMechanism, ciphertext.AsSpan(0, ciphertextWritten), decrypted, out int decryptedWritten));
            Assert.True(plaintext.AsSpan().SequenceEqual(decrypted.AsSpan(0, decryptedWritten)));
        }
        finally
        {
            if (rightDerivedCreated)
            {
                TryDestroyObject(activeContext.Session, rightDerivedKeyHandle);
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: rightDerivedLabel, id: rightDerivedId, objectClass: Pkcs11ObjectClasses.SecretKey, keyType: Pkcs11KeyTypes.Aes));
            }

            if (leftDerivedCreated)
            {
                TryDestroyObject(activeContext.Session, leftDerivedKeyHandle);
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: leftDerivedLabel, id: leftDerivedId, objectClass: Pkcs11ObjectClasses.SecretKey, keyType: Pkcs11KeyTypes.Aes));
            }

            if (rightPairCreated)
            {
                TryDestroyObject(activeContext.Session, rightKeyPair.PrivateKeyHandle);
                TryDestroyObject(activeContext.Session, rightKeyPair.PublicKeyHandle);
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: rightLabelUtf8, id: rightId, objectClass: Pkcs11ObjectClasses.PrivateKey, keyType: Pkcs11KeyTypes.Ec));
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: rightLabelUtf8, id: rightId, objectClass: Pkcs11ObjectClasses.PublicKey, keyType: Pkcs11KeyTypes.Ec));
            }

            if (leftPairCreated)
            {
                TryDestroyObject(activeContext.Session, leftKeyPair.PrivateKeyHandle);
                TryDestroyObject(activeContext.Session, leftKeyPair.PublicKeyHandle);
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: leftLabelUtf8, id: leftId, objectClass: Pkcs11ObjectClasses.PrivateKey, keyType: Pkcs11KeyTypes.Ec));
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: leftLabelUtf8, id: leftId, objectClass: Pkcs11ObjectClasses.PublicKey, keyType: Pkcs11KeyTypes.Ec));
            }
        }
    }

    [Fact]
    public void DataObjectLifecycleRoundTripsThroughCreateUpdateAndDestroy()
    {
        string? modulePath = Environment.GetEnvironmentVariable("PKCS11_MODULE_PATH");
        string? tokenLabel = Environment.GetEnvironmentVariable("PKCS11_TOKEN_LABEL");
        string? userPin = Environment.GetEnvironmentVariable("PKCS11_USER_PIN");

        if (string.IsNullOrWhiteSpace(modulePath) ||
            string.IsNullOrWhiteSpace(tokenLabel) ||
            string.IsNullOrWhiteSpace(userPin))
        {
            return;
        }

        using var module = Pkcs11Module.Load(modulePath);
        module.Initialize();

        Pkcs11SlotId slotId = FindSlotByTokenLabel(module, tokenLabel);
        using Pkcs11Session session = module.OpenSession(slotId, readWrite: true);

        byte[] pinUtf8 = Encoding.UTF8.GetBytes(userPin);
        LoginUser(session, pinUtf8);

        string label = $"phase7-create-{Guid.NewGuid():N}";
        string updatedLabel = label + "-updated";
        byte[] labelUtf8 = Encoding.UTF8.GetBytes(label);
        byte[] updatedLabelUtf8 = Encoding.UTF8.GetBytes(updatedLabel);
        byte[] applicationUtf8 = Encoding.UTF8.GetBytes("phase7");
        byte[] value = [0x50, 0x37, 0x2D, 0x01];

        Pkcs11ObjectHandle handle = default;
        bool created = false;

        try
        {
            handle = session.CreateObject(
            [
                Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.Data),
                Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, true),
                Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, false),
                Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Modifiable, true),
                Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, labelUtf8),
                Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Application, applicationUtf8),
                Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Value, value)
            ]);

            created = true;
            Assert.True(handle.Value != 0);
            Assert.True(session.GetObjectSize(handle) > 0);

            Assert.True(session.TryFindObject(new Pkcs11ObjectSearchParameters(label: labelUtf8, objectClass: Pkcs11ObjectClasses.Data), out Pkcs11ObjectHandle locatedHandle));
            Assert.Equal(handle, locatedHandle);
            Assert.Equal(label, Encoding.UTF8.GetString(GetRequiredAttributeBytes(session, handle, Pkcs11AttributeTypes.Label)));
            Assert.Equal("phase7", Encoding.UTF8.GetString(GetRequiredAttributeBytes(session, handle, Pkcs11AttributeTypes.Application)));
            Assert.Equal(value, GetRequiredAttributeBytes(session, handle, Pkcs11AttributeTypes.Value));

            session.SetAttributeValue(handle,
            [
                Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, updatedLabelUtf8)
            ]);

            Assert.False(session.TryFindObject(new Pkcs11ObjectSearchParameters(label: labelUtf8, objectClass: Pkcs11ObjectClasses.Data), out _));
            Assert.True(session.TryFindObject(new Pkcs11ObjectSearchParameters(label: updatedLabelUtf8, objectClass: Pkcs11ObjectClasses.Data), out Pkcs11ObjectHandle updatedHandle));
            Assert.Equal(handle, updatedHandle);
            Assert.Equal(updatedLabel, Encoding.UTF8.GetString(GetRequiredAttributeBytes(session, handle, Pkcs11AttributeTypes.Label)));

            session.DestroyObject(handle);
            created = false;

            Assert.False(session.TryFindObject(new Pkcs11ObjectSearchParameters(label: updatedLabelUtf8, objectClass: Pkcs11ObjectClasses.Data), out _));
        }
        finally
        {
            if (created)
            {
                TryDestroyObject(session, handle);
                TryDestroyDataObjectByLabel(session, updatedLabelUtf8);
                TryDestroyDataObjectByLabel(session, labelUtf8);
            }

            session.Logout();
        }
    }

    [Fact]
    public void SetPinRoundTripsAndRestoresOriginalUserPin()
    {
        if (!TryCreateAdminContext(out AdminContext? context))
        {
            return;
        }

        using AdminContext activeContext = context!;
        byte[] originalPinUtf8 = activeContext.UserPinUtf8;
        byte[] updatedPinUtf8 = Encoding.UTF8.GetBytes("1234567");
        Assert.False(originalPinUtf8.AsSpan().SequenceEqual(updatedPinUtf8));

        bool reverted = false;

        try
        {
            using (Pkcs11Session session = activeContext.Module.OpenSession(activeContext.SlotId, readWrite: true))
            {
                session.Login(Pkcs11UserType.User, originalPinUtf8);
                session.SetPin(originalPinUtf8, updatedPinUtf8);
                session.Logout();
            }

            using (Pkcs11Session oldPinSession = activeContext.Module.OpenSession(activeContext.SlotId, readWrite: true))
            {
                Pkcs11Exception exception = Assert.Throws<Pkcs11Exception>(() => oldPinSession.Login(Pkcs11UserType.User, originalPinUtf8));
                Assert.Equal(0x000000a0u, exception.Result.Value);
            }

            using (Pkcs11Session newPinSession = activeContext.Module.OpenSession(activeContext.SlotId, readWrite: true))
            {
                newPinSession.Login(Pkcs11UserType.User, updatedPinUtf8);
                newPinSession.SetPin(updatedPinUtf8, originalPinUtf8);
                newPinSession.Logout();
            }

            reverted = true;

            using Pkcs11Session restoredSession = activeContext.Module.OpenSession(activeContext.SlotId, readWrite: true);
            restoredSession.Login(Pkcs11UserType.User, originalPinUtf8);
            restoredSession.Logout();
        }
        finally
        {
            if (!reverted)
            {
                TryRestoreUserPin(activeContext.Module, activeContext.SlotId, updatedPinUtf8, originalPinUtf8);
            }
        }
    }

    [Fact]
    public void InitPinRoundTripsWhenSecurityOfficerPinIsConfigured()
    {
        if (!TryCreateAdminContext(out AdminContext? context) || context!.SoPinUtf8 is null)
        {
            return;
        }

        using AdminContext activeContext = context;
        byte[] originalPinUtf8 = activeContext.UserPinUtf8;
        byte[] updatedPinUtf8 = Encoding.UTF8.GetBytes("234567");
        Assert.False(originalPinUtf8.AsSpan().SequenceEqual(updatedPinUtf8));

        bool reverted = false;

        try
        {
            using (Pkcs11Session soSession = activeContext.Module.OpenSession(activeContext.SlotId, readWrite: true))
            {
                soSession.Login(Pkcs11UserType.SecurityOfficer, activeContext.SoPinUtf8);
                soSession.InitPin(updatedPinUtf8);
                soSession.Logout();
            }

            using (Pkcs11Session userSession = activeContext.Module.OpenSession(activeContext.SlotId, readWrite: true))
            {
                userSession.Login(Pkcs11UserType.User, updatedPinUtf8);
                userSession.SetPin(updatedPinUtf8, originalPinUtf8);
                userSession.Logout();
            }

            reverted = true;

            using Pkcs11Session restoredSession = activeContext.Module.OpenSession(activeContext.SlotId, readWrite: true);
            restoredSession.Login(Pkcs11UserType.User, originalPinUtf8);
            restoredSession.Logout();
        }
        finally
        {
            if (!reverted)
            {
                TryRestoreUserPin(activeContext.Module, activeContext.SlotId, updatedPinUtf8, originalPinUtf8);
            }
        }
    }

    [Fact]
    public void CloseAllSessionsInvalidatesExistingSessionsAndAllowsNewSessions()
    {
        if (!TryCreateAdminContext(out AdminContext? context))
        {
            return;
        }

        using AdminContext activeContext = context!;
        using Pkcs11Session session1 = activeContext.Module.OpenSession(activeContext.SlotId);
        using Pkcs11Session session2 = activeContext.Module.OpenSession(activeContext.SlotId, readWrite: true);

        Assert.Equal(activeContext.SlotId, session1.GetInfo().SlotId);
        Assert.Equal(activeContext.SlotId, session2.GetInfo().SlotId);

        activeContext.Module.CloseAllSessions(activeContext.SlotId);

        Assert.Throws<InvalidOperationException>(() => session1.GetInfo());
        Assert.Throws<InvalidOperationException>(() => session2.GetInfo());

        session1.Dispose();
        session2.Dispose();

        using Pkcs11Session replacementSession = activeContext.Module.OpenSession(activeContext.SlotId);
        Assert.Equal(activeContext.SlotId, replacementSession.GetInfo().SlotId);
    }

    [Fact]
    public void InitTokenProvisionsFreshSoftHsmSlotAndInvalidatesExistingSessions()
    {
        if (!TryCreateProvisioningContext(out ProvisioningContext? context))
        {
            return;
        }

        using ProvisioningContext activeContext = context!;
        string initialLabel = $"p9-init-{Guid.NewGuid():N}"[..20];
        string resetLabel = $"p9-reset-{Guid.NewGuid():N}"[..20];
        byte[] initialLabelUtf8 = Encoding.ASCII.GetBytes(initialLabel);
        byte[] resetLabelUtf8 = Encoding.ASCII.GetBytes(resetLabel);
        byte[] dataLabelUtf8 = Encoding.ASCII.GetBytes($"p9-data-{Guid.NewGuid():N}"[..20]);
        byte[] applicationUtf8 = Encoding.ASCII.GetBytes("phase9");
        byte[] objectValue = [0x50, 0x39, 0x2D, 0x01];

        Console.WriteLine($"Phase 9 provisioning slot: {activeContext.SlotId.Value}");
        activeContext.Module.InitToken(activeContext.SlotId, activeContext.SoPinUtf8, initialLabelUtf8);

        Assert.True(activeContext.Module.TryGetTokenInfo(activeContext.SlotId, out Pkcs11TokenInfo tokenInfo));
        Assert.Equal(initialLabel, tokenInfo.Label.TrimEnd());
        Assert.True(tokenInfo.Flags.HasFlag(Pkcs11TokenFlags.TokenInitialized));

        using (Pkcs11Session soSession = activeContext.Module.OpenSession(activeContext.SlotId, readWrite: true))
        {
            soSession.Login(Pkcs11UserType.SecurityOfficer, activeContext.SoPinUtf8);
            soSession.InitPin(activeContext.UserPinUtf8);
            soSession.Logout();
        }

        using (Pkcs11Session userSession = activeContext.Module.OpenSession(activeContext.SlotId, readWrite: true))
        {
            userSession.Login(Pkcs11UserType.User, activeContext.UserPinUtf8);

            Pkcs11ObjectHandle handle = userSession.CreateObject(
            [
                Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.Data),
                Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, false),
                Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, false),
                Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Modifiable, true),
                Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, dataLabelUtf8),
                Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Application, applicationUtf8),
                Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Value, objectValue)
            ]);

            Assert.True(handle.Value != 0);
            Assert.True(userSession.TryFindObject(new Pkcs11ObjectSearchParameters(label: dataLabelUtf8, objectClass: Pkcs11ObjectClasses.Data), out Pkcs11ObjectHandle locatedHandle));
            Assert.Equal(handle, locatedHandle);
            userSession.DestroyObject(handle);
            Assert.False(userSession.TryFindObject(new Pkcs11ObjectSearchParameters(label: dataLabelUtf8, objectClass: Pkcs11ObjectClasses.Data), out _));
            userSession.Logout();
        }

        using Pkcs11Session invalidatedSession = activeContext.Module.OpenSession(activeContext.SlotId, readWrite: true);
        invalidatedSession.Login(Pkcs11UserType.User, activeContext.UserPinUtf8);
        Assert.Equal(activeContext.SlotId, invalidatedSession.GetInfo().SlotId);

        activeContext.Module.InitToken(activeContext.SlotId, activeContext.SoPinUtf8, resetLabelUtf8);

        Assert.Throws<InvalidOperationException>(() => invalidatedSession.GetInfo());
        invalidatedSession.Dispose();

        Assert.True(activeContext.Module.TryGetTokenInfo(activeContext.SlotId, out Pkcs11TokenInfo reinitializedTokenInfo));
        Assert.Equal(resetLabel, reinitializedTokenInfo.Label.TrimEnd());
        Assert.True(reinitializedTokenInfo.Flags.HasFlag(Pkcs11TokenFlags.TokenInitialized));
    }

    private static Pkcs11SlotId FindSlotByTokenLabel(Pkcs11Module module, string tokenLabel)
    {
        int slotCount = module.GetSlotCount();
        Assert.True(slotCount > 0);

        Pkcs11SlotId[] slots = new Pkcs11SlotId[slotCount];
        Assert.True(module.TryGetSlots(slots, out int written));

        for (int i = 0; i < written; i++)
        {
            if (module.TryGetTokenInfo(slots[i], out Pkcs11TokenInfo tokenInfo) &&
                string.Equals(tokenInfo.Label.Trim(), tokenLabel, StringComparison.Ordinal))
            {
                return slots[i];
            }
        }

        throw new Xunit.Sdk.XunitException($"Token '{tokenLabel}' was not found.");
    }

    private static Pkcs11SlotId FindProvisioningSlot(Pkcs11Module module)
    {
        int slotCount = module.GetSlotCount();
        Assert.True(slotCount > 0);

        Pkcs11SlotId[] slots = new Pkcs11SlotId[slotCount];
        Assert.True(module.TryGetSlots(slots, out int written));

        for (int i = 0; i < written; i++)
        {
            Pkcs11SlotInfo slotInfo = module.GetSlotInfo(slots[i]);
            if (!slotInfo.Flags.HasFlag(Pkcs11SlotFlags.TokenPresent))
            {
                return slots[i];
            }
        }

        for (int i = 0; i < written; i++)
        {
            if (!module.TryGetTokenInfo(slots[i], out Pkcs11TokenInfo tokenInfo) ||
                !tokenInfo.Flags.HasFlag(Pkcs11TokenFlags.TokenInitialized))
            {
                return slots[i];
            }
        }

        throw new Xunit.Sdk.XunitException("No free or uninitialized slot was available for Phase 9 provisioning regression.");
    }

    private static byte[] ParseHex(string? value, Func<string, byte[]> parser)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        return parser(value.Trim());
    }

    private static nuint ParseNuint(string value)
    {
        string trimmed = value.Trim();
        NumberStyles style = trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? NumberStyles.AllowHexSpecifier
            : NumberStyles.Integer;

        string numericText = trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? trimmed[2..]
            : trimmed;

        return nuint.Parse(numericText, style, CultureInfo.InvariantCulture);
    }

    private static bool? ParseNullableBoolean(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : bool.Parse(value);

    private static Pkcs11ObjectClass ParseObjectClass(string value)
        => value.Trim().ToLowerInvariant() switch
        {
            "data" => Pkcs11ObjectClasses.Data,
            "certificate" => Pkcs11ObjectClasses.Certificate,
            "public" or "publickey" => Pkcs11ObjectClasses.PublicKey,
            "private" or "privatekey" => Pkcs11ObjectClasses.PrivateKey,
            "secret" or "secretkey" => Pkcs11ObjectClasses.SecretKey,
            _ => throw new Xunit.Sdk.XunitException($"Unsupported PKCS11_FIND_CLASS value '{value}'.")
        };

    private static Pkcs11KeyType ParseKeyType(string value)
        => value.Trim().ToLowerInvariant() switch
        {
            "aes" => Pkcs11KeyTypes.Aes,
            "rsa" => Pkcs11KeyTypes.Rsa,
            "dsa" => Pkcs11KeyTypes.Dsa,
            "dh" => Pkcs11KeyTypes.Dh,
            "ec" => Pkcs11KeyTypes.Ec,
            "genericsecret" or "generic-secret" or "generic_secret" => Pkcs11KeyTypes.GenericSecret,
            _ => throw new Xunit.Sdk.XunitException($"Unsupported PKCS11_FIND_KEY_TYPE value '{value}'.")
        };

    private static byte[] EncryptMultipart(Pkcs11Session session, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> chunk1, ReadOnlySpan<byte> chunk2)
    {
        session.EncryptInit(keyHandle, mechanism);

        byte[] ciphertext = new byte[chunk1.Length + chunk2.Length + 32];
        Assert.True(session.TryEncryptUpdate(chunk1, ciphertext, out int firstWritten));
        Assert.True(session.TryEncryptUpdate(chunk2, ciphertext.AsSpan(firstWritten), out int secondWritten));
        Assert.True(session.TryEncryptFinal(ciphertext.AsSpan(firstWritten + secondWritten), out int finalWritten));
        return ciphertext.AsSpan(0, firstWritten + secondWritten + finalWritten).ToArray();
    }

    private static byte[] DecryptMultipart(Pkcs11Session session, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> chunk1, ReadOnlySpan<byte> chunk2)
    {
        session.DecryptInit(keyHandle, mechanism);

        byte[] plaintext = new byte[chunk1.Length + chunk2.Length + 32];
        Assert.True(session.TryDecryptUpdate(chunk1, plaintext, out int firstWritten));
        Assert.True(session.TryDecryptUpdate(chunk2, plaintext.AsSpan(firstWritten), out int secondWritten));
        Assert.True(session.TryDecryptFinal(plaintext.AsSpan(firstWritten + secondWritten), out int finalWritten));
        return plaintext.AsSpan(0, firstWritten + secondWritten + finalWritten).ToArray();
    }

    private static byte[] SignMultipart(Pkcs11Session session, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> chunk1, ReadOnlySpan<byte> chunk2)
    {
        session.SignInit(keyHandle, mechanism);
        session.SignUpdate(chunk1);
        session.SignUpdate(chunk2);

        byte[] signature = new byte[512];
        Assert.True(session.TrySignFinal(signature, out int written));
        return signature.AsSpan(0, written).ToArray();
    }

    private static byte[] ParseExactHex(string text, int expectedLength)
    {
        byte[] bytes = Convert.FromHexString(text);
        Assert.Equal(expectedLength, bytes.Length);
        return bytes;
    }

    private static void LoginUser(Pkcs11Session session, ReadOnlySpan<byte> pinUtf8)
    {
        try
        {
            session.Login(Pkcs11UserType.User, pinUtf8);
        }
        catch (Pkcs11Exception ex) when (ex.Result.Value is 0x000000a0u or 0x00000100u)
        {
        }
    }

    private static bool IsOperationStateUnavailable(Pkcs11Exception exception)
        => exception.Result.Value == 0x00000054u;

    private static byte[] GetRequiredAttributeBytes(Pkcs11Session session, Pkcs11ObjectHandle handle, Pkcs11AttributeType attributeType)
    {
        Pkcs11AttributeReadResult info = session.GetAttributeValueInfo(handle, attributeType);
        Assert.True(info.IsReadable);
        Assert.True(info.Length <= int.MaxValue);

        byte[] buffer = new byte[(int)info.Length];
        Assert.True(session.TryGetAttributeValue(handle, attributeType, buffer, out int written, out Pkcs11AttributeReadResult result));
        Assert.True(result.IsReadable);
        return buffer.AsSpan(0, written).ToArray();
    }

    private static void TryDestroyObjectBySearch(Pkcs11Session session, Pkcs11ObjectSearchParameters search)
    {
        if (session.TryFindObject(search, out Pkcs11ObjectHandle handle))
        {
            TryDestroyObject(session, handle);
        }
    }

    private static void TryDestroyDataObjectByLabel(Pkcs11Session session, byte[] labelUtf8)
    {
        if (session.TryFindObject(new Pkcs11ObjectSearchParameters(label: labelUtf8, objectClass: Pkcs11ObjectClasses.Data), out Pkcs11ObjectHandle handle))
        {
            TryDestroyObject(session, handle);
        }
    }

    private static void TryDestroyObject(Pkcs11Session session, Pkcs11ObjectHandle handle)
    {
        if (handle.Value == 0)
        {
            return;
        }

        try
        {
            session.DestroyObject(handle);
        }
        catch (Pkcs11Exception ex) when (ex.Result.Value == 0x00000082u)
        {
        }
    }

    private static void TryRestoreUserPin(Pkcs11Module module, Pkcs11SlotId slotId, ReadOnlySpan<byte> candidatePinUtf8, ReadOnlySpan<byte> originalPinUtf8)
    {
        try
        {
            using Pkcs11Session session = module.OpenSession(slotId, readWrite: true);
            session.Login(Pkcs11UserType.User, candidatePinUtf8);
            session.SetPin(candidatePinUtf8, originalPinUtf8);
            session.Logout();
        }
        catch
        {
        }
    }

    private static bool TryCreateAdminContext(out AdminContext? context)
    {
        string? modulePath = Environment.GetEnvironmentVariable("PKCS11_MODULE_PATH");
        string? tokenLabel = Environment.GetEnvironmentVariable("PKCS11_TOKEN_LABEL");
        string? userPin = Environment.GetEnvironmentVariable("PKCS11_USER_PIN");

        if (string.IsNullOrWhiteSpace(modulePath) ||
            string.IsNullOrWhiteSpace(tokenLabel) ||
            string.IsNullOrWhiteSpace(userPin))
        {
            context = null;
            return false;
        }

        Pkcs11Module module = Pkcs11Module.Load(modulePath);

        try
        {
            module.Initialize();
            context = new AdminContext(
                module,
                FindSlotByTokenLabel(module, tokenLabel),
                Encoding.UTF8.GetBytes(userPin),
                GetOptionalUtf8Bytes(Environment.GetEnvironmentVariable("PKCS11_SO_PIN")));
            return true;
        }
        catch
        {
            module.Dispose();
            throw;
        }
    }

    private static byte[]? GetOptionalUtf8Bytes(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : Encoding.UTF8.GetBytes(value);

    private static bool TryCreateProvisioningContext(out ProvisioningContext? context)
    {
        string? modulePath = Environment.GetEnvironmentVariable("PKCS11_MODULE_PATH");
        string? soPin = Environment.GetEnvironmentVariable("PKCS11_SO_PIN");
        string? enableProvisioning = Environment.GetEnvironmentVariable("PKCS11_PROVISIONING_REGRESSION");

        if (string.IsNullOrWhiteSpace(modulePath) ||
            string.IsNullOrWhiteSpace(soPin) ||
            !string.Equals(enableProvisioning, "1", StringComparison.Ordinal))
        {
            context = null;
            return false;
        }

        Pkcs11Module module = Pkcs11Module.Load(modulePath);

        try
        {
            module.Initialize();
            context = new ProvisioningContext(
                module,
                FindProvisioningSlot(module),
                Encoding.UTF8.GetBytes(soPin),
                Encoding.ASCII.GetBytes("246810"));
            return true;
        }
        catch
        {
            module.Dispose();
            throw;
        }
    }

    private static bool TryCreateGenerateContext(out GenerateContext? context)
    {
        string? modulePath = Environment.GetEnvironmentVariable("PKCS11_MODULE_PATH");
        string? tokenLabel = Environment.GetEnvironmentVariable("PKCS11_TOKEN_LABEL");
        string? userPin = Environment.GetEnvironmentVariable("PKCS11_USER_PIN");

        if (string.IsNullOrWhiteSpace(modulePath) ||
            string.IsNullOrWhiteSpace(tokenLabel) ||
            string.IsNullOrWhiteSpace(userPin))
        {
            context = null;
            return false;
        }

        Pkcs11Module module = Pkcs11Module.Load(modulePath);

        try
        {
            module.Initialize();
            Pkcs11SlotId slotId = FindSlotByTokenLabel(module, tokenLabel);
            Pkcs11Session session = module.OpenSession(slotId, readWrite: true);
            byte[] pinUtf8 = Encoding.UTF8.GetBytes(userPin);
            LoginUser(session, pinUtf8);
            context = new GenerateContext(module, session);
            return true;
        }
        catch
        {
            module.Dispose();
            throw;
        }
    }

    private static bool TryCreateCryptContext(out TestContext? context)
    {
        string? modulePath = Environment.GetEnvironmentVariable("PKCS11_MODULE_PATH");
        string? tokenLabel = Environment.GetEnvironmentVariable("PKCS11_TOKEN_LABEL");
        string? userPin = Environment.GetEnvironmentVariable("PKCS11_USER_PIN");
        string? findClass = Environment.GetEnvironmentVariable("PKCS11_FIND_CLASS");
        string? findKeyType = Environment.GetEnvironmentVariable("PKCS11_FIND_KEY_TYPE");

        if (string.IsNullOrWhiteSpace(modulePath) ||
            string.IsNullOrWhiteSpace(tokenLabel) ||
            string.IsNullOrWhiteSpace(userPin) ||
            string.IsNullOrWhiteSpace(findClass) ||
            string.IsNullOrWhiteSpace(findKeyType))
        {
            context = null;
            return false;
        }

        Pkcs11Module module = Pkcs11Module.Load(modulePath);

        try
        {
            module.Initialize();
            Pkcs11SlotId slotId = FindSlotByTokenLabel(module, tokenLabel);
            Pkcs11Session session = module.OpenSession(slotId);
            byte[] pinUtf8 = Encoding.UTF8.GetBytes(userPin);
            LoginUser(session, pinUtf8);

            Pkcs11ObjectSearchParameters search = new(
                label: ParseHex(Environment.GetEnvironmentVariable("PKCS11_FIND_LABEL"), Encoding.UTF8.GetBytes),
                id: ParseHex(Environment.GetEnvironmentVariable("PKCS11_FIND_ID_HEX"), Convert.FromHexString),
                objectClass: ParseObjectClass(findClass),
                keyType: ParseKeyType(findKeyType),
                requireEncrypt: ParseNullableBoolean(Environment.GetEnvironmentVariable("PKCS11_REQUIRE_ENCRYPT")),
                requireDecrypt: ParseNullableBoolean(Environment.GetEnvironmentVariable("PKCS11_REQUIRE_DECRYPT")));

            Assert.True(session.TryFindObject(search, out Pkcs11ObjectHandle keyHandle));
            context = new TestContext(module, session, slotId, keyHandle, pinUtf8);
            return true;
        }
        catch
        {
            module.Dispose();
            throw;
        }
    }

    private static bool TryCreateSignVerifyContext(out SignVerifyContext? context)
    {
        string? modulePath = Environment.GetEnvironmentVariable("PKCS11_MODULE_PATH");
        string? tokenLabel = Environment.GetEnvironmentVariable("PKCS11_TOKEN_LABEL");
        string? userPin = Environment.GetEnvironmentVariable("PKCS11_USER_PIN");
        string? signMechanismText = Environment.GetEnvironmentVariable("PKCS11_SIGN_MECHANISM");
        string? signClass = Environment.GetEnvironmentVariable("PKCS11_SIGN_FIND_CLASS");
        string? signKeyType = Environment.GetEnvironmentVariable("PKCS11_SIGN_FIND_KEY_TYPE");
        string? verifyClass = Environment.GetEnvironmentVariable("PKCS11_VERIFY_FIND_CLASS");
        string? verifyKeyType = Environment.GetEnvironmentVariable("PKCS11_VERIFY_FIND_KEY_TYPE");

        if (string.IsNullOrWhiteSpace(modulePath) ||
            string.IsNullOrWhiteSpace(tokenLabel) ||
            string.IsNullOrWhiteSpace(userPin) ||
            string.IsNullOrWhiteSpace(signMechanismText) ||
            string.IsNullOrWhiteSpace(signClass) ||
            string.IsNullOrWhiteSpace(signKeyType) ||
            string.IsNullOrWhiteSpace(verifyClass) ||
            string.IsNullOrWhiteSpace(verifyKeyType))
        {
            context = null;
            return false;
        }

        Pkcs11Module module = Pkcs11Module.Load(modulePath);

        try
        {
            module.Initialize();
            Pkcs11SlotId slotId = FindSlotByTokenLabel(module, tokenLabel);
            Pkcs11Session session = module.OpenSession(slotId);
            byte[] pinUtf8 = Encoding.UTF8.GetBytes(userPin);
            LoginUser(session, pinUtf8);

            Pkcs11ObjectSearchParameters signSearch = new(
                label: ParseHex(Environment.GetEnvironmentVariable("PKCS11_SIGN_FIND_LABEL"), Encoding.UTF8.GetBytes),
                id: ParseHex(Environment.GetEnvironmentVariable("PKCS11_SIGN_FIND_ID_HEX"), Convert.FromHexString),
                objectClass: ParseObjectClass(signClass),
                keyType: ParseKeyType(signKeyType),
                requireSign: ParseNullableBoolean(Environment.GetEnvironmentVariable("PKCS11_SIGN_REQUIRE_SIGN")));

            Pkcs11ObjectSearchParameters verifySearch = new(
                label: ParseHex(Environment.GetEnvironmentVariable("PKCS11_VERIFY_FIND_LABEL"), Encoding.UTF8.GetBytes),
                id: ParseHex(Environment.GetEnvironmentVariable("PKCS11_VERIFY_FIND_ID_HEX"), Convert.FromHexString),
                objectClass: ParseObjectClass(verifyClass),
                keyType: ParseKeyType(verifyKeyType),
                requireVerify: ParseNullableBoolean(Environment.GetEnvironmentVariable("PKCS11_VERIFY_REQUIRE_VERIFY")));

            Assert.True(session.TryFindObject(signSearch, out Pkcs11ObjectHandle signKeyHandle));
            Assert.True(session.TryFindObject(verifySearch, out Pkcs11ObjectHandle verifyKeyHandle));

            Pkcs11MechanismType mechanismType = new(ParseNuint(signMechanismText));
            byte[] mechanismParameter = ParseHex(Environment.GetEnvironmentVariable("PKCS11_SIGN_MECHANISM_PARAM_HEX"), Convert.FromHexString);

            context = new SignVerifyContext(module, session, signKeyHandle, verifyKeyHandle, mechanismType, mechanismParameter);
            return true;
        }
        catch
        {
            module.Dispose();
            throw;
        }
    }

    private sealed class TestContext : IDisposable
    {
        public TestContext(Pkcs11Module module, Pkcs11Session session, Pkcs11SlotId slotId, Pkcs11ObjectHandle keyHandle, byte[] pinUtf8)
        {
            Module = module;
            Session = session;
            SlotId = slotId;
            KeyHandle = keyHandle;
            PinUtf8 = pinUtf8;
        }

        public Pkcs11Module Module { get; }

        public Pkcs11Session Session { get; }

        public Pkcs11SlotId SlotId { get; }

        public Pkcs11ObjectHandle KeyHandle { get; }

        public byte[] PinUtf8 { get; }

        public void Dispose()
        {
            try
            {
                Session.Logout();
            }
            catch
            {
            }

            Session.Dispose();
            Module.Dispose();
        }
    }

    private sealed class SignVerifyContext : IDisposable
    {
        public SignVerifyContext(Pkcs11Module module, Pkcs11Session session, Pkcs11ObjectHandle signKeyHandle, Pkcs11ObjectHandle verifyKeyHandle, Pkcs11MechanismType mechanismType, byte[] mechanismParameter)
        {
            Module = module;
            Session = session;
            SignKeyHandle = signKeyHandle;
            VerifyKeyHandle = verifyKeyHandle;
            MechanismType = mechanismType;
            MechanismParameter = mechanismParameter;
        }

        public Pkcs11Module Module { get; }

        public Pkcs11Session Session { get; }

        public Pkcs11ObjectHandle SignKeyHandle { get; }

        public Pkcs11ObjectHandle VerifyKeyHandle { get; }

        public Pkcs11MechanismType MechanismType { get; }

        public byte[] MechanismParameter { get; }

        public Pkcs11Mechanism Mechanism => new(MechanismType, MechanismParameter);

        public void Dispose()
        {
            try
            {
                Session.Logout();
            }
            catch
            {
            }

            Session.Dispose();
            Module.Dispose();
        }
    }

    private sealed class AdminContext : IDisposable
    {
        public AdminContext(Pkcs11Module module, Pkcs11SlotId slotId, byte[] userPinUtf8, byte[]? soPinUtf8)
        {
            Module = module;
            SlotId = slotId;
            UserPinUtf8 = userPinUtf8;
            SoPinUtf8 = soPinUtf8;
        }

        public Pkcs11Module Module { get; }

        public Pkcs11SlotId SlotId { get; }

        public byte[] UserPinUtf8 { get; }

        public byte[]? SoPinUtf8 { get; }

        public void Dispose() => Module.Dispose();
    }

    private sealed class ProvisioningContext : IDisposable
    {
        public ProvisioningContext(Pkcs11Module module, Pkcs11SlotId slotId, byte[] soPinUtf8, byte[] userPinUtf8)
        {
            Module = module;
            SlotId = slotId;
            SoPinUtf8 = soPinUtf8;
            UserPinUtf8 = userPinUtf8;
        }

        public Pkcs11Module Module { get; }

        public Pkcs11SlotId SlotId { get; }

        public byte[] SoPinUtf8 { get; }

        public byte[] UserPinUtf8 { get; }

        public void Dispose() => Module.Dispose();
    }

    private sealed class GenerateContext : IDisposable
    {
        public GenerateContext(Pkcs11Module module, Pkcs11Session session)
        {
            Module = module;
            Session = session;
        }

        public Pkcs11Module Module { get; }

        public Pkcs11Session Session { get; }

        public void Dispose()
        {
            try
            {
                Session.Logout();
            }
            catch
            {
            }

            Session.Dispose();
            Module.Dispose();
        }
    }
}
