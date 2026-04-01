using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Text;
using Pkcs11Wrapper;
using Pkcs11Wrapper.Native;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper.Native.Tests;

[Collection(Pkcs11RuntimeCollection.Name)]
public sealed class SoftHsmCryptRegressionTests
{
    private static readonly Pkcs11AttributeType SignRecoverAttributeType = new(0x00000109u);
    private static readonly Pkcs11AttributeType VerifyRecoverAttributeType = new(0x0000010Bu);
    private const nuint CkrFunctionNotSupported = 0x00000054u;
    private const nuint CkrArgumentsBad = 0x00000007u;
    private const nuint CkrMechanismInvalid = 0x00000070u;
    private const nuint CkrMechanismParamInvalid = 0x00000071u;
    private const nuint CkrOperationActive = 0x00000090u;
    private const nuint CkrOperationNotInitialized = 0x00000091u;
    private const nuint CkrPinIncorrect = 0x000000a0u;
    private const nuint CkrUserAlreadyLoggedIn = 0x00000100u;
    private const nuint CkrKeyTypeInconsistent = 0x00000063u;
    private const nuint CkrKeyUnwrappable = 0x00000067u;
    private const nuint CkrKeyFunctionNotPermitted = 0x00000068u;
    private const nuint CkrObjectHandleInvalid = 0x00000082u;

    [Fact]
    public void InterfaceDiscoveryGracefullyReportsAbsentOnSoftHsm()
    {
        if (!TryCreateCryptContext(out TestContext? context))
        {
            return;
        }

        using TestContext activeContext = context!;
        Pkcs11Module module = activeContext.Module;

        Assert.False(module.SupportsInterfaceDiscovery);
        Assert.Equal(0, module.GetInterfaceCount());

        Pkcs11Interface[] interfaces = new Pkcs11Interface[1];
        Assert.True(module.TryGetInterfaces(interfaces, out int written));
        Assert.Equal(0, written);
        Assert.False(module.TryGetInterface("PKCS 11"u8, new CK_VERSION(3, 0), Pkcs11InterfaceFlags.None, out _));
    }

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
    public void SeedRandomAcceptsEntropyAndGenerateRandomStillProducesOutput()
    {
        if (!TryCreateCryptContext(out TestContext? context))
        {
            return;
        }

        using TestContext activeContext = context!;
        byte[] seed = ParseHex(Environment.GetEnvironmentVariable("PKCS11_SEED_RANDOM_HEX") ?? "102132435465768798A9BACBDCEDFE0F", Convert.FromHexString);
        byte[] random = new byte[32];

        activeContext.Session.SeedRandom(seed);
        activeContext.Session.GenerateRandom(random);

        Assert.Contains(random, static value => value != 0);
    }

    [Fact]
    public void LegacyFunctionStatusAndCancelReturnFalseWhenParallelFunctionsAreUnavailable()
    {
        if (!TryCreateCryptContext(out TestContext? context))
        {
            return;
        }

        using TestContext activeContext = context!;

        Assert.False(activeContext.Session.TryGetFunctionStatus());
        Assert.False(activeContext.Session.TryCancelFunction());
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
    public void DigestKeyAndRecoverOperationsAreCapabilityGatedAndPreserveBufferTooSmallSemantics()
    {
        if (!TryCreateSignVerifyContext(out SignVerifyContext? context))
        {
            return;
        }

        using SignVerifyContext activeContext = context!;
        byte[] data = ParseExactHex(Environment.GetEnvironmentVariable("PKCS11_SIGN_RECOVER_DATA_HEX") ?? "00112233445566778899AABBCCDDEEFF", 16);

        if (!RequireMechanismSupport(
                activeContext.Module,
                activeContext.Session.SlotId,
                (Pkcs11MechanismTypes.Sha256, Pkcs11MechanismFlags.Digest, "CKM_SHA256 digest"),
                (Pkcs11MechanismTypes.RsaX509, Pkcs11MechanismFlags.SignRecover | Pkcs11MechanismFlags.VerifyRecover, "CKM_RSA_X_509 sign/verify recover")))
        {
            return;
        }

        if (!TryGetBooleanAttribute(activeContext.Session, activeContext.SignKeyHandle, SignRecoverAttributeType, out bool canSignRecover) ||
            !TryGetBooleanAttribute(activeContext.Session, activeContext.VerifyKeyHandle, VerifyRecoverAttributeType, out bool canVerifyRecover) ||
            !canSignRecover ||
            !canVerifyRecover)
        {
            return;
        }

        try
        {
            activeContext.Session.DigestInit(new Pkcs11Mechanism(Pkcs11MechanismTypes.Sha256));
            activeContext.Session.DigestUpdate(data);
            activeContext.Session.DigestKey(activeContext.SignKeyHandle);

            Span<byte> tooSmallDigest = stackalloc byte[31];
            Assert.False(activeContext.Session.TryDigestFinal(tooSmallDigest, out int digestLength));
            Assert.True(digestLength > 0);

            byte[] digest = new byte[digestLength];
            Assert.True(activeContext.Session.TryDigestFinal(digest, out int digestWritten));
            Assert.Equal(digestLength, digestWritten);

            Pkcs11Mechanism rsaX509 = new(Pkcs11MechanismTypes.RsaX509);
            activeContext.Session.SignRecoverInit(activeContext.SignKeyHandle, rsaX509);
            int signRecoverLength = activeContext.Session.GetSignRecoverOutputLength(data);
            Assert.True(signRecoverLength > 0);

            activeContext.Session.SignRecoverInit(activeContext.SignKeyHandle, rsaX509);
            Span<byte> tooSmallSignature = stackalloc byte[Math.Max(signRecoverLength - 1, 0)];
            if (signRecoverLength > 0)
            {
                Assert.False(activeContext.Session.TrySignRecover(data, tooSmallSignature, out int requiredSignRecoverLength));
                Assert.Equal(signRecoverLength, requiredSignRecoverLength);
            }

            activeContext.Session.SignRecoverInit(activeContext.SignKeyHandle, rsaX509);
            byte[] signature = new byte[signRecoverLength];
            Assert.True(activeContext.Session.TrySignRecover(data, signature, out int signatureWritten));
            Assert.Equal(signRecoverLength, signatureWritten);

            activeContext.Session.VerifyRecoverInit(activeContext.VerifyKeyHandle, rsaX509);
            int verifyRecoverLength = activeContext.Session.GetVerifyRecoverOutputLength(signature.AsSpan(0, signatureWritten));
            Assert.True(verifyRecoverLength > 0);

            activeContext.Session.VerifyRecoverInit(activeContext.VerifyKeyHandle, rsaX509);
            Span<byte> tooSmallRecovered = stackalloc byte[Math.Max(verifyRecoverLength - 1, 0)];
            if (verifyRecoverLength > 0)
            {
                Assert.False(activeContext.Session.TryVerifyRecover(signature.AsSpan(0, signatureWritten), tooSmallRecovered, out int requiredVerifyRecoverLength));
                Assert.Equal(verifyRecoverLength, requiredVerifyRecoverLength);
            }

            activeContext.Session.VerifyRecoverInit(activeContext.VerifyKeyHandle, rsaX509);
            byte[] recovered = new byte[verifyRecoverLength];
            Assert.True(activeContext.Session.TryVerifyRecover(signature.AsSpan(0, signatureWritten), recovered, out int recoveredWritten));
            Assert.Equal(verifyRecoverLength, recoveredWritten);
        }
        catch (Pkcs11Exception ex) when (IsRecoverOrDigestKeyUnavailable(ex))
        {
            return;
        }
    }

    [Fact]
    public void CombinedDigestEncryptAndDecryptDigestUpdatesAreCapabilityGatedAndRoundTrip()
    {
        if (!TryCreateCryptContext(out TestContext? context))
        {
            return;
        }

        using TestContext activeContext = context!;
        byte[] iv = ParseExactHex(Environment.GetEnvironmentVariable("PKCS11_MULTIPART_IV_HEX") ?? "00112233445566778899AABBCCDDEEFF", 16);
        byte[] block = ParseExactHex(Environment.GetEnvironmentVariable("PKCS11_COMBINED_UPDATE_BLOCK_HEX") ?? "404142434445464748494A4B4C4D4E4F", 16);
        Pkcs11Mechanism digestMechanism = new(Pkcs11MechanismTypes.Sha256);
        Pkcs11Mechanism cryptMechanism = new(Pkcs11MechanismTypes.AesCbc, iv);

        if (!RequireMechanismSupport(
                activeContext.Module,
                activeContext.SlotId,
                (Pkcs11MechanismTypes.Sha256, Pkcs11MechanismFlags.Digest, "CKM_SHA256 digest"),
                (Pkcs11MechanismTypes.AesCbc, Pkcs11MechanismFlags.Encrypt | Pkcs11MechanismFlags.Decrypt, "CKM_AES_CBC encrypt/decrypt")))
        {
            return;
        }

        try
        {
            activeContext.Session.DigestInit(digestMechanism);
            activeContext.Session.EncryptInit(activeContext.KeyHandle, cryptMechanism);

            Span<byte> tooSmallEncrypt = stackalloc byte[15];
            Assert.False(activeContext.Session.TryDigestEncryptUpdate(block, tooSmallEncrypt, out int requiredDigestEncryptLength));
            Assert.Equal(16, requiredDigestEncryptLength);

            byte[] digestEncrypted = new byte[requiredDigestEncryptLength];
            Assert.True(activeContext.Session.TryDigestEncryptUpdate(block, digestEncrypted, out int digestEncryptWritten));
            Assert.Equal(requiredDigestEncryptLength, digestEncryptWritten);

            byte[] baselineCiphertext = EncryptMultipart(activeContext.Session, activeContext.KeyHandle, cryptMechanism, block, ReadOnlySpan<byte>.Empty);

            activeContext.Session.DigestInit(digestMechanism);
            activeContext.Session.DecryptInit(activeContext.KeyHandle, cryptMechanism);

            Span<byte> tooSmallDecrypt = stackalloc byte[15];
            Assert.False(activeContext.Session.TryDecryptDigestUpdate(baselineCiphertext, tooSmallDecrypt, out int requiredDecryptDigestLength));
            Assert.Equal(16, requiredDecryptDigestLength);

            byte[] decrypted = new byte[requiredDecryptDigestLength];
            Assert.True(activeContext.Session.TryDecryptDigestUpdate(baselineCiphertext, decrypted, out int decryptDigestWritten));
            Assert.Equal(requiredDecryptDigestLength, decryptDigestWritten);
            Assert.True(block.AsSpan().SequenceEqual(decrypted.AsSpan(0, decryptDigestWritten)));
        }
        catch (Pkcs11Exception ex) when (IsCombinedUpdateUnavailable(ex))
        {
            return;
        }
    }

    [Fact]
    public void CombinedSignEncryptAndDecryptVerifyUpdatesAreCapabilityGatedAndRoundTrip()
    {
        if (!TryCreateSignVerifyContext(out SignVerifyContext? context))
        {
            return;
        }

        using SignVerifyContext activeContext = context!;
        byte[] data = ParseExactHex(Environment.GetEnvironmentVariable("PKCS11_SIGN_ENCRYPT_DATA_HEX") ?? "505152535455565758595A5B5C5D5E5F", 16);
        Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.RsaX509);

        if (!SupportsMechanism(activeContext.Module, activeContext.Session.SlotId, Pkcs11MechanismTypes.RsaX509, Pkcs11MechanismFlags.Sign | Pkcs11MechanismFlags.Verify | Pkcs11MechanismFlags.Encrypt | Pkcs11MechanismFlags.Decrypt) ||
            !TryGetBooleanAttribute(activeContext.Session, activeContext.SignKeyHandle, Pkcs11AttributeTypes.Sign, out bool canSign) ||
            !TryGetBooleanAttribute(activeContext.Session, activeContext.SignKeyHandle, Pkcs11AttributeTypes.Decrypt, out bool canDecrypt) ||
            !TryGetBooleanAttribute(activeContext.Session, activeContext.VerifyKeyHandle, Pkcs11AttributeTypes.Verify, out bool canVerify) ||
            !TryGetBooleanAttribute(activeContext.Session, activeContext.VerifyKeyHandle, Pkcs11AttributeTypes.Encrypt, out bool canEncrypt) ||
            !canSign ||
            !canDecrypt ||
            !canVerify ||
            !canEncrypt)
        {
            return;
        }

        try
        {
            activeContext.Session.SignInit(activeContext.SignKeyHandle, mechanism);
            activeContext.Session.EncryptInit(activeContext.VerifyKeyHandle, mechanism);

            Assert.False(activeContext.Session.TrySignEncryptUpdate(data, Span<byte>.Empty, out int requiredSignEncryptLength));
            Assert.True(requiredSignEncryptLength > 0);

            byte[] signEncrypted = new byte[requiredSignEncryptLength];
            Assert.True(activeContext.Session.TrySignEncryptUpdate(data, signEncrypted, out int signEncryptWritten));
            Assert.Equal(requiredSignEncryptLength, signEncryptWritten);

            byte[] signature = new byte[activeContext.Session.GetSignOutputLength(activeContext.SignKeyHandle, mechanism, data)];
            Assert.True(activeContext.Session.TrySignFinal(signature, out int signatureWritten));
            Assert.True(signatureWritten > 0);

            activeContext.Session.DecryptInit(activeContext.SignKeyHandle, mechanism);
            activeContext.Session.VerifyInit(activeContext.VerifyKeyHandle, mechanism);

            Assert.False(activeContext.Session.TryDecryptVerifyUpdate(signEncrypted.AsSpan(0, signEncryptWritten), Span<byte>.Empty, out int requiredDecryptVerifyLength));
            Assert.True(requiredDecryptVerifyLength > 0);

            byte[] decrypted = new byte[requiredDecryptVerifyLength];
            Assert.True(activeContext.Session.TryDecryptVerifyUpdate(signEncrypted.AsSpan(0, signEncryptWritten), decrypted, out int decryptVerifyWritten));
            Assert.Equal(requiredDecryptVerifyLength, decryptVerifyWritten);
            Assert.True(activeContext.Session.VerifyFinal(signature.AsSpan(0, signatureWritten)));
        }
        catch (Pkcs11Exception ex) when (IsCombinedUpdateUnavailable(ex))
        {
            return;
        }
    }

    [Fact]
    public void InvalidMechanismAttemptDoesNotPoisonSubsequentEncryptDecryptFlow()
    {
        if (!TryCreateCryptContext(out TestContext? context))
        {
            return;
        }

        using TestContext activeContext = context!;
        if (!RequireMechanismSupport(
                activeContext.Module,
                activeContext.SlotId,
                (Pkcs11MechanismTypes.AesGcm, Pkcs11MechanismFlags.Encrypt | Pkcs11MechanismFlags.Decrypt, "CKM_AES_GCM encrypt/decrypt"),
                (Pkcs11MechanismTypes.AesCbc, Pkcs11MechanismFlags.Encrypt | Pkcs11MechanismFlags.Decrypt, "CKM_AES_CBC encrypt/decrypt")))
        {
            return;
        }

        byte[] plaintext = ParseExactHex(Environment.GetEnvironmentVariable("PKCS11_RECOVERY_PLAINTEXT_HEX") ?? "0102030405060708090A0B0C0D0E0F10", 16);
        byte[] gcmIv = ParseExactHex(Environment.GetEnvironmentVariable("PKCS11_RECOVERY_GCM_IV_HEX") ?? "00112233445566778899AABB", 12);
        byte[] aad = ParseExactHex(Environment.GetEnvironmentVariable("PKCS11_RECOVERY_GCM_AAD_HEX") ?? "A1A2A3A4A5A6A7A8", 8);
        byte[] cbcIv = ParseExactHex(Environment.GetEnvironmentVariable("PKCS11_RECOVERY_CBC_IV_HEX") ?? "00112233445566778899AABBCCDDEEFF", 16);
        Pkcs11Mechanism invalidMechanism = new(Pkcs11MechanismTypes.AesGcm, Pkcs11MechanismParameters.AesGcm(gcmIv, aad, tagBits: 7));

        Pkcs11Exception? exception = null;
        try
        {
            _ = activeContext.Session.GetEncryptOutputLength(activeContext.KeyHandle, invalidMechanism, plaintext);
        }
        catch (Pkcs11Exception ex)
        {
            exception = ex;
        }

        Assert.NotNull(exception);
        Assert.True(IsMechanismParamOrInvalid(exception!.Result.Value));

        Pkcs11Mechanism validMechanism = new(Pkcs11MechanismTypes.AesCbc, cbcIv);
        byte[] ciphertext = new byte[activeContext.Session.GetEncryptOutputLength(activeContext.KeyHandle, validMechanism, plaintext)];
        Assert.True(activeContext.Session.TryEncrypt(activeContext.KeyHandle, validMechanism, plaintext, ciphertext, out int ciphertextWritten));

        byte[] decrypted = new byte[activeContext.Session.GetDecryptOutputLength(activeContext.KeyHandle, validMechanism, ciphertext.AsSpan(0, ciphertextWritten))];
        Assert.True(activeContext.Session.TryDecrypt(activeContext.KeyHandle, validMechanism, ciphertext.AsSpan(0, ciphertextWritten), decrypted, out int decryptedWritten));
        Assert.True(plaintext.AsSpan().SequenceEqual(decrypted.AsSpan(0, decryptedWritten)));
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
    public void MechanismMatrixAesGcmRoundTripsAndCoversNegativeCases()
    {
        if (!TryCreateGenerateContext(out GenerateContext? context))
        {
            return;
        }

        using GenerateContext activeContext = context!;
        if (!RequireMechanismSupport(
                activeContext.Module,
                activeContext.Session.SlotId,
                (Pkcs11MechanismTypes.AesKeyGen, Pkcs11MechanismFlags.Generate, "CKM_AES_KEY_GEN generate"),
                (Pkcs11MechanismTypes.AesGcm, Pkcs11MechanismFlags.Encrypt | Pkcs11MechanismFlags.Decrypt, "CKM_AES_GCM encrypt/decrypt")))
        {
            return;
        }

        byte[] label = Encoding.ASCII.GetBytes($"phase16-gcm-{Guid.NewGuid():N}");
        byte[] id = Guid.NewGuid().ToByteArray();
        byte[] iv = ParseExactHex("00112233445566778899AABB", 12);
        byte[] aad = ParseExactHex("A1A2A3A4A5A6A7A8", 8);
        byte[] plaintext = Encoding.UTF8.GetBytes("phase16-aes-gcm-matrix");
        Pkcs11ObjectHandle keyHandle = default;
        bool created = false;

        try
        {
            keyHandle = activeContext.Session.GenerateKey(
                new Pkcs11Mechanism(Pkcs11MechanismTypes.AesKeyGen),
                Pkcs11ProvisioningTemplates.CreateAesEncryptDecryptSecretKey(label, id, token: false, extractable: false, valueLength: 32));
            created = true;

            Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.AesGcm, Pkcs11MechanismParameters.AesGcm(iv, aad, tagBits: 128));
            int expectedCiphertextLength = activeContext.Session.GetEncryptOutputLength(keyHandle, mechanism, plaintext);

            Span<byte> tooSmall = stackalloc byte[Math.Max(expectedCiphertextLength - 1, 0)];
            if (expectedCiphertextLength > 0)
            {
                Assert.False(activeContext.Session.TryEncrypt(keyHandle, mechanism, plaintext, tooSmall, out int requiredLength));
                Assert.Equal(expectedCiphertextLength, requiredLength);
            }

            byte[] ciphertext = new byte[expectedCiphertextLength];
            Assert.True(activeContext.Session.TryEncrypt(keyHandle, mechanism, plaintext, ciphertext, out int ciphertextWritten));

            byte[] decrypted = new byte[activeContext.Session.GetDecryptOutputLength(keyHandle, mechanism, ciphertext.AsSpan(0, ciphertextWritten))];
            Assert.True(activeContext.Session.TryDecrypt(keyHandle, mechanism, ciphertext.AsSpan(0, ciphertextWritten), decrypted, out int decryptedWritten));
            Assert.True(plaintext.AsSpan().SequenceEqual(decrypted.AsSpan(0, decryptedWritten)));

            Pkcs11Mechanism invalidMechanism = new(Pkcs11MechanismTypes.AesGcm, Pkcs11MechanismParameters.AesGcm(iv, aad, tagBits: 7));
            Pkcs11Exception? exception = null;
            try
            {
                _ = activeContext.Session.GetEncryptOutputLength(keyHandle, invalidMechanism, plaintext);
            }
            catch (Pkcs11Exception ex)
            {
                exception = ex;
            }

            Assert.NotNull(exception);
            Assert.True(IsMechanismParamOrInvalid(exception!.Result.Value));
        }
        finally
        {
            if (created)
            {
                TryDestroyObject(activeContext.Session, keyHandle);
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: label, id: id, objectClass: Pkcs11ObjectClasses.SecretKey, keyType: Pkcs11KeyTypes.Aes));
            }
        }
    }

    [Fact]
    public void MechanismMatrixAesCtrRoundTripsAndRejectsWrongCounterBits()
    {
        if (!TryCreateGenerateContext(out GenerateContext? context))
        {
            return;
        }

        using GenerateContext activeContext = context!;
        if (!RequireMechanismSupport(
                activeContext.Module,
                activeContext.Session.SlotId,
                (Pkcs11MechanismTypes.AesKeyGen, Pkcs11MechanismFlags.Generate, "CKM_AES_KEY_GEN generate"),
                (Pkcs11MechanismTypes.AesCtr, Pkcs11MechanismFlags.Encrypt | Pkcs11MechanismFlags.Decrypt, "CKM_AES_CTR encrypt/decrypt")))
        {
            return;
        }

        byte[] label = Encoding.ASCII.GetBytes($"phase16-ctr-{Guid.NewGuid():N}");
        byte[] id = Guid.NewGuid().ToByteArray();
        byte[] ctrBlock = ParseExactHex("00000000000000000000000000000001", 16);
        byte[] plaintext = Encoding.UTF8.GetBytes("phase16-aes-ctr-matrix");
        Pkcs11ObjectHandle keyHandle = default;
        bool created = false;

        try
        {
            keyHandle = activeContext.Session.GenerateKey(
                new Pkcs11Mechanism(Pkcs11MechanismTypes.AesKeyGen),
                Pkcs11ProvisioningTemplates.CreateAesEncryptDecryptSecretKey(label, id, token: false, extractable: false, valueLength: 32));
            created = true;

            Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.AesCtr, Pkcs11MechanismParameters.AesCtr(ctrBlock, counterBits: 32));
            byte[] ciphertext = new byte[activeContext.Session.GetEncryptOutputLength(keyHandle, mechanism, plaintext)];
            Assert.True(activeContext.Session.TryEncrypt(keyHandle, mechanism, plaintext, ciphertext, out int ciphertextWritten));

            byte[] decrypted = new byte[activeContext.Session.GetDecryptOutputLength(keyHandle, mechanism, ciphertext.AsSpan(0, ciphertextWritten))];
            Assert.True(activeContext.Session.TryDecrypt(keyHandle, mechanism, ciphertext.AsSpan(0, ciphertextWritten), decrypted, out int decryptedWritten));
            Assert.True(plaintext.AsSpan().SequenceEqual(decrypted.AsSpan(0, decryptedWritten)));

            Pkcs11Exception? exception = null;
            try
            {
                _ = activeContext.Session.GetEncryptOutputLength(
                    keyHandle,
                    new Pkcs11Mechanism(Pkcs11MechanismTypes.AesCtr, Pkcs11MechanismParameters.AesCtr(ctrBlock, counterBits: 0)),
                    plaintext);
            }
            catch (Pkcs11Exception ex)
            {
                exception = ex;
            }

            Assert.NotNull(exception);
            Assert.True(IsMechanismParamOrInvalid(exception!.Result.Value));
        }
        finally
        {
            if (created)
            {
                TryDestroyObject(activeContext.Session, keyHandle);
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: label, id: id, objectClass: Pkcs11ObjectClasses.SecretKey, keyType: Pkcs11KeyTypes.Aes));
            }
        }
    }

    [Fact]
    public void MechanismMatrixAesCbcPadRoundTripsAndRejectsWrongIvLength()
    {
        if (!TryCreateGenerateContext(out GenerateContext? context))
        {
            return;
        }

        using GenerateContext activeContext = context!;
        if (!RequireMechanismSupport(
                activeContext.Module,
                activeContext.Session.SlotId,
                (Pkcs11MechanismTypes.AesKeyGen, Pkcs11MechanismFlags.Generate, "CKM_AES_KEY_GEN generate"),
                (Pkcs11MechanismTypes.AesCbcPad, Pkcs11MechanismFlags.Encrypt | Pkcs11MechanismFlags.Decrypt, "CKM_AES_CBC_PAD encrypt/decrypt")))
        {
            return;
        }

        byte[] label = Encoding.ASCII.GetBytes($"phase16-cbc-{Guid.NewGuid():N}");
        byte[] id = Guid.NewGuid().ToByteArray();
        byte[] iv = ParseExactHex("00112233445566778899AABBCCDDEEFF", 16);
        byte[] plaintext = Encoding.UTF8.GetBytes("phase16-aes-cbc-pad-matrix");
        Pkcs11ObjectHandle keyHandle = default;
        bool created = false;

        try
        {
            keyHandle = activeContext.Session.GenerateKey(
                new Pkcs11Mechanism(Pkcs11MechanismTypes.AesKeyGen),
                Pkcs11ProvisioningTemplates.CreateAesEncryptDecryptSecretKey(label, id, token: false, extractable: false, valueLength: 32));
            created = true;

            Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.AesCbcPad, iv);
            byte[] ciphertext = new byte[activeContext.Session.GetEncryptOutputLength(keyHandle, mechanism, plaintext)];
            Assert.True(activeContext.Session.TryEncrypt(keyHandle, mechanism, plaintext, ciphertext, out int ciphertextWritten));

            byte[] decrypted = new byte[activeContext.Session.GetDecryptOutputLength(keyHandle, mechanism, ciphertext.AsSpan(0, ciphertextWritten))];
            Assert.True(activeContext.Session.TryDecrypt(keyHandle, mechanism, ciphertext.AsSpan(0, ciphertextWritten), decrypted, out int decryptedWritten));
            Assert.True(plaintext.AsSpan().SequenceEqual(decrypted.AsSpan(0, decryptedWritten)));

            Pkcs11Exception? exception = null;
            try
            {
                _ = activeContext.Session.GetEncryptOutputLength(keyHandle, new Pkcs11Mechanism(Pkcs11MechanismTypes.AesCbcPad, iv.AsSpan(..15)), plaintext);
            }
            catch (Pkcs11Exception ex)
            {
                exception = ex;
            }

            Assert.NotNull(exception);
            Assert.True(IsMechanismParamOrInvalid(exception!.Result.Value));
        }
        finally
        {
            if (created)
            {
                TryDestroyObject(activeContext.Session, keyHandle);
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: label, id: id, objectClass: Pkcs11ObjectClasses.SecretKey, keyType: Pkcs11KeyTypes.Aes));
            }
        }
    }

    [Fact]
    public void MechanismMatrixRsaOaepRoundTripsAndRejectsKeyMismatch()
    {
        if (!TryCreateGenerateContext(out GenerateContext? context))
        {
            return;
        }

        using GenerateContext activeContext = context!;
        if (!RequireMechanismSupport(
                activeContext.Module,
                activeContext.Session.SlotId,
                (Pkcs11MechanismTypes.RsaPkcsKeyPairGen, Pkcs11MechanismFlags.GenerateKeyPair, "CKM_RSA_PKCS_KEY_PAIR_GEN generate key pair"),
                (Pkcs11MechanismTypes.RsaPkcsOaep, Pkcs11MechanismFlags.Encrypt | Pkcs11MechanismFlags.Decrypt, "CKM_RSA_PKCS_OAEP encrypt/decrypt")))
        {
            return;
        }

        byte[] label = Encoding.ASCII.GetBytes($"phase16-oaep-{Guid.NewGuid():N}");
        byte[] id = Guid.NewGuid().ToByteArray();
        byte[] plaintext = Encoding.UTF8.GetBytes("phase16-rsa-oaep-matrix");
        Pkcs11GeneratedKeyPair keyPair = default;
        bool created = false;

        try
        {
            Pkcs11KeyPairTemplate template = CreateRsaEncryptDecryptKeyPair(label, id, token: false);
            keyPair = activeContext.Session.GenerateKeyPair(new Pkcs11Mechanism(Pkcs11MechanismTypes.RsaPkcsKeyPairGen), template.PublicKeyAttributes, template.PrivateKeyAttributes);
            created = true;

            Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.RsaPkcsOaep, Pkcs11MechanismParameters.RsaOaep(Pkcs11MechanismTypes.Sha256, Pkcs11RsaMgfTypes.Mgf1Sha256));
            int ciphertextLength;

            try
            {
                ciphertextLength = activeContext.Session.GetEncryptOutputLength(keyPair.PublicKeyHandle, mechanism, plaintext);
            }
            catch (Pkcs11Exception ex) when (IsMechanismParamOrInvalid(ex.Result.Value))
            {
                mechanism = new(Pkcs11MechanismTypes.RsaPkcsOaep, Pkcs11MechanismParameters.RsaOaep(Pkcs11MechanismTypes.Sha1, Pkcs11RsaMgfTypes.Mgf1Sha1));

                try
                {
                    ciphertextLength = activeContext.Session.GetEncryptOutputLength(keyPair.PublicKeyHandle, mechanism, plaintext);
                }
                catch (Pkcs11Exception fallbackEx) when (IsMechanismParamOrInvalid(fallbackEx.Result.Value))
                {
                    return;
                }
            }

            byte[] ciphertext = new byte[ciphertextLength];
            Assert.True(activeContext.Session.TryEncrypt(keyPair.PublicKeyHandle, mechanism, plaintext, ciphertext, out int ciphertextWritten));

            byte[] decrypted = new byte[activeContext.Session.GetDecryptOutputLength(keyPair.PrivateKeyHandle, mechanism, ciphertext.AsSpan(0, ciphertextWritten))];
            Assert.True(activeContext.Session.TryDecrypt(keyPair.PrivateKeyHandle, mechanism, ciphertext.AsSpan(0, ciphertextWritten), decrypted, out int decryptedWritten));
            Assert.True(plaintext.AsSpan().SequenceEqual(decrypted.AsSpan(0, decryptedWritten)));

            Pkcs11Exception? mismatchException = null;
            try
            {
                _ = activeContext.Session.GetDecryptOutputLength(keyPair.PublicKeyHandle, mechanism, ciphertext.AsSpan(0, ciphertextWritten));
            }
            catch (Pkcs11Exception ex)
            {
                mismatchException = ex;
            }

            Assert.NotNull(mismatchException);
            Assert.True(IsKeyMismatchOrInvalid(mismatchException!.Result.Value));
        }
        finally
        {
            if (created)
            {
                TryDestroyObject(activeContext.Session, keyPair.PrivateKeyHandle);
                TryDestroyObject(activeContext.Session, keyPair.PublicKeyHandle);
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: label, id: id, objectClass: Pkcs11ObjectClasses.PrivateKey, keyType: Pkcs11KeyTypes.Rsa));
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: label, id: id, objectClass: Pkcs11ObjectClasses.PublicKey, keyType: Pkcs11KeyTypes.Rsa));
            }
        }
    }

    [Fact]
    public void MechanismMatrixRsaPssRoundTripsAndCoversBufferTooSmall()
    {
        if (!TryCreateGenerateContext(out GenerateContext? context))
        {
            return;
        }

        using GenerateContext activeContext = context!;
        if (!RequireMechanismSupport(
                activeContext.Module,
                activeContext.Session.SlotId,
                (Pkcs11MechanismTypes.RsaPkcsKeyPairGen, Pkcs11MechanismFlags.GenerateKeyPair, "CKM_RSA_PKCS_KEY_PAIR_GEN generate key pair"),
                (Pkcs11MechanismTypes.Sha256RsaPkcsPss, Pkcs11MechanismFlags.Sign | Pkcs11MechanismFlags.Verify, "CKM_SHA256_RSA_PKCS_PSS sign/verify")))
        {
            return;
        }

        byte[] label = Encoding.ASCII.GetBytes($"phase16-pss-{Guid.NewGuid():N}");
        byte[] id = Guid.NewGuid().ToByteArray();
        byte[] data = Encoding.UTF8.GetBytes("phase16-rsa-pss-matrix");
        Pkcs11GeneratedKeyPair keyPair = default;
        bool created = false;

        try
        {
            Pkcs11KeyPairTemplate templates = Pkcs11ProvisioningTemplates.CreateRsaSignVerifyKeyPair(label, id, token: false, modulusBits: 2048);
            keyPair = activeContext.Session.GenerateKeyPair(new Pkcs11Mechanism(Pkcs11MechanismTypes.RsaPkcsKeyPairGen), templates.PublicKeyAttributes, templates.PrivateKeyAttributes);
            created = true;

            Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.Sha256RsaPkcsPss, Pkcs11MechanismParameters.RsaPss(Pkcs11MechanismTypes.Sha256, Pkcs11RsaMgfTypes.Mgf1Sha256, 32));
            int expectedLength = activeContext.Session.GetSignOutputLength(keyPair.PrivateKeyHandle, mechanism, data);

            Span<byte> tooSmall = stackalloc byte[Math.Max(expectedLength - 1, 0)];
            if (expectedLength > 0)
            {
                Assert.False(activeContext.Session.TrySign(keyPair.PrivateKeyHandle, mechanism, data, tooSmall, out int requiredLength));
                Assert.Equal(expectedLength, requiredLength);
            }

            byte[] signature = new byte[expectedLength];
            Assert.True(activeContext.Session.TrySign(keyPair.PrivateKeyHandle, mechanism, data, signature, out int written));
            Assert.True(activeContext.Session.Verify(keyPair.PublicKeyHandle, mechanism, data, signature.AsSpan(0, written)));

            Pkcs11Mechanism mismatchedSalt = new(Pkcs11MechanismTypes.Sha256RsaPkcsPss, Pkcs11MechanismParameters.RsaPss(Pkcs11MechanismTypes.Sha256, Pkcs11RsaMgfTypes.Mgf1Sha256, 31));
            Assert.False(activeContext.Session.Verify(keyPair.PublicKeyHandle, mismatchedSalt, data, signature.AsSpan(0, written)));
        }
        finally
        {
            if (created)
            {
                TryDestroyObject(activeContext.Session, keyPair.PrivateKeyHandle);
                TryDestroyObject(activeContext.Session, keyPair.PublicKeyHandle);
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: label, id: id, objectClass: Pkcs11ObjectClasses.PrivateKey, keyType: Pkcs11KeyTypes.Rsa));
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: label, id: id, objectClass: Pkcs11ObjectClasses.PublicKey, keyType: Pkcs11KeyTypes.Rsa));
            }
        }
    }

    [Fact]
    public void MechanismMatrixSha256HmacRoundTripsAndRejectsWrongKey()
    {
        if (!TryCreateGenerateContext(out GenerateContext? context))
        {
            return;
        }

        using GenerateContext activeContext = context!;
        if (!RequireMechanismSupport(
                activeContext.Module,
                activeContext.Session.SlotId,
                (Pkcs11MechanismTypes.GenericSecretKeyGen, Pkcs11MechanismFlags.Generate, "CKM_GENERIC_SECRET_KEY_GEN generate"),
                (Pkcs11MechanismTypes.Sha256Hmac, Pkcs11MechanismFlags.Sign | Pkcs11MechanismFlags.Verify, "CKM_SHA256_HMAC sign/verify")))
        {
            return;
        }

        byte[] firstLabel = Encoding.ASCII.GetBytes($"phase16-hmac-a-{Guid.NewGuid():N}");
        byte[] secondLabel = Encoding.ASCII.GetBytes($"phase16-hmac-b-{Guid.NewGuid():N}");
        byte[] firstId = Guid.NewGuid().ToByteArray();
        byte[] secondId = Guid.NewGuid().ToByteArray();
        byte[] data = Encoding.UTF8.GetBytes("phase16-hmac-matrix");
        Pkcs11ObjectHandle firstKey = default;
        Pkcs11ObjectHandle secondKey = default;
        bool firstCreated = false;
        bool secondCreated = false;

        try
        {
            firstKey = activeContext.Session.GenerateKey(new Pkcs11Mechanism(Pkcs11MechanismTypes.GenericSecretKeyGen), CreateGenericSecretHmacKeyTemplate(firstLabel, firstId));
            secondKey = activeContext.Session.GenerateKey(new Pkcs11Mechanism(Pkcs11MechanismTypes.GenericSecretKeyGen), CreateGenericSecretHmacKeyTemplate(secondLabel, secondId));
            firstCreated = true;
            secondCreated = true;

            Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.Sha256Hmac);
            int expectedLength = activeContext.Session.GetSignOutputLength(firstKey, mechanism, data);

            Span<byte> tooSmall = stackalloc byte[Math.Max(expectedLength - 1, 0)];
            if (expectedLength > 0)
            {
                Assert.False(activeContext.Session.TrySign(firstKey, mechanism, data, tooSmall, out int requiredLength));
                Assert.Equal(expectedLength, requiredLength);
            }

            byte[] signature = new byte[expectedLength];
            Assert.True(activeContext.Session.TrySign(firstKey, mechanism, data, signature, out int written));
            Assert.True(activeContext.Session.Verify(firstKey, mechanism, data, signature.AsSpan(0, written)));
            Assert.False(activeContext.Session.Verify(secondKey, mechanism, data, signature.AsSpan(0, written)));
        }
        finally
        {
            if (secondCreated)
            {
                TryDestroyObject(activeContext.Session, secondKey);
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: secondLabel, id: secondId, objectClass: Pkcs11ObjectClasses.SecretKey, keyType: Pkcs11KeyTypes.GenericSecret));
            }

            if (firstCreated)
            {
                TryDestroyObject(activeContext.Session, firstKey);
                TryDestroyObjectBySearch(activeContext.Session, new Pkcs11ObjectSearchParameters(label: firstLabel, id: firstId, objectClass: Pkcs11ObjectClasses.SecretKey, keyType: Pkcs11KeyTypes.GenericSecret));
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
    public void CopyObjectClonesDataObjectWithTemplateOverrides()
    {
        if (!TryCreateGenerateContext(out GenerateContext? context))
        {
            return;
        }

        using GenerateContext activeContext = context!;
        byte[] sourceLabel = Encoding.UTF8.GetBytes($"phase14-copy-src-{Guid.NewGuid():N}");
        byte[] copiedLabel = Encoding.UTF8.GetBytes($"phase14-copy-dst-{Guid.NewGuid():N}");
        byte[] application = Encoding.UTF8.GetBytes("phase14-copy");
        byte[] value = [0x50, 0x31, 0x34, 0x2D, 0x01];

        Pkcs11ObjectHandle sourceHandle = default;
        Pkcs11ObjectHandle copiedHandle = default;
        bool sourceCreated = false;
        bool copiedCreated = false;

        try
        {
            sourceHandle = activeContext.Session.CreateObject(
            [
                Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.Data),
                Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, false),
                Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, false),
                Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Modifiable, true),
                Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, sourceLabel),
                Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Application, application),
                Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Value, value)
            ]);

            sourceCreated = true;
            copiedHandle = activeContext.Session.CopyObject(
                sourceHandle,
                [
                    Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, copiedLabel)
                ]);

            copiedCreated = true;
            Assert.True(sourceHandle.Value != 0);
            Assert.True(copiedHandle.Value != 0);
            Assert.NotEqual(sourceHandle, copiedHandle);

            Assert.True(activeContext.Session.TryFindObject(new Pkcs11ObjectSearchParameters(label: sourceLabel, objectClass: Pkcs11ObjectClasses.Data), out Pkcs11ObjectHandle locatedSource));
            Assert.True(activeContext.Session.TryFindObject(new Pkcs11ObjectSearchParameters(label: copiedLabel, objectClass: Pkcs11ObjectClasses.Data), out Pkcs11ObjectHandle locatedCopy));
            Assert.Equal(sourceHandle, locatedSource);
            Assert.Equal(copiedHandle, locatedCopy);
            Assert.Equal(value, GetRequiredAttributeBytes(activeContext.Session, copiedHandle, Pkcs11AttributeTypes.Value));

            activeContext.Session.DestroyObject(copiedHandle);
            copiedCreated = false;
            activeContext.Session.DestroyObject(sourceHandle);
            sourceCreated = false;
        }
        finally
        {
            if (copiedCreated)
            {
                TryDestroyObject(activeContext.Session, copiedHandle);
                TryDestroyDataObjectByLabel(activeContext.Session, copiedLabel);
            }

            if (sourceCreated)
            {
                TryDestroyObject(activeContext.Session, sourceHandle);
                TryDestroyDataObjectByLabel(activeContext.Session, sourceLabel);
            }
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
                Assert.Equal(CkrPinIncorrect, exception.Result.Value);
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

    [Fact]
    public void FinalizeModuleInvalidatesExistingSessionsUntilModuleIsInitializedAgain()
    {
        if (!TryCreateAdminContext(out AdminContext? context))
        {
            return;
        }

        using AdminContext activeContext = context!;
        using Pkcs11Session invalidatedSession = activeContext.Module.OpenSession(activeContext.SlotId);
        Assert.Equal(activeContext.SlotId, invalidatedSession.GetInfo().SlotId);

        activeContext.Module.FinalizeModule();
        Assert.Throws<InvalidOperationException>(() => invalidatedSession.GetInfo());

        activeContext.Module.Initialize();
        using Pkcs11Session replacementSession = activeContext.Module.OpenSession(activeContext.SlotId);
        Assert.Equal(activeContext.SlotId, replacementSession.GetInfo().SlotId);
    }

    [Fact]
    public void RepeatedFinalizeAndReinitializeCyclesKeepModuleUsable()
    {
        if (!TryCreateAdminContext(out AdminContext? context))
        {
            return;
        }

        using AdminContext activeContext = context!;

        for (int round = 0; round < 5; round++)
        {
            using Pkcs11Session liveSession = activeContext.Module.OpenSession(activeContext.SlotId, readWrite: (round & 1) == 0);
            Assert.Equal(activeContext.SlotId, liveSession.GetInfo().SlotId);

            activeContext.Module.FinalizeModule();
            Assert.Throws<InvalidOperationException>(() => liveSession.GetInfo());

            activeContext.Module.Initialize();
            using Pkcs11Session replacementSession = activeContext.Module.OpenSession(activeContext.SlotId);
            Assert.Equal(activeContext.SlotId, replacementSession.GetInfo().SlotId);
        }
    }

    [Fact]
    public async Task ParallelOpenSessionBurstsRemainStableAcrossRounds()
    {
        if (!OperatingSystem.IsLinux())
        {
            return;
        }

        string? modulePath = Environment.GetEnvironmentVariable("PKCS11_MODULE_PATH");
        string? tokenLabel = Environment.GetEnvironmentVariable("PKCS11_TOKEN_LABEL");
        if (string.IsNullOrWhiteSpace(modulePath) || string.IsNullOrWhiteSpace(tokenLabel))
        {
            return;
        }

        using Pkcs11Module module = Pkcs11Module.Load(modulePath);
        module.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));
        Pkcs11SlotId slotId = FindSlotByTokenLabel(module, tokenLabel);

        for (int round = 0; round < 4; round++)
        {
            Task[] tasks = new Task[8];
            for (int i = 0; i < tasks.Length; i++)
            {
                bool readWrite = (i & 1) == 0;
                tasks[i] = Task.Run(() =>
                {
                    using Pkcs11Session session = module.OpenSession(slotId, readWrite);
                    Assert.Equal(slotId, session.GetInfo().SlotId);
                });
            }

            await Task.WhenAll(tasks);

            using Pkcs11Session probeSession = module.OpenSession(slotId);
            Assert.Equal(slotId, probeSession.GetInfo().SlotId);
        }
    }

    [Fact]
    public void InitializeSupportsOperatingSystemLockingFlag()
    {
        string? modulePath = Environment.GetEnvironmentVariable("PKCS11_MODULE_PATH");
        if (string.IsNullOrWhiteSpace(modulePath))
        {
            return;
        }

        using Pkcs11Module module = Pkcs11Module.Load(modulePath);
        module.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));

        Assert.True(module.GetSlotCount() > 0);
    }

    [Fact]
    public unsafe void InitializeSupportsCustomMutexCallbacks()
    {
        string? modulePath = Environment.GetEnvironmentVariable("PKCS11_MODULE_PATH");
        if (string.IsNullOrWhiteSpace(modulePath))
        {
            return;
        }

        using Pkcs11Module module = Pkcs11Module.Load(modulePath);
        Pkcs11MutexCallbacks mutexCallbacks = new(&CreateMutex, &DestroyMutex, &LockMutex, &UnlockMutex);
        module.Initialize(new Pkcs11InitializeOptions(mutexCallbacks: mutexCallbacks));

        Assert.True(module.GetSlotCount() > 0);
    }

    [Fact]
    public unsafe void InitializeRejectsIncompleteCustomMutexCallbackSets()
    {
        string? modulePath = Environment.GetEnvironmentVariable("PKCS11_MODULE_PATH");
        if (string.IsNullOrWhiteSpace(modulePath))
        {
            return;
        }

        using Pkcs11Module module = Pkcs11Module.Load(modulePath);
        Pkcs11MutexCallbacks incompleteCallbacks = new(&CreateMutex, null, null, null);

        Assert.Throws<ArgumentException>(() => module.Initialize(new Pkcs11InitializeOptions(mutexCallbacks: incompleteCallbacks)));
    }

    [Fact]
    public void DisposeModuleInvalidatesExistingSessionsAndRejectsNewOperations()
    {
        if (!TryCreateAdminContext(out AdminContext? context))
        {
            return;
        }

        using AdminContext activeContext = context!;
        using Pkcs11Session invalidatedSession = activeContext.Module.OpenSession(activeContext.SlotId);
        Assert.Equal(activeContext.SlotId, invalidatedSession.GetInfo().SlotId);

        activeContext.Module.Dispose();

        Assert.Throws<InvalidOperationException>(() => invalidatedSession.GetInfo());
        Assert.Throws<ObjectDisposedException>(() => activeContext.Module.OpenSession(activeContext.SlotId));
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe CK_RV CreateMutex(void** mutex)
    {
        *mutex = NativeMemory.Alloc(1);
        return CK_RV.Ok;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe CK_RV DestroyMutex(void* mutex)
    {
        if (mutex is not null)
        {
            NativeMemory.Free(mutex);
        }

        return CK_RV.Ok;
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe CK_RV LockMutex(void* mutex) => CK_RV.Ok;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe CK_RV UnlockMutex(void* mutex) => CK_RV.Ok;

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

    private static bool IsMechanismParamOrInvalid(nuint result)
        => result is CkrArgumentsBad or CkrMechanismInvalid or CkrMechanismParamInvalid;

    private static bool IsKeyMismatchOrInvalid(nuint result)
        => result is CkrKeyTypeInconsistent or CkrKeyUnwrappable or CkrKeyFunctionNotPermitted or CkrMechanismInvalid;

    private static Pkcs11KeyPairTemplate CreateRsaEncryptDecryptKeyPair(ReadOnlySpan<byte> label, ReadOnlySpan<byte> id, bool token)
    {
        byte[] labelBytes = label.ToArray();
        byte[] idBytes = id.ToArray();

        return new Pkcs11KeyPairTemplate(
        [
            Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.PublicKey),
            Pkcs11ObjectAttribute.KeyType(Pkcs11AttributeTypes.KeyType, Pkcs11KeyTypes.Rsa),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, token),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, false),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Encrypt, true),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, labelBytes),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Id, idBytes),
            Pkcs11ObjectAttribute.Nuint(Pkcs11AttributeTypes.ModulusBits, 2048),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.PublicExponent, new byte[] { 0x01, 0x00, 0x01 })
        ],
        [
            Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.PrivateKey),
            Pkcs11ObjectAttribute.KeyType(Pkcs11AttributeTypes.KeyType, Pkcs11KeyTypes.Rsa),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, token),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, true),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Decrypt, true),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Sensitive, true),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Extractable, false),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, labelBytes),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Id, idBytes)
        ]);
    }

    private static Pkcs11ObjectAttribute[] CreateGenericSecretHmacKeyTemplate(ReadOnlySpan<byte> label, ReadOnlySpan<byte> id)
        =>
        [
            Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.SecretKey),
            Pkcs11ObjectAttribute.KeyType(Pkcs11AttributeTypes.KeyType, Pkcs11KeyTypes.GenericSecret),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, false),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, true),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Sign, true),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Verify, true),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Sensitive, true),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Extractable, false),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, label.ToArray()),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Id, id.ToArray()),
            Pkcs11ObjectAttribute.Nuint(Pkcs11AttributeTypes.ValueLen, 32)
        ];

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
        catch (Pkcs11Exception ex) when (ex.Result.Value is CkrPinIncorrect or CkrUserAlreadyLoggedIn)
        {
        }
    }

    private static bool IsOperationStateUnavailable(Pkcs11Exception exception)
        => exception.Result.Value == CkrFunctionNotSupported;

    private static bool IsStrictRequired()
        => string.Equals(Environment.GetEnvironmentVariable("PKCS11_STRICT_REQUIRED"), "1", StringComparison.Ordinal);

    private static string? GetEnvironmentVariableOrDefault(string name, string? fallback)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrWhiteSpace(value) ? fallback : value;
    }

    private static string[] GetMissingRequiredEnvironmentVariables(params string[] names)
    {
        List<string> missing = [];
        foreach (string name in names)
        {
            if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(name)))
            {
                missing.Add(name);
            }
        }

        return [.. missing];
    }

    private static void ThrowIfStrictMissingEnvironment(string scenario, params string[] missing)
    {
        if (missing.Length != 0 && IsStrictRequired())
        {
            throw new Xunit.Sdk.XunitException($"Required PKCS#11 environment for {scenario} is missing: {string.Join(", ", missing)}.");
        }
    }

    private static bool RequireMechanismSupport(Pkcs11Module module, Pkcs11SlotId slotId, params (Pkcs11MechanismType MechanismType, Pkcs11MechanismFlags RequiredFlags, string DisplayName)[] requirements)
    {
        List<string> missing = [];
        foreach ((Pkcs11MechanismType mechanismType, Pkcs11MechanismFlags requiredFlags, string displayName) in requirements)
        {
            if (!SupportsMechanism(module, slotId, mechanismType, requiredFlags))
            {
                missing.Add(displayName);
            }
        }

        if (missing.Count != 0)
        {
            Console.WriteLine($"Capability-gated: module does not expose required mechanism support for this regression path: {string.Join(", ", missing)}.");
            return false;
        }

        return true;
    }

    private static bool SupportsMechanism(Pkcs11Module module, Pkcs11SlotId slotId, Pkcs11MechanismType mechanismType, Pkcs11MechanismFlags requiredFlags)
    {
        int mechanismCount = module.GetMechanismCount(slotId);
        if (mechanismCount == 0)
        {
            return false;
        }

        Pkcs11MechanismType[] mechanisms = new Pkcs11MechanismType[mechanismCount];
        if (!module.TryGetMechanisms(slotId, mechanisms, out int written))
        {
            return false;
        }

        bool mechanismFound = false;
        for (int i = 0; i < written; i++)
        {
            if (mechanisms[i] == mechanismType)
            {
                mechanismFound = true;
                break;
            }
        }

        if (!mechanismFound)
        {
            return false;
        }

        try
        {
            Pkcs11MechanismInfo info = module.GetMechanismInfo(slotId, mechanismType);
            return (info.Flags & requiredFlags) == requiredFlags;
        }
        catch (Pkcs11Exception)
        {
            return false;
        }
    }

    private static bool TryGetBooleanAttribute(Pkcs11Session session, Pkcs11ObjectHandle objectHandle, Pkcs11AttributeType attributeType, out bool value)
    {
        if (session.TryGetAttributeBoolean(objectHandle, attributeType, out bool nativeValue, out Pkcs11AttributeReadResult result) && result.IsReadable)
        {
            value = nativeValue;
            return true;
        }

        value = false;
        return false;
    }

    private static bool IsRecoverOrDigestKeyUnavailable(Pkcs11Exception exception)
        => IsUnsupportedOrUnavailableCode(exception.Result.Value);

    private static bool IsCombinedUpdateUnavailable(Pkcs11Exception exception)
        => IsUnsupportedOrUnavailableCode(exception.Result.Value);

    private static bool IsUnsupportedOrUnavailableCode(nuint result)
        => result is
            CkrFunctionNotSupported or
            CkrKeyTypeInconsistent or
            CkrKeyUnwrappable or
            CkrKeyFunctionNotPermitted or
            CkrMechanismInvalid or
            CkrMechanismParamInvalid or
            CkrOperationActive or
            CkrOperationNotInitialized or
            CkrArgumentsBad;

    [Fact]
    public void BatchedAttributeReadsReturnMixedReadableAndInvalidAttributes()
    {
        if (!TryCreateCryptContext(out TestContext? context))
        {
            return;
        }

        using TestContext activeContext = context!;
        using Pkcs11Session session = activeContext.Module.OpenSession(activeContext.SlotId, readWrite: true);
        LoginUser(session, activeContext.PinUtf8);

        byte[] label = Encoding.UTF8.GetBytes("batch-attr-test");
        TryDestroyDataObjectByLabel(session, label);

        Pkcs11ObjectHandle handle = session.CreateObject(
        [
            Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.Data),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, false),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, false),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Modifiable, true),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, label),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Application, Encoding.UTF8.GetBytes("pkcs11-batch-test")),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Value, new byte[] { 0x01, 0x02, 0x03, 0x04 })
        ]);

        try
        {
            IReadOnlyList<Pkcs11AttributeValue> values = session.GetAttributeValues(handle,
            [
                Pkcs11AttributeTypes.Class,
                Pkcs11AttributeTypes.Label,
                Pkcs11AttributeTypes.Token,
                Pkcs11AttributeTypes.KeyType
            ]);

            Assert.Equal(4, values.Count);
            Assert.Equal(Pkcs11AttributeReadStatus.Success, values[0].Result.Status);
            Assert.Equal(Pkcs11ObjectClasses.Data.NativeValue.Value, IntPtr.Size == sizeof(uint)
                ? BitConverter.ToUInt32(values[0].Value!)
                : BitConverter.ToUInt64(values[0].Value!));
            Assert.Equal("batch-attr-test", Encoding.UTF8.GetString(values[1].Value!));
            Assert.Equal(new byte[] { 0 }, values[2].Value);
            Assert.Equal(Pkcs11AttributeReadStatus.TypeInvalid, values[3].Result.Status);
            Assert.Null(values[3].Value);
        }
        finally
        {
            TryDestroyObject(session, handle);
            session.Logout();
        }
    }

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
        catch (Pkcs11Exception ex) when (ex.Result.Value == CkrObjectHandleInvalid)
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
        string[] missing = GetMissingRequiredEnvironmentVariables("PKCS11_MODULE_PATH", "PKCS11_TOKEN_LABEL", "PKCS11_USER_PIN");
        ThrowIfStrictMissingEnvironment("admin context", missing);

        if (missing.Length != 0)
        {
            context = null;
            return false;
        }

        Pkcs11Module module = Pkcs11Module.Load(modulePath!);

        try
        {
            module.Initialize();
            context = new AdminContext(
                module,
                FindSlotByTokenLabel(module, tokenLabel!),
                Encoding.UTF8.GetBytes(userPin!),
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

        if (!string.Equals(enableProvisioning, "1", StringComparison.Ordinal))
        {
            context = null;
            return false;
        }

        string[] missing = GetMissingRequiredEnvironmentVariables("PKCS11_MODULE_PATH", "PKCS11_SO_PIN");
        ThrowIfStrictMissingEnvironment("provisioning context", missing);
        if (missing.Length != 0)
        {
            context = null;
            return false;
        }

        Pkcs11Module module = Pkcs11Module.Load(modulePath!);

        try
        {
            module.Initialize();
            context = new ProvisioningContext(
                module,
                FindProvisioningSlot(module),
                Encoding.UTF8.GetBytes(soPin!),
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
        string[] missing = GetMissingRequiredEnvironmentVariables("PKCS11_MODULE_PATH", "PKCS11_TOKEN_LABEL", "PKCS11_USER_PIN");
        ThrowIfStrictMissingEnvironment("generation context", missing);

        if (missing.Length != 0)
        {
            context = null;
            return false;
        }

        Pkcs11Module module = Pkcs11Module.Load(modulePath!);

        try
        {
            module.Initialize();
            Pkcs11SlotId slotId = FindSlotByTokenLabel(module, tokenLabel!);
            Pkcs11Session session = module.OpenSession(slotId, readWrite: true);
            byte[] pinUtf8 = Encoding.UTF8.GetBytes(userPin!);
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
        string? findClass = GetEnvironmentVariableOrDefault("PKCS11_FIND_CLASS", "secret");
        string? findKeyType = GetEnvironmentVariableOrDefault("PKCS11_FIND_KEY_TYPE", "aes");
        string[] missing = GetMissingRequiredEnvironmentVariables("PKCS11_MODULE_PATH", "PKCS11_TOKEN_LABEL", "PKCS11_USER_PIN");
        ThrowIfStrictMissingEnvironment("crypt context", missing);

        if (missing.Length != 0)
        {
            context = null;
            return false;
        }

        Pkcs11Module module = Pkcs11Module.Load(modulePath!);

        try
        {
            module.Initialize();
            Pkcs11SlotId slotId = FindSlotByTokenLabel(module, tokenLabel!);
            Pkcs11Session session = module.OpenSession(slotId);
            byte[] pinUtf8 = Encoding.UTF8.GetBytes(userPin!);
            LoginUser(session, pinUtf8);

            Pkcs11ObjectSearchParameters search = new(
                label: ParseHex(Environment.GetEnvironmentVariable("PKCS11_FIND_LABEL"), Encoding.UTF8.GetBytes),
                id: ParseHex(Environment.GetEnvironmentVariable("PKCS11_FIND_ID_HEX"), Convert.FromHexString),
                objectClass: ParseObjectClass(findClass!),
                keyType: ParseKeyType(findKeyType!),
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
        string? signMechanismText = GetEnvironmentVariableOrDefault("PKCS11_SIGN_MECHANISM", "0x00000040");
        string? signClass = GetEnvironmentVariableOrDefault("PKCS11_SIGN_FIND_CLASS", "private");
        string? signKeyType = GetEnvironmentVariableOrDefault("PKCS11_SIGN_FIND_KEY_TYPE", "rsa");
        string? verifyClass = GetEnvironmentVariableOrDefault("PKCS11_VERIFY_FIND_CLASS", "public");
        string? verifyKeyType = GetEnvironmentVariableOrDefault("PKCS11_VERIFY_FIND_KEY_TYPE", "rsa");
        string[] missing = GetMissingRequiredEnvironmentVariables("PKCS11_MODULE_PATH", "PKCS11_TOKEN_LABEL", "PKCS11_USER_PIN");
        ThrowIfStrictMissingEnvironment("sign/verify context", missing);

        if (missing.Length != 0)
        {
            context = null;
            return false;
        }

        Pkcs11Module module = Pkcs11Module.Load(modulePath!);

        try
        {
            module.Initialize();
            Pkcs11SlotId slotId = FindSlotByTokenLabel(module, tokenLabel!);
            Pkcs11Session session = module.OpenSession(slotId);
            byte[] pinUtf8 = Encoding.UTF8.GetBytes(userPin!);
            LoginUser(session, pinUtf8);

            string? signLabelText = Environment.GetEnvironmentVariable("PKCS11_SIGN_FIND_LABEL");
            string? signIdText = Environment.GetEnvironmentVariable("PKCS11_SIGN_FIND_ID_HEX");
            string? verifyLabelText = GetEnvironmentVariableOrDefault("PKCS11_VERIFY_FIND_LABEL", signLabelText);
            string? verifyIdText = GetEnvironmentVariableOrDefault("PKCS11_VERIFY_FIND_ID_HEX", signIdText);

            Pkcs11ObjectSearchParameters signSearch = new(
                label: ParseHex(signLabelText, Encoding.UTF8.GetBytes),
                id: ParseHex(signIdText, Convert.FromHexString),
                objectClass: ParseObjectClass(signClass!),
                keyType: ParseKeyType(signKeyType!),
                requireSign: ParseNullableBoolean(Environment.GetEnvironmentVariable("PKCS11_SIGN_REQUIRE_SIGN")));

            Pkcs11ObjectSearchParameters verifySearch = new(
                label: ParseHex(verifyLabelText, Encoding.UTF8.GetBytes),
                id: ParseHex(verifyIdText, Convert.FromHexString),
                objectClass: ParseObjectClass(verifyClass!),
                keyType: ParseKeyType(verifyKeyType!),
                requireVerify: ParseNullableBoolean(Environment.GetEnvironmentVariable("PKCS11_VERIFY_REQUIRE_VERIFY")));

            Assert.True(session.TryFindObject(signSearch, out Pkcs11ObjectHandle signKeyHandle));
            Assert.True(session.TryFindObject(verifySearch, out Pkcs11ObjectHandle verifyKeyHandle));

            Pkcs11MechanismType mechanismType = new(ParseNuint(signMechanismText!));
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
