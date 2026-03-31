using BenchmarkDotNet.Attributes;

namespace Pkcs11Wrapper.Benchmarks;

[MemoryDiagnoser]
[ShortRunJob]
public class CryptoBenchmarks : SoftHsmBenchmarkBase
{
    private readonly byte[] _digestData = CreatePayload(1024, 0x31);
    private readonly byte[] _signData = CreatePayload(1024, 0x41);
    private readonly byte[] _plaintext = CreatePayload(1024, 0x51);
    private byte[] _digestBuffer = [];
    private byte[] _ciphertext = [];
    private byte[] _encryptBuffer = [];
    private byte[] _decryptBuffer = [];
    private byte[] _signature = [];
    private byte[] _signatureBuffer = [];

    [GlobalSetup]
    public void GlobalSetup()
    {
        InitializeEnvironment();

        Pkcs11Mechanism digestMechanism = new(Pkcs11MechanismTypes.Sha256);
        _digestBuffer = new byte[Environment.Session.GetDigestOutputLength(digestMechanism, _digestData)];

        Pkcs11Mechanism encryptionMechanism = new(Pkcs11MechanismTypes.AesCbcPad, Environment.AesIv);
        _encryptBuffer = new byte[Environment.Session.GetEncryptOutputLength(Environment.AesKeyHandle, encryptionMechanism, _plaintext)];
        Environment.Session.TryEncrypt(Environment.AesKeyHandle, encryptionMechanism, _plaintext, _encryptBuffer, out int encryptedLength);
        _ciphertext = _encryptBuffer.AsSpan(0, encryptedLength).ToArray();
        _decryptBuffer = new byte[Environment.Session.GetDecryptOutputLength(Environment.AesKeyHandle, encryptionMechanism, _ciphertext)];

        Pkcs11Mechanism signMechanism = new(Pkcs11MechanismTypes.Sha256RsaPkcs);
        _signatureBuffer = new byte[Environment.Session.GetSignOutputLength(Environment.RsaPrivateKeyHandle, signMechanism, _signData)];
        Environment.Session.TrySign(Environment.RsaPrivateKeyHandle, signMechanism, _signData, _signatureBuffer, out int signatureLength);
        _signature = _signatureBuffer.AsSpan(0, signatureLength).ToArray();
    }

    [GlobalCleanup]
    public void GlobalCleanup() => DisposeEnvironment();

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Crypto")]
    public int GenerateRandom32()
    {
        Span<byte> buffer = stackalloc byte[32];
        Environment.Session.GenerateRandom(buffer);
        return buffer[0];
    }

    [Benchmark]
    [BenchmarkCategory("Crypto")]
    public int DigestSha256_1KiB()
    {
        Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.Sha256);
        return Environment.Session.TryDigest(mechanism, _digestData, _digestBuffer, out int written)
            ? written
            : 0;
    }

    [Benchmark]
    [BenchmarkCategory("Crypto")]
    public int DigestSha256Multipart_1KiB()
    {
        Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.Sha256);
        Environment.Session.DigestInit(mechanism);
        Environment.Session.DigestUpdate(_digestData.AsSpan(0, 512));
        Environment.Session.DigestUpdate(_digestData.AsSpan(512));
        return Environment.Session.TryDigestFinal(_digestBuffer, out int written)
            ? written
            : 0;
    }

    [Benchmark]
    [BenchmarkCategory("Crypto")]
    public int EncryptAesCbcPad_1KiB()
    {
        Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.AesCbcPad, Environment.AesIv);
        return Environment.Session.TryEncrypt(Environment.AesKeyHandle, mechanism, _plaintext, _encryptBuffer, out int written)
            ? written
            : 0;
    }

    [Benchmark]
    [BenchmarkCategory("Crypto")]
    public int DecryptAesCbcPad_1KiB()
    {
        Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.AesCbcPad, Environment.AesIv);
        return Environment.Session.TryDecrypt(Environment.AesKeyHandle, mechanism, _ciphertext, _decryptBuffer, out int written)
            ? written
            : 0;
    }

    [Benchmark]
    [BenchmarkCategory("Crypto")]
    public int SignSha256RsaPkcs_1KiB()
    {
        Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.Sha256RsaPkcs);
        return Environment.Session.TrySign(Environment.RsaPrivateKeyHandle, mechanism, _signData, _signatureBuffer, out int written)
            ? written
            : 0;
    }

    [Benchmark]
    [BenchmarkCategory("Crypto")]
    public bool VerifySha256RsaPkcs_1KiB()
    {
        Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.Sha256RsaPkcs);
        return Environment.Session.Verify(Environment.RsaPublicKeyHandle, mechanism, _signData, _signature);
    }
}
