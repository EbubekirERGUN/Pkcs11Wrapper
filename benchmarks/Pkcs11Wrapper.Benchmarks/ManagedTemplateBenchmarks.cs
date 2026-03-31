using BenchmarkDotNet.Attributes;

namespace Pkcs11Wrapper.Benchmarks;

[MemoryDiagnoser]
[ShortRunJob]
public class ManagedTemplateBenchmarks
{
    private readonly byte[] _label = "benchmark-template"u8.ToArray();
    private readonly byte[] _id = [0xAA, 0x10];
    private readonly byte[] _curveParameters = Convert.FromHexString("06082A8648CE3D030107");

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Managed")]
    public Pkcs11ObjectAttribute[] CreateAesEncryptDecryptTemplate()
        => Pkcs11ProvisioningTemplates.CreateAesEncryptDecryptSecretKey(_label, _id, token: false, extractable: false, valueLength: 32);

    [Benchmark]
    [BenchmarkCategory("Managed")]
    public Pkcs11KeyPairTemplate CreateRsaSignVerifyTemplate()
        => Pkcs11ProvisioningTemplates.CreateRsaSignVerifyKeyPair(_label, _id, token: false, modulusBits: 2048);

    [Benchmark]
    [BenchmarkCategory("Managed")]
    public Pkcs11KeyPairTemplate CreateEcSignVerifyTemplate()
        => Pkcs11ProvisioningTemplates.CreateEcSignVerifyKeyPair(_curveParameters, _label, _id, token: false);
}
