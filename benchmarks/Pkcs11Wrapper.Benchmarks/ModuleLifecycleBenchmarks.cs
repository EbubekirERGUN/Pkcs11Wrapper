using BenchmarkDotNet.Attributes;

namespace Pkcs11Wrapper.Benchmarks;

[MemoryDiagnoser]
[ShortRunJob]
public class ModuleLifecycleBenchmarks : SoftHsmBenchmarkBase
{
    private Pkcs11SlotId[] _slotBuffer = [];
    private Pkcs11MechanismType[] _mechanismBuffer = [];

    [GlobalSetup]
    public void GlobalSetup()
    {
        InitializeEnvironment();
        _slotBuffer = new Pkcs11SlotId[Math.Max(Environment.Module.GetSlotCount(tokenPresentOnly: true), 1)];
        _mechanismBuffer = new Pkcs11MechanismType[Math.Max(Environment.Module.GetMechanismCount(Environment.SlotId), 1)];
    }

    [GlobalCleanup]
    public void GlobalCleanup() => DisposeEnvironment();

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Module")]
    public string LoadInitializeGetInfoFinalizeDispose()
    {
        using Pkcs11Module module = Pkcs11Module.Load(Environment.ModulePath);
        module.Initialize();
        string description = module.GetInfo().LibraryDescription;
        module.FinalizeModule();
        return description;
    }

    [Benchmark]
    [BenchmarkCategory("Module")]
    public int GetSlotCount()
        => Environment.Module.GetSlotCount(tokenPresentOnly: true);

    [Benchmark]
    [BenchmarkCategory("Module")]
    public int EnumerateSlots()
    {
        Environment.Module.TryGetSlots(_slotBuffer, out int written, tokenPresentOnly: true);
        return written;
    }

    [Benchmark]
    [BenchmarkCategory("Module")]
    public int EnumerateMechanisms()
    {
        Environment.Module.TryGetMechanisms(Environment.SlotId, _mechanismBuffer, out int written);
        return written;
    }

    [Benchmark]
    [BenchmarkCategory("Module")]
    public ulong GetAesCbcPadMechanismFlags()
        => (ulong)Environment.Module.GetMechanismInfo(Environment.SlotId, Pkcs11MechanismTypes.AesCbcPad).Flags;
}
