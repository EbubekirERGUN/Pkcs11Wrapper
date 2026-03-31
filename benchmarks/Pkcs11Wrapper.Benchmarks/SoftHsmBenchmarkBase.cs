namespace Pkcs11Wrapper.Benchmarks;

public abstract class SoftHsmBenchmarkBase
{
    protected SoftHsmBenchmarkEnvironment Environment { get; private set; } = null!;

    protected void InitializeEnvironment()
        => Environment = SoftHsmBenchmarkEnvironment.Create();

    protected void DisposeEnvironment()
    {
        Environment.Dispose();
        Environment = null!;
    }

    protected static byte[] CreatePayload(int length, byte seed)
    {
        byte[] payload = new byte[length];
        for (int i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)(seed + i);
        }

        return payload;
    }
}
