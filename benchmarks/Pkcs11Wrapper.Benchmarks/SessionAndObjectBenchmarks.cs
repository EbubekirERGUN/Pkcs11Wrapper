using System.Text;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Pkcs11Wrapper.Native;

namespace Pkcs11Wrapper.Benchmarks;

[MemoryDiagnoser]
[ShortRunJob]
public class SessionAndObjectBenchmarks : SoftHsmBenchmarkBase
{
    private const nuint CkrUserAlreadyLoggedIn = 0x00000100u;
    private const int ConcurrentIterationsPerWorker = 256;

    private int _sequence;
    private Pkcs11Session[] _concurrentSessions8 = [];
    private Pkcs11Session[] _concurrentSessions32 = [];

    [GlobalSetup]
    public void GlobalSetup()
    {
        InitializeEnvironment();
        _concurrentSessions8 = OpenConcurrentSessions(workerCount: 8);
        _concurrentSessions32 = OpenConcurrentSessions(workerCount: 32);
    }

    [GlobalCleanup]
    public void GlobalCleanup()
    {
        DisposeSessions(_concurrentSessions32);
        DisposeSessions(_concurrentSessions8);
        DisposeEnvironment();
    }

    [Benchmark(Baseline = true)]
    [BenchmarkCategory("Session")]
    public Pkcs11SessionInfo OpenReadOnlySessionAndGetInfo()
    {
        using Pkcs11Session session = Environment.Module.OpenSession(Environment.SlotId);
        return session.GetInfo();
    }

    [Benchmark]
    [BenchmarkCategory("Session")]
    public Pkcs11SessionInfo OpenReadWriteLoginLogoutSession()
    {
        using Pkcs11Session session = Environment.Module.OpenSession(Environment.SlotId, readWrite: true);

        TryLoginUser(session);

        Pkcs11SessionInfo info = session.GetInfo();
        session.Logout();
        return info;
    }

    [Benchmark]
    [BenchmarkCategory("Concurrent")]
    public long GetSessionInfoBurst8Workers() => RunGetInfoBurst(_concurrentSessions8);

    [Benchmark]
    [BenchmarkCategory("Concurrent")]
    public long GetSessionInfoBurst32Workers() => RunGetInfoBurst(_concurrentSessions32);

    [Benchmark]
    [BenchmarkCategory("Object")]
    public nuint FindAesKeyByLabel()
    {
        Environment.Session.TryFindObject(
            new Pkcs11ObjectSearchParameters(
                label: Environment.AesLabel,
                id: Environment.AesId,
                objectClass: Pkcs11ObjectClasses.SecretKey,
                keyType: Pkcs11KeyTypes.Aes,
                requireEncrypt: true,
                requireDecrypt: true),
            out Pkcs11ObjectHandle handle);

        return handle.Value;
    }

    [Benchmark]
    [BenchmarkCategory("Object")]
    public int ReadAesKeyLabelAttribute()
        => Environment.ReadRequiredAttributeBytes(Environment.AesKeyHandle, Pkcs11AttributeTypes.Label).Length;

    [Benchmark]
    [BenchmarkCategory("Object")]
    public nuint CreateUpdateDestroyDataObject()
    {
        int next = Interlocked.Increment(ref _sequence);
        byte[] label = Encoding.UTF8.GetBytes($"bench-data-{next:N0}");
        byte[] updatedLabel = Encoding.UTF8.GetBytes($"bench-data-{next:N0}-updated");
        byte[] application = Encoding.UTF8.GetBytes("benchmarks");
        byte[] value = [(byte)0xBE, (byte)0xEF, (byte)(next & 0xFF), (byte)((next >> 8) & 0xFF)];

        Pkcs11ObjectHandle handle = Environment.Session.CreateObject(
        [
            Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.Data),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, false),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, false),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Modifiable, true),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, label),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Application, application),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Value, value)
        ]);

        try
        {
            Environment.Session.SetAttributeValue(handle,
            [
                Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, updatedLabel)
            ]);

            return Environment.Session.GetObjectSize(handle);
        }
        finally
        {
            Environment.Session.DestroyObject(handle);
        }
    }

    [Benchmark]
    [BenchmarkCategory("Object")]
    public nuint GenerateDestroyAesKey()
    {
        int next = Interlocked.Increment(ref _sequence);
        byte[] label = Encoding.UTF8.GetBytes($"bench-aes-{next:N0}");
        byte[] id = BitConverter.GetBytes(next);
        Pkcs11ObjectHandle handle = Environment.Session.GenerateKey(
            new Pkcs11Mechanism(Pkcs11MechanismTypes.AesKeyGen),
            Pkcs11ProvisioningTemplates.CreateAesEncryptDecryptSecretKey(label, id, token: false, extractable: false, valueLength: 32));

        try
        {
            return Environment.Session.GetObjectSize(handle);
        }
        finally
        {
            Environment.Session.DestroyObject(handle);
        }
    }

    [Benchmark]
    [BenchmarkCategory("Object")]
    public nuint GenerateDestroyRsaKeyPair()
    {
        int next = Interlocked.Increment(ref _sequence);
        byte[] label = Encoding.UTF8.GetBytes($"bench-rsa-{next:N0}");
        byte[] id = BitConverter.GetBytes(next);
        Pkcs11KeyPairTemplate template = Pkcs11ProvisioningTemplates.CreateRsaSignVerifyKeyPair(label, id, token: false, modulusBits: 2048, extractable: false);
        Pkcs11GeneratedKeyPair pair = Environment.Session.GenerateKeyPair(new Pkcs11Mechanism(Pkcs11MechanismTypes.RsaPkcsKeyPairGen), template.PublicKeyAttributes, template.PrivateKeyAttributes);

        try
        {
            return Environment.Session.GetObjectSize(pair.PrivateKeyHandle);
        }
        finally
        {
            Environment.Session.DestroyObject(pair.PrivateKeyHandle);
            Environment.Session.DestroyObject(pair.PublicKeyHandle);
        }
    }

    private Pkcs11Session[] OpenConcurrentSessions(int workerCount)
    {
        Pkcs11Session[] sessions = new Pkcs11Session[workerCount];
        for (int i = 0; i < sessions.Length; i++)
        {
            sessions[i] = Environment.Module.OpenSession(Environment.SlotId);
        }

        return sessions;
    }

    private void TryLoginUser(Pkcs11Session session)
    {
        try
        {
            session.Login(Pkcs11UserType.User, Environment.UserPin);
        }
        catch (Pkcs11Exception ex) when (ex.Result.Value == CkrUserAlreadyLoggedIn)
        {
        }
    }

    private static void DisposeSessions(Pkcs11Session[] sessions)
    {
        for (int i = sessions.Length - 1; i >= 0; i--)
        {
            sessions[i].Dispose();
        }
    }

    private static long RunGetInfoBurst(Pkcs11Session[] sessions)
    {
        long total = 0;
        Parallel.For(
            fromInclusive: 0,
            toExclusive: sessions.Length,
            localInit: static () => 0L,
            body: (index, _, local) =>
            {
                Pkcs11Session session = sessions[index];
                for (int iteration = 0; iteration < ConcurrentIterationsPerWorker; iteration++)
                {
                    local += (long)session.GetInfo().SlotId.Value;
                }

                return local;
            },
            localFinally: local => Interlocked.Add(ref total, local));

        return total;
    }
}
