using System.Text;
using Pkcs11Wrapper;
using Pkcs11Wrapper.Native;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper.Native.Tests;

[Collection(Pkcs11RuntimeCollection.Name)]
public sealed class Pkcs11V3ShimRuntimeTests
{
    private static readonly byte[] ExpectedPinUtf8 = "123456"u8.ToArray();
    private static readonly byte[] ExpectedUsernameUtf8 = "runtime-user"u8.ToArray();
    private static readonly byte[] ExpectedMechanismParameter = [0xCA, 0xFE, 0x01];
    private static readonly byte[] MessageParameter = [0x10, 0x20, 0x30];
    private static readonly byte[] AssociatedData = Encoding.UTF8.GetBytes("aad");
    private static readonly byte[] Plaintext = Encoding.UTF8.GetBytes("pkcs11-v3-runtime");
    private const nuint CkrOperationNotInitialized = 0x00000091u;

    [Fact]
    public void InterfaceDiscoveryEnumeratesRuntimeShimInterface()
    {
        if (!TryCreateModule(out Pkcs11Module? module))
        {
            return;
        }

        using Pkcs11Module activeModule = module!;
        Assert.True(activeModule.SupportsInterfaceDiscovery);
        Assert.Equal(1, activeModule.GetInterfaceCount());

        Assert.False(activeModule.TryGetInterfaces(Span<Pkcs11Interface>.Empty, out int requiredCount));
        Assert.Equal(1, requiredCount);

        Pkcs11Interface[] interfaces = new Pkcs11Interface[requiredCount];
        Assert.True(activeModule.TryGetInterfaces(interfaces, out int written));
        Assert.Equal(1, written);
        Assert.Equal("PKCS 11", interfaces[0].Name);
        Assert.Equal(new CK_VERSION(3, 0), interfaces[0].Version);
        Assert.Equal(Pkcs11InterfaceFlags.None, interfaces[0].Flags);

        Assert.True(activeModule.TryGetInterface("PKCS 11"u8, new CK_VERSION(3, 0), Pkcs11InterfaceFlags.None, out Pkcs11Interface selectedInterface));
        Assert.Equal(interfaces[0], selectedInterface);
        Assert.False(activeModule.TryGetInterface("not-supported"u8, new CK_VERSION(3, 0), Pkcs11InterfaceFlags.None, out _));
    }

    [Fact]
    public void LoginUserAndMessageEncryptFlowWorkAgainstRuntimeShim()
    {
        if (!TryCreateModule(out Pkcs11Module? module))
        {
            return;
        }

        using Pkcs11Module activeModule = module!;
        using Pkcs11Session session = activeModule.OpenSession(new Pkcs11SlotId(1), readWrite: true);
        session.LoginUser(Pkcs11UserType.User, ExpectedPinUtf8, ExpectedUsernameUtf8);

        Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.AesCbc, ExpectedMechanismParameter);
        session.MessageEncryptInit(new Pkcs11ObjectHandle(1), mechanism);

        byte[] expectedCiphertext = BuildExpectedCiphertext(MessageParameter, AssociatedData, Plaintext);
        Assert.Equal(expectedCiphertext.Length, session.GetMessageEncryptOutputLength(MessageParameter, AssociatedData, Plaintext));

        Span<byte> tooSmall = stackalloc byte[expectedCiphertext.Length - 1];
        Assert.False(session.TryEncryptMessage(MessageParameter, AssociatedData, Plaintext, tooSmall, out int requiredLength));
        Assert.Equal(expectedCiphertext.Length, requiredLength);

        byte[] ciphertext = new byte[requiredLength];
        Assert.True(session.TryEncryptMessage(MessageParameter, AssociatedData, Plaintext, ciphertext, out int written));
        Assert.Equal(expectedCiphertext.Length, written);
        Assert.True(expectedCiphertext.AsSpan().SequenceEqual(ciphertext.AsSpan(0, written)));

        session.MessageEncryptFinal();
    }

    [Fact]
    public void SessionCancelClearsActiveMessageOperationOnRuntimeShim()
    {
        if (!TryCreateModule(out Pkcs11Module? module))
        {
            return;
        }

        using Pkcs11Module activeModule = module!;
        using Pkcs11Session session = activeModule.OpenSession(new Pkcs11SlotId(1), readWrite: true);
        session.LoginUser(Pkcs11UserType.User, ExpectedPinUtf8, ExpectedUsernameUtf8);

        Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.AesCbc, ExpectedMechanismParameter);
        session.MessageEncryptInit(new Pkcs11ObjectHandle(1), mechanism);
        session.SessionCancel();

        Pkcs11Exception exception = Assert.Throws<Pkcs11Exception>(() => session.GetMessageEncryptOutputLength(MessageParameter, AssociatedData, Plaintext));
        Assert.Equal(CkrOperationNotInitialized, exception.Result.Value);

        session.MessageEncryptInit(new Pkcs11ObjectHandle(1), mechanism);
        byte[] ciphertext = new byte[session.GetMessageEncryptOutputLength(MessageParameter, AssociatedData, Plaintext)];
        Assert.True(session.TryEncryptMessage(MessageParameter, AssociatedData, Plaintext, ciphertext, out int written));
        Assert.Equal(ciphertext.Length, written);
        session.MessageEncryptFinal();
    }

    private static bool TryCreateModule(out Pkcs11Module? module)
    {
        string? shimPath = ResolveShimPath();
        if (string.IsNullOrWhiteSpace(shimPath) || !File.Exists(shimPath))
        {
            module = null;
            return false;
        }

        module = Pkcs11Module.Load(shimPath);
        module.Initialize();
        return true;
    }

    private static string? ResolveShimPath()
    {
        if (!OperatingSystem.IsLinux())
        {
            return null;
        }

        string? configuredPath = Environment.GetEnvironmentVariable("PKCS11_V3_SHIM_PATH");
        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            return configuredPath;
        }

        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Pkcs11Wrapper.sln")))
            {
                return Path.Combine(current.FullName, "artifacts", "test-fixtures", "pkcs11-v3-shim", "libpkcs11-v3-shim.so");
            }

            current = current.Parent;
        }

        return null;
    }

    private static byte[] BuildExpectedCiphertext(ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext)
    {
        byte[] ciphertext = new byte[parameter.Length + associatedData.Length + plaintext.Length];
        int offset = 0;
        parameter.CopyTo(ciphertext);
        offset += parameter.Length;
        associatedData.CopyTo(ciphertext.AsSpan(offset));
        offset += associatedData.Length;

        for (int i = 0; i < plaintext.Length; i++)
        {
            ciphertext[offset + i] = (byte)(plaintext[i] ^ 0x5A);
        }

        return ciphertext;
    }
}
