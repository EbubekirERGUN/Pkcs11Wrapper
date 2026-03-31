using System.Text;
using Pkcs11Wrapper.Native;

namespace Pkcs11Wrapper.Benchmarks;

public sealed class SoftHsmBenchmarkEnvironment : IDisposable
{
    private const nuint CkrUserAlreadyLoggedIn = 0x00000100u;

    private SoftHsmBenchmarkEnvironment(
        string modulePath,
        string tokenLabel,
        byte[] userPin,
        byte[] aesLabel,
        byte[] aesId,
        byte[] rsaLabel,
        byte[] rsaId,
        byte[] aesIv,
        Pkcs11Module module,
        Pkcs11SlotId slotId,
        Pkcs11Session session,
        Pkcs11ObjectHandle aesKeyHandle,
        Pkcs11ObjectHandle rsaPrivateKeyHandle,
        Pkcs11ObjectHandle rsaPublicKeyHandle)
    {
        ModulePath = modulePath;
        TokenLabel = tokenLabel;
        UserPin = userPin;
        AesLabel = aesLabel;
        AesId = aesId;
        RsaLabel = rsaLabel;
        RsaId = rsaId;
        AesIv = aesIv;
        Module = module;
        SlotId = slotId;
        Session = session;
        AesKeyHandle = aesKeyHandle;
        RsaPrivateKeyHandle = rsaPrivateKeyHandle;
        RsaPublicKeyHandle = rsaPublicKeyHandle;
    }

    public string ModulePath { get; }

    public string TokenLabel { get; }

    public byte[] UserPin { get; }

    public byte[] AesLabel { get; }

    public byte[] AesId { get; }

    public byte[] RsaLabel { get; }

    public byte[] RsaId { get; }

    public byte[] AesIv { get; }

    public Pkcs11Module Module { get; }

    public Pkcs11SlotId SlotId { get; }

    public Pkcs11Session Session { get; }

    public Pkcs11ObjectHandle AesKeyHandle { get; }

    public Pkcs11ObjectHandle RsaPrivateKeyHandle { get; }

    public Pkcs11ObjectHandle RsaPublicKeyHandle { get; }

    public static SoftHsmBenchmarkEnvironment Create()
    {
        string modulePath = RequireEnvironment("PKCS11_MODULE_PATH");
        string tokenLabel = RequireEnvironment("PKCS11_TOKEN_LABEL");
        byte[] userPin = Encoding.UTF8.GetBytes(RequireEnvironment("PKCS11_USER_PIN"));
        byte[] aesLabel = Encoding.UTF8.GetBytes(GetEnvironmentVariableOrDefault("PKCS11_FIND_LABEL", "ci-aes"));
        byte[] aesId = Convert.FromHexString(GetEnvironmentVariableOrDefault("PKCS11_FIND_ID_HEX", "A1"));
        byte[] rsaLabel = Encoding.UTF8.GetBytes(GetEnvironmentVariableOrDefault("PKCS11_SIGN_FIND_LABEL", "ci-rsa"));
        byte[] rsaId = Convert.FromHexString(GetEnvironmentVariableOrDefault("PKCS11_SIGN_FIND_ID_HEX", "B2"));
        byte[] aesIv = Convert.FromHexString(GetEnvironmentVariableOrDefault("PKCS11_MECHANISM_PARAM_HEX", "00112233445566778899AABBCCDDEEFF"));

        Pkcs11Module module = Pkcs11Module.Load(modulePath);
        try
        {
            module.Initialize();
            Pkcs11SlotId slotId = FindSlotByTokenLabel(module, tokenLabel);
            Pkcs11Session session = module.OpenSession(slotId, readWrite: true);
            TryLoginUser(session, userPin);

            try
            {
                Pkcs11ObjectHandle aesKeyHandle = FindRequiredObjectHandle(
                    session,
                    new Pkcs11ObjectSearchParameters(
                        label: aesLabel,
                        id: aesId,
                        objectClass: Pkcs11ObjectClasses.SecretKey,
                        keyType: Pkcs11KeyTypes.Aes,
                        requireEncrypt: true,
                        requireDecrypt: true));

                Pkcs11ObjectHandle rsaPrivateKeyHandle = FindRequiredObjectHandle(
                    session,
                    new Pkcs11ObjectSearchParameters(
                        label: rsaLabel,
                        id: rsaId,
                        objectClass: Pkcs11ObjectClasses.PrivateKey,
                        keyType: Pkcs11KeyTypes.Rsa,
                        requireSign: true));

                Pkcs11ObjectHandle rsaPublicKeyHandle = FindRequiredObjectHandle(
                    session,
                    new Pkcs11ObjectSearchParameters(
                        label: rsaLabel,
                        id: rsaId,
                        objectClass: Pkcs11ObjectClasses.PublicKey,
                        keyType: Pkcs11KeyTypes.Rsa,
                        requireVerify: true));

                return new SoftHsmBenchmarkEnvironment(
                    modulePath,
                    tokenLabel,
                    userPin,
                    aesLabel,
                    aesId,
                    rsaLabel,
                    rsaId,
                    aesIv,
                    module,
                    slotId,
                    session,
                    aesKeyHandle,
                    rsaPrivateKeyHandle,
                    rsaPublicKeyHandle);
            }
            catch
            {
                session.Dispose();
                throw;
            }
        }
        catch
        {
            module.Dispose();
            throw;
        }
    }

    public Pkcs11Session OpenUserSession(bool readWrite = false)
    {
        Pkcs11Session session = Module.OpenSession(SlotId, readWrite);
        TryLoginUser(session, UserPin);
        return session;
    }

    public byte[] ReadRequiredAttributeBytes(Pkcs11ObjectHandle handle, Pkcs11AttributeType attributeType)
    {
        Pkcs11AttributeReadResult info = Session.GetAttributeValueInfo(handle, attributeType);
        if (!info.IsReadable || info.Length > int.MaxValue)
        {
            throw new InvalidOperationException($"Attribute {attributeType} is not readable in the benchmark fixture.");
        }

        byte[] buffer = new byte[(int)info.Length];
        if (!Session.TryGetAttributeValue(handle, attributeType, buffer, out int written, out Pkcs11AttributeReadResult result) || !result.IsReadable)
        {
            throw new InvalidOperationException($"Failed to read attribute {attributeType} from the benchmark fixture.");
        }

        if (written == buffer.Length)
        {
            return buffer;
        }

        return buffer.AsSpan(0, written).ToArray();
    }

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

    private static string RequireEnvironment(string name)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        if (!string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        throw new InvalidOperationException(
            $"Required benchmark environment variable '{name}' is missing. Run eng/run-benchmarks.sh or eng/run-benchmarks.ps1 so the SoftHSM fixture is provisioned first.");
    }

    private static string GetEnvironmentVariableOrDefault(string name, string fallback)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrWhiteSpace(value) ? fallback : value;
    }

    private static void TryLoginUser(Pkcs11Session session, ReadOnlySpan<byte> pinUtf8)
    {
        try
        {
            session.Login(Pkcs11UserType.User, pinUtf8);
        }
        catch (Pkcs11Exception ex) when (ex.Result.Value == CkrUserAlreadyLoggedIn)
        {
        }
    }

    private static Pkcs11SlotId FindSlotByTokenLabel(Pkcs11Module module, string tokenLabel)
    {
        int slotCount = module.GetSlotCount();
        if (slotCount <= 0)
        {
            throw new InvalidOperationException("No PKCS#11 slots were exposed by the benchmark module.");
        }

        Pkcs11SlotId[] slots = new Pkcs11SlotId[slotCount];
        if (!module.TryGetSlots(slots, out int written))
        {
            throw new InvalidOperationException("Failed to enumerate PKCS#11 slots for the benchmark module.");
        }

        for (int i = 0; i < written; i++)
        {
            if (module.TryGetTokenInfo(slots[i], out Pkcs11TokenInfo tokenInfo) &&
                string.Equals(tokenInfo.Label.Trim(), tokenLabel, StringComparison.Ordinal))
            {
                return slots[i];
            }
        }

        throw new InvalidOperationException($"Benchmark token '{tokenLabel}' was not found.");
    }

    private static Pkcs11ObjectHandle FindRequiredObjectHandle(Pkcs11Session session, Pkcs11ObjectSearchParameters search)
    {
        if (session.TryFindObject(search, out Pkcs11ObjectHandle handle))
        {
            return handle;
        }

        throw new InvalidOperationException("A required benchmark object was not found in the SoftHSM fixture.");
    }
}
