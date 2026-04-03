using System.Text;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.Native;

namespace Pkcs11Wrapper.CryptoApi.Operations;

public interface ICryptoApiCustomerOperationService
{
    CryptoApiSignOperationResult Sign(CryptoApiAuthorizedKeyOperation authorization, string? algorithm, string? payloadBase64);

    CryptoApiVerifyOperationResult Verify(CryptoApiAuthorizedKeyOperation authorization, string? algorithm, string? payloadBase64, string? signatureBase64);

    CryptoApiRandomOperationResult GenerateRandom(CryptoApiAuthorizedKeyOperation authorization, int length);
}

public sealed record CryptoApiSignOperationResult(
    string Algorithm,
    byte[] Signature,
    DateTimeOffset CompletedAtUtc);

public sealed record CryptoApiVerifyOperationResult(
    string Algorithm,
    bool Verified,
    DateTimeOffset CompletedAtUtc);

public sealed record CryptoApiRandomOperationResult(
    byte[] RandomBytes,
    DateTimeOffset CompletedAtUtc);

public sealed class CryptoApiPkcs11CustomerOperationService(
    IOptions<CryptoApiRuntimeOptions> runtimeOptions,
    TimeProvider timeProvider) : ICryptoApiCustomerOperationService
{
    private const int MaxPayloadBytes = 1024 * 1024;
    private const int MaxRandomLength = 4096;
    private const nuint CkrFunctionFailed = 0x00000006u;
    private const nuint CkrUserAlreadyLoggedIn = 0x00000100u;

    public CryptoApiSignOperationResult Sign(CryptoApiAuthorizedKeyOperation authorization, string? algorithm, string? payloadBase64)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        SignatureAlgorithmProfile profile = SignatureAlgorithmProfile.Parse(algorithm);
        byte[] payload = ParseRequiredBase64(payloadBase64, nameof(payloadBase64), MaxPayloadBytes);

        using Pkcs11Module module = CreateInitializedModule();
        using Pkcs11Session session = OpenCompatibleSession(module, ResolveRequiredSlotId(authorization));
        LoginIfConfigured(session);

        Pkcs11ObjectHandle keyHandle = ResolveRequiredKeyHandle(session, authorization, profile, forSign: true);
        Pkcs11Mechanism mechanism = profile.CreateMechanism();
        byte[] signature = SignWithRetry(session, keyHandle, mechanism, payload);

        return new CryptoApiSignOperationResult(profile.Name, signature, timeProvider.GetUtcNow());
    }

    public CryptoApiVerifyOperationResult Verify(CryptoApiAuthorizedKeyOperation authorization, string? algorithm, string? payloadBase64, string? signatureBase64)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        SignatureAlgorithmProfile profile = SignatureAlgorithmProfile.Parse(algorithm);
        byte[] payload = ParseRequiredBase64(payloadBase64, nameof(payloadBase64), MaxPayloadBytes);
        byte[] signature = ParseRequiredBase64(signatureBase64, nameof(signatureBase64), MaxPayloadBytes);

        using Pkcs11Module module = CreateInitializedModule();
        using Pkcs11Session session = OpenCompatibleSession(module, ResolveRequiredSlotId(authorization));
        LoginIfConfigured(session);

        Pkcs11ObjectHandle keyHandle = ResolveRequiredKeyHandle(session, authorization, profile, forSign: false);
        Pkcs11Mechanism mechanism = profile.CreateMechanism();
        bool verified = session.Verify(keyHandle, mechanism, payload, signature);

        return new CryptoApiVerifyOperationResult(profile.Name, verified, timeProvider.GetUtcNow());
    }

    public CryptoApiRandomOperationResult GenerateRandom(CryptoApiAuthorizedKeyOperation authorization, int length)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(length, MaxRandomLength);

        using Pkcs11Module module = CreateInitializedModule();
        using Pkcs11Session session = OpenCompatibleSession(module, ResolveRequiredSlotId(authorization));
        LoginIfConfigured(session);

        byte[] buffer = new byte[length];
        session.GenerateRandom(buffer);
        return new CryptoApiRandomOperationResult(buffer, timeProvider.GetUtcNow());
    }

    private Pkcs11Module CreateInitializedModule()
    {
        string modulePath = runtimeOptions.Value.ModulePath?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(modulePath))
        {
            throw new CryptoApiOperationConfigurationException("Crypto API PKCS#11 module path is not configured.");
        }

        Pkcs11Module module = Pkcs11Module.Load(modulePath);
        try
        {
            module.Initialize();
            return module;
        }
        catch
        {
            module.Dispose();
            throw;
        }
    }

    private static Pkcs11SlotId ResolveRequiredSlotId(CryptoApiAuthorizedKeyOperation authorization)
    {
        ulong? slotId = authorization.ResolvedRoute.SlotId;
        if (!slotId.HasValue)
        {
            throw new CryptoApiOperationConfigurationException($"Key alias '{authorization.AliasName}' does not define a PKCS#11 slot route.");
        }

        return new Pkcs11SlotId((nuint)slotId.Value);
    }

    private void LoginIfConfigured(Pkcs11Session session)
    {
        string userPin = runtimeOptions.Value.UserPin?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(userPin))
        {
            return;
        }

        byte[] pinUtf8 = Encoding.UTF8.GetBytes(userPin);
        try
        {
            session.Login(Pkcs11UserType.User, pinUtf8);
        }
        catch (Pkcs11Exception ex) when ((nuint)ex.RawResult == CkrUserAlreadyLoggedIn)
        {
        }
    }

    private static Pkcs11Session OpenCompatibleSession(Pkcs11Module module, Pkcs11SlotId slotId)
    {
        try
        {
            return module.OpenSession(slotId, readWrite: false);
        }
        catch (Pkcs11Exception ex) when ((nuint)ex.RawResult == CkrFunctionFailed)
        {
            return module.OpenSession(slotId, readWrite: true);
        }
    }

    private static Pkcs11ObjectHandle ResolveRequiredKeyHandle(
        Pkcs11Session session,
        CryptoApiAuthorizedKeyOperation authorization,
        SignatureAlgorithmProfile profile,
        bool forSign)
    {
        byte[] objectId = ParseOptionalHex(authorization.ResolvedRoute.ObjectIdHex);
        byte[] objectLabel = string.IsNullOrWhiteSpace(authorization.ResolvedRoute.ObjectLabel)
            ? []
            : Encoding.UTF8.GetBytes(authorization.ResolvedRoute.ObjectLabel.Trim());

        if (objectId.Length == 0 && objectLabel.Length == 0)
        {
            throw new CryptoApiOperationConfigurationException($"Key alias '{authorization.AliasName}' does not define a PKCS#11 object locator.");
        }

        KeyResolutionAttempt result;
        if (objectId.Length != 0)
        {
            result = TryResolveKeyHandle(session, objectId, label: null, profile, forSign);
            if (result.Handle is not null)
            {
                return result.Handle.Value;
            }

            if (result.Ambiguous)
            {
                throw new CryptoApiOperationExecutionException($"Key alias '{authorization.AliasName}' resolved to multiple PKCS#11 objects for {(forSign ? "signing" : "verification")}.");
            }
        }

        if (objectLabel.Length != 0)
        {
            result = TryResolveKeyHandle(session, id: null, objectLabel, profile, forSign);
            if (result.Handle is not null)
            {
                return result.Handle.Value;
            }

            if (result.Ambiguous)
            {
                throw new CryptoApiOperationExecutionException($"Key alias '{authorization.AliasName}' resolved to multiple PKCS#11 objects for {(forSign ? "signing" : "verification")}.");
            }
        }

        throw new CryptoApiOperationExecutionException($"Key alias '{authorization.AliasName}' could not be resolved to a PKCS#11 object for {(forSign ? "signing" : "verification")}.");
    }

    private static KeyResolutionAttempt TryResolveKeyHandle(
        Pkcs11Session session,
        byte[]? id,
        byte[]? label,
        SignatureAlgorithmProfile profile,
        bool forSign)
    {
        Pkcs11ObjectSearchParametersBuilder builder = Pkcs11ObjectSearchParameters.CreateBuilder()
            .WithObjectClass(forSign ? profile.SignObjectClass : profile.VerifyObjectClass)
            .WithKeyType(profile.KeyType);

        builder = forSign ? builder.RequireSign() : builder.RequireVerify();

        if (id is { Length: > 0 })
        {
            builder = builder.WithId(id);
        }

        if (label is { Length: > 0 })
        {
            builder = builder.WithLabel(label);
        }

        Pkcs11ObjectSearchParameters search = builder.Build();
        Span<Pkcs11ObjectHandle> buffer = stackalloc Pkcs11ObjectHandle[2];
        _ = session.TryFindObjects(search, buffer, out int written, out bool hasMore);

        return written switch
        {
            0 => new KeyResolutionAttempt(null, false),
            1 when !hasMore => new KeyResolutionAttempt(buffer[0], false),
            _ => new KeyResolutionAttempt(null, true)
        };
    }

    private static byte[] SignWithRetry(Pkcs11Session session, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, byte[] payload)
    {
        int declaredLength = Math.Max(session.GetSignOutputLength(keyHandle, mechanism, payload), 1);
        byte[] buffer = new byte[declaredLength];
        if (session.TrySign(keyHandle, mechanism, payload, buffer, out int written))
        {
            return buffer.AsSpan(0, written).ToArray();
        }

        if (written <= 0)
        {
            throw new CryptoApiOperationExecutionException("The PKCS#11 module did not return a signature output buffer.");
        }

        byte[] retryBuffer = new byte[written];
        if (!session.TrySign(keyHandle, mechanism, payload, retryBuffer, out int retryWritten))
        {
            throw new CryptoApiOperationExecutionException("The PKCS#11 module did not return a signature output buffer.");
        }

        return retryBuffer.AsSpan(0, retryWritten).ToArray();
    }

    private static byte[] ParseRequiredBase64(string? value, string parameterName, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Value is required.", parameterName);
        }

        try
        {
            byte[] decoded = Convert.FromBase64String(value.Trim());
            if (decoded.Length > maxLength)
            {
                throw new ArgumentException($"Decoded payload must be {maxLength} bytes or fewer.", parameterName);
            }

            return decoded;
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("Value must be valid base64.", parameterName, ex);
        }
    }

    private static byte[] ParseOptionalHex(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        try
        {
            return Convert.FromHexString(value.Trim());
        }
        catch (FormatException ex)
        {
            throw new CryptoApiOperationConfigurationException($"Configured object ID hex '{value}' is not valid.", ex);
        }
    }

    private readonly record struct KeyResolutionAttempt(Pkcs11ObjectHandle? Handle, bool Ambiguous);

    private readonly record struct SignatureAlgorithmProfile(
        string Name,
        Pkcs11KeyType KeyType,
        Pkcs11ObjectClass SignObjectClass,
        Pkcs11ObjectClass VerifyObjectClass,
        Pkcs11MechanismType MechanismType,
        byte[] MechanismParameter)
    {
        public Pkcs11Mechanism CreateMechanism()
            => MechanismParameter.Length == 0
                ? new Pkcs11Mechanism(MechanismType)
                : new Pkcs11Mechanism(MechanismType, MechanismParameter);

        public static SignatureAlgorithmProfile Parse(string? value)
        {
            string normalized = string.IsNullOrWhiteSpace(value)
                ? throw new ArgumentException("Value is required.", nameof(value))
                : value.Trim().ToUpperInvariant();

            return normalized switch
            {
                "RS256" => new SignatureAlgorithmProfile(
                    Name: "RS256",
                    KeyType: Pkcs11KeyTypes.Rsa,
                    SignObjectClass: Pkcs11ObjectClasses.PrivateKey,
                    VerifyObjectClass: Pkcs11ObjectClasses.PublicKey,
                    MechanismType: Pkcs11MechanismTypes.Sha256RsaPkcs,
                    MechanismParameter: []),
                "PS256" => new SignatureAlgorithmProfile(
                    Name: "PS256",
                    KeyType: Pkcs11KeyTypes.Rsa,
                    SignObjectClass: Pkcs11ObjectClasses.PrivateKey,
                    VerifyObjectClass: Pkcs11ObjectClasses.PublicKey,
                    MechanismType: Pkcs11MechanismTypes.Sha256RsaPkcsPss,
                    MechanismParameter: Pkcs11MechanismParameters.RsaPss(Pkcs11MechanismTypes.Sha256, Pkcs11RsaMgfTypes.Mgf1Sha256, 32)),
                "ES256" => new SignatureAlgorithmProfile(
                    Name: "ES256",
                    KeyType: Pkcs11KeyTypes.Ec,
                    SignObjectClass: Pkcs11ObjectClasses.PrivateKey,
                    VerifyObjectClass: Pkcs11ObjectClasses.PublicKey,
                    MechanismType: Pkcs11MechanismTypes.EcdsaSha256,
                    MechanismParameter: []),
                "HS256" => new SignatureAlgorithmProfile(
                    Name: "HS256",
                    KeyType: Pkcs11KeyTypes.GenericSecret,
                    SignObjectClass: Pkcs11ObjectClasses.SecretKey,
                    VerifyObjectClass: Pkcs11ObjectClasses.SecretKey,
                    MechanismType: Pkcs11MechanismTypes.Sha256Hmac,
                    MechanismParameter: []),
                _ => throw new ArgumentException("Unsupported algorithm. Supported values: RS256, PS256, ES256, HS256.", nameof(value))
            };
        }
    }
}

public sealed class CryptoApiOperationConfigurationException : InvalidOperationException
{
    public CryptoApiOperationConfigurationException(string message)
        : base(message)
    {
    }

    public CryptoApiOperationConfigurationException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

public sealed class CryptoApiOperationExecutionException : InvalidOperationException
{
    public CryptoApiOperationExecutionException(string message)
        : base(message)
    {
    }

    public CryptoApiOperationExecutionException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
