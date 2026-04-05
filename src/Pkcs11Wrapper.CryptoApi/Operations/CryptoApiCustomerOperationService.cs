using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Observability;
using Pkcs11Wrapper.CryptoApi.Runtime;
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
    CryptoApiPkcs11Runtime pkcs11Runtime,
    CryptoApiRouteDispatchService routeDispatchService,
    TimeProvider timeProvider,
    CryptoApiMetrics? metrics = null) : ICryptoApiCustomerOperationService
{
    private const int MaxPayloadBytes = 1024 * 1024;
    private const int MaxRandomLength = 4096;
    private static readonly nuint CkrObjectHandleInvalid = 0x00000082u;
    private static readonly nuint CkrSessionHandleInvalid = 0x000000B3u;
    private readonly ConditionalWeakTable<Pkcs11Session, SessionKeyHandleCache> _sessionKeyHandleCaches = new();

    public CryptoApiSignOperationResult Sign(CryptoApiAuthorizedKeyOperation authorization, string? algorithm, string? payloadBase64)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        SignatureAlgorithmProfile profile = SignatureAlgorithmProfile.Parse(algorithm);
        byte[] payload = ParseRequiredBase64(payloadBase64, nameof(payloadBase64), MaxPayloadBytes);
        ResolvedKeyLocator locator = ResolveRequiredLocator(authorization.RoutePlan, authorization.AliasName);

        return routeDispatchService.Execute(authorization, route => SignOnRoute(authorization, route, locator, profile, payload));
    }

    public CryptoApiVerifyOperationResult Verify(CryptoApiAuthorizedKeyOperation authorization, string? algorithm, string? payloadBase64, string? signatureBase64)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        SignatureAlgorithmProfile profile = SignatureAlgorithmProfile.Parse(algorithm);
        byte[] payload = ParseRequiredBase64(payloadBase64, nameof(payloadBase64), MaxPayloadBytes);
        byte[] signature = ParseRequiredBase64(signatureBase64, nameof(signatureBase64), MaxPayloadBytes);
        ResolvedKeyLocator locator = ResolveRequiredLocator(authorization.RoutePlan, authorization.AliasName);

        return routeDispatchService.Execute(authorization, route => VerifyOnRoute(authorization, route, locator, profile, payload, signature));
    }

    public CryptoApiRandomOperationResult GenerateRandom(CryptoApiAuthorizedKeyOperation authorization, int length)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(length, MaxRandomLength);

        return routeDispatchService.Execute(authorization, route => GenerateRandomOnRoute(authorization, route, length));
    }

    private CryptoApiSignOperationResult SignOnRoute(
        CryptoApiAuthorizedKeyOperation authorization,
        CryptoApiResolvedKeyRoute route,
        ResolvedKeyLocator locator,
        SignatureAlgorithmProfile profile,
        byte[] payload)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        string backend = route.DeviceRoute ?? "default";
        Pkcs11SlotId slotId = new((nuint)route.SlotId);
        using CryptoApiPkcs11Runtime.CryptoApiPooledSessionLease sessionLease = RentCandidateSession(route, slotId);
        Pkcs11Session session = sessionLease.Session;
        KeyHandleCacheKey cacheKey = CreateCacheKey(locator, profile, forSign: true);

        try
        {
            byte[] signature = ExecuteWithKeyHandleRecovery(
                sessionLease,
                cacheKey,
                () =>
                {
                    Pkcs11ObjectHandle keyHandle = ResolveRequiredKeyHandle(session, authorization.AliasName, locator, profile, forSign: true);
                    Pkcs11Mechanism mechanism = profile.CreateMechanism();
                    return SignWithRetry(session, keyHandle, mechanism, payload);
                });

            metrics?.RecordPkcs11Operation("sign", profile.Name, backend, "success", stopwatch.Elapsed);
            return new CryptoApiSignOperationResult(profile.Name, signature, timeProvider.GetUtcNow());
        }
        catch (Exception ex) when (IsRecoverableCandidateFailure(ex))
        {
            sessionLease.MarkBroken();
            metrics?.RecordPkcs11Operation("sign", profile.Name, backend, "failure", stopwatch.Elapsed);
            throw CreateRouteCandidateUnavailable(route, authorization, ex);
        }
    }

    private CryptoApiVerifyOperationResult VerifyOnRoute(
        CryptoApiAuthorizedKeyOperation authorization,
        CryptoApiResolvedKeyRoute route,
        ResolvedKeyLocator locator,
        SignatureAlgorithmProfile profile,
        byte[] payload,
        byte[] signature)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        string backend = route.DeviceRoute ?? "default";
        Pkcs11SlotId slotId = new((nuint)route.SlotId);
        using CryptoApiPkcs11Runtime.CryptoApiPooledSessionLease sessionLease = RentCandidateSession(route, slotId);
        Pkcs11Session session = sessionLease.Session;
        KeyHandleCacheKey cacheKey = CreateCacheKey(locator, profile, forSign: false);

        try
        {
            bool verified = ExecuteWithKeyHandleRecovery(
                sessionLease,
                cacheKey,
                () =>
                {
                    Pkcs11ObjectHandle keyHandle = ResolveRequiredKeyHandle(session, authorization.AliasName, locator, profile, forSign: false);
                    Pkcs11Mechanism mechanism = profile.CreateMechanism();
                    return session.Verify(keyHandle, mechanism, payload, signature);
                });

            metrics?.RecordPkcs11Operation("verify", profile.Name, backend, verified ? "verified" : "invalid", stopwatch.Elapsed);
            return new CryptoApiVerifyOperationResult(profile.Name, verified, timeProvider.GetUtcNow());
        }
        catch (Exception ex) when (IsRecoverableCandidateFailure(ex))
        {
            sessionLease.MarkBroken();
            metrics?.RecordPkcs11Operation("verify", profile.Name, backend, "failure", stopwatch.Elapsed);
            throw CreateRouteCandidateUnavailable(route, authorization, ex);
        }
    }

    private CryptoApiRandomOperationResult GenerateRandomOnRoute(CryptoApiAuthorizedKeyOperation authorization, CryptoApiResolvedKeyRoute route, int length)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();
        string backend = route.DeviceRoute ?? "default";
        Pkcs11SlotId slotId = new((nuint)route.SlotId);
        using CryptoApiPkcs11Runtime.CryptoApiPooledSessionLease sessionLease = RentCandidateSession(route, slotId);

        try
        {
            byte[] buffer = new byte[length];
            sessionLease.Session.GenerateRandom(buffer);
            metrics?.RecordPkcs11Operation("random", "RANDOM", backend, "success", stopwatch.Elapsed);
            return new CryptoApiRandomOperationResult(buffer, timeProvider.GetUtcNow());
        }
        catch (Exception ex) when (IsRecoverableCandidateFailure(ex))
        {
            sessionLease.MarkBroken();
            metrics?.RecordPkcs11Operation("random", "RANDOM", backend, "failure", stopwatch.Elapsed);
            throw CreateRouteCandidateUnavailable(route, authorization, ex);
        }
    }

    private CryptoApiPkcs11Runtime.CryptoApiPooledSessionLease RentCandidateSession(CryptoApiResolvedKeyRoute route, Pkcs11SlotId slotId)
    {
        try
        {
            return pkcs11Runtime.RentSession(route.DeviceRoute, slotId);
        }
        catch (Exception ex) when (ex is CryptoApiOperationConfigurationException or Pkcs11Exception or InvalidOperationException)
        {
            throw new CryptoApiRouteCandidateUnavailableException(
                $"Backend '{route.DeviceRoute ?? "default"}' slot '{route.SlotId}' could not open a PKCS#11 session.",
                ex);
        }
    }

    private static ResolvedKeyLocator ResolveRequiredLocator(CryptoApiRoutePlan routePlan, string aliasName)
    {
        byte[] objectId = ParseOptionalHex(routePlan.ObjectIdHex);
        byte[] objectLabel = string.IsNullOrWhiteSpace(routePlan.ObjectLabel)
            ? []
            : Encoding.UTF8.GetBytes(routePlan.ObjectLabel.Trim());

        if (objectId.Length == 0 && objectLabel.Length == 0)
        {
            throw new CryptoApiOperationConfigurationException($"Key alias '{aliasName}' does not define a PKCS#11 object locator.");
        }

        return new ResolvedKeyLocator(
            ObjectId: objectId,
            ObjectIdHex: objectId.Length == 0 ? null : Convert.ToHexString(objectId),
            ObjectLabel: objectLabel,
            ObjectLabelText: objectLabel.Length == 0 ? null : routePlan.ObjectLabel?.Trim());
    }

    private T ExecuteWithKeyHandleRecovery<T>(
        CryptoApiPkcs11Runtime.CryptoApiPooledSessionLease sessionLease,
        KeyHandleCacheKey cacheKey,
        Func<T> operation)
    {
        try
        {
            return operation();
        }
        catch (Pkcs11Exception ex) when ((nuint)ex.RawResult == CkrObjectHandleInvalid)
        {
            GetOrCreateSessionKeyHandleCache(sessionLease.Session).Invalidate(cacheKey);
            return operation();
        }
        catch (Pkcs11Exception ex) when ((nuint)ex.RawResult == CkrSessionHandleInvalid)
        {
            sessionLease.MarkBroken();
            throw new CryptoApiRouteCandidateUnavailableException("The PKCS#11 session became invalid during execution.", ex);
        }
    }

    private Pkcs11ObjectHandle ResolveRequiredKeyHandle(
        Pkcs11Session session,
        string aliasName,
        ResolvedKeyLocator locator,
        SignatureAlgorithmProfile profile,
        bool forSign)
    {
        KeyHandleCacheKey cacheKey = CreateCacheKey(locator, profile, forSign);
        SessionKeyHandleCache cache = GetOrCreateSessionKeyHandleCache(session);
        if (cache.TryGetValue(cacheKey, out Pkcs11ObjectHandle cachedHandle))
        {
            return cachedHandle;
        }

        KeyResolutionAttempt result;
        if (locator.ObjectId.Length != 0)
        {
            result = TryResolveKeyHandle(session, locator.ObjectId, label: null, profile, forSign);
            if (result.Handle is not null)
            {
                cache.Set(cacheKey, result.Handle.Value);
                return result.Handle.Value;
            }

            if (result.Ambiguous)
            {
                throw new CryptoApiRouteCandidateUnavailableException(
                    $"Key alias '{aliasName}' resolved to multiple PKCS#11 objects for {(forSign ? "signing" : "verification")}.");
            }
        }

        if (locator.ObjectLabel.Length != 0)
        {
            result = TryResolveKeyHandle(session, id: null, locator.ObjectLabel, profile, forSign);
            if (result.Handle is not null)
            {
                cache.Set(cacheKey, result.Handle.Value);
                return result.Handle.Value;
            }

            if (result.Ambiguous)
            {
                throw new CryptoApiRouteCandidateUnavailableException(
                    $"Key alias '{aliasName}' resolved to multiple PKCS#11 objects for {(forSign ? "signing" : "verification")}.");
            }
        }

        throw new CryptoApiRouteCandidateUnavailableException(
            $"Key alias '{aliasName}' could not be resolved to a PKCS#11 object for {(forSign ? "signing" : "verification")}.");
    }

    private SessionKeyHandleCache GetOrCreateSessionKeyHandleCache(Pkcs11Session session)
        => _sessionKeyHandleCaches.GetValue(session, static _ => new SessionKeyHandleCache());

    private static KeyHandleCacheKey CreateCacheKey(ResolvedKeyLocator locator, SignatureAlgorithmProfile profile, bool forSign)
        => new(
            locator.ObjectIdHex,
            locator.ObjectLabelText,
            profile.KeyType,
            forSign ? profile.SignObjectClass : profile.VerifyObjectClass,
            forSign);

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
            throw new CryptoApiRouteCandidateUnavailableException("The PKCS#11 module did not return a signature output buffer.");
        }

        byte[] retryBuffer = new byte[written];
        if (!session.TrySign(keyHandle, mechanism, payload, retryBuffer, out int retryWritten))
        {
            throw new CryptoApiRouteCandidateUnavailableException("The PKCS#11 module did not return a signature output buffer.");
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

    private static CryptoApiRouteCandidateUnavailableException CreateRouteCandidateUnavailable(
        CryptoApiResolvedKeyRoute route,
        CryptoApiAuthorizedKeyOperation authorization,
        Exception ex)
        => ex as CryptoApiRouteCandidateUnavailableException
            ?? new CryptoApiRouteCandidateUnavailableException(
                $"Backend '{route.DeviceRoute ?? "default"}' slot '{route.SlotId}' failed while executing '{authorization.Operation}' for alias '{authorization.AliasName}'.",
                ex);

    private static bool IsRecoverableCandidateFailure(Exception ex)
        => ex is CryptoApiRouteCandidateUnavailableException
            or CryptoApiOperationExecutionException
            or CryptoApiOperationConfigurationException
            or InvalidOperationException
            or Pkcs11Exception;

    private readonly record struct ResolvedKeyLocator(
        byte[] ObjectId,
        string? ObjectIdHex,
        byte[] ObjectLabel,
        string? ObjectLabelText);

    private readonly record struct KeyHandleCacheKey(
        string? ObjectIdHex,
        string? ObjectLabel,
        Pkcs11KeyType KeyType,
        Pkcs11ObjectClass ObjectClass,
        bool ForSign);

    private sealed class SessionKeyHandleCache
    {
        private readonly Dictionary<KeyHandleCacheKey, Pkcs11ObjectHandle> _handles = new();

        public bool TryGetValue(KeyHandleCacheKey key, out Pkcs11ObjectHandle handle)
            => _handles.TryGetValue(key, out handle);

        public void Set(KeyHandleCacheKey key, Pkcs11ObjectHandle handle)
            => _handles[key] = handle;

        public void Invalidate(KeyHandleCacheKey key)
            => _handles.Remove(key);
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
