using System.Text.Json;
using Pkcs11Wrapper.CryptoApi.Caching;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Access;

public sealed class CryptoApiKeyOperationAuthorizationService
{
    private readonly ICryptoApiSharedStateStore _sharedStateStore;
    private readonly TimeProvider _timeProvider;
    private readonly CryptoApiClientSecretHasher _secretHasher;
    private readonly CryptoApiRequestPathCache _requestPathCache;

    public CryptoApiKeyOperationAuthorizationService(
        ICryptoApiSharedStateStore sharedStateStore,
        TimeProvider timeProvider,
        CryptoApiClientSecretHasher? secretHasher = null,
        CryptoApiRequestPathCache? requestPathCache = null)
    {
        _sharedStateStore = sharedStateStore;
        _timeProvider = timeProvider;
        _secretHasher = secretHasher ?? new CryptoApiClientSecretHasher();
        _requestPathCache = requestPathCache ?? new CryptoApiRequestPathCache(timeProvider);
    }

    public async Task<CryptoApiRequestAuthorizationResult> AuthorizeRequestAsync(
        string? keyIdentifier,
        string? secret,
        string? aliasName,
        string? operation,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(keyIdentifier) || string.IsNullOrWhiteSpace(secret))
        {
            return AuthenticationFailed("API key id and secret are required.");
        }

        string normalizedKeyIdentifier = keyIdentifier.Trim();
        string normalizedSecret = secret.Trim();
        string normalizedAliasName = NormalizeAliasName(aliasName, nameof(aliasName));
        string normalizedOperation = CryptoApiOperationPolicyDocumentCodec.NormalizeOperation(operation, nameof(operation));

        long authStateRevision = await _sharedStateStore.GetAuthStateRevisionAsync(cancellationToken);
        if (authStateRevision <= 0)
        {
            return AuthenticationFailed("Shared persistence is not configured.");
        }

        DateTimeOffset now = _timeProvider.GetUtcNow();
        string secretFingerprint = _requestPathCache.CreateSecretFingerprint(normalizedSecret);
        CryptoApiSharedStateSnapshot? snapshot = null;
        CryptoApiAuthenticatedClient authenticatedClient;

        if (_requestPathCache.TryGetAuthenticatedClient(authStateRevision, normalizedKeyIdentifier, secretFingerprint, now, out CryptoApiAuthenticatedClient cachedClient))
        {
            authenticatedClient = cachedClient;
        }
        else
        {
            snapshot = await _sharedStateStore.GetSnapshotAsync(cancellationToken);
            AuthenticatedClientAuthenticationResult authentication = AuthenticateClientFromSnapshot(snapshot, normalizedKeyIdentifier, normalizedSecret, now);
            if (!authentication.Succeeded || authentication.Template is null)
            {
                return AuthenticationFailed(authentication.FailureReason ?? "The provided API credentials were rejected.");
            }

            authenticatedClient = authentication.Template.Client;
            await RefreshLastUsedIfNeededAsync(authStateRevision, authentication.Template.Key, normalizedKeyIdentifier, secretFingerprint, now, cancellationToken);
            _requestPathCache.SetAuthenticatedClient(authStateRevision, normalizedKeyIdentifier, secretFingerprint, authenticatedClient, now);
        }

        await RefreshLastUsedIfNeededAsync(authStateRevision, authenticatedClient.ClientKeyId, normalizedKeyIdentifier, secretFingerprint, now, cancellationToken);

        if (_requestPathCache.TryGetAuthorizedOperation(authStateRevision, authenticatedClient.ClientId, normalizedAliasName, normalizedOperation, authenticatedClient, now, out CryptoApiAuthorizedKeyOperation cachedAuthorization))
        {
            return new CryptoApiRequestAuthorizationResult(
                Succeeded: true,
                FailureStatusCode: null,
                FailureReason: null,
                Authorization: cachedAuthorization);
        }

        snapshot ??= await _sharedStateStore.GetSnapshotAsync(cancellationToken);
        CryptoApiKeyOperationAuthorizationResult authorization = AuthorizeFromSnapshot(snapshot, authenticatedClient, normalizedAliasName, normalizedOperation);
        if (!authorization.Succeeded || authorization.Authorization is null)
        {
            return AuthorizationFailed(authorization.FailureReason ?? "The caller is not allowed to use the requested key alias or operation.");
        }

        _requestPathCache.SetAuthorizedOperation(authStateRevision, authenticatedClient.ClientId, authorization.Authorization);
        return new CryptoApiRequestAuthorizationResult(
            Succeeded: true,
            FailureStatusCode: null,
            FailureReason: null,
            Authorization: authorization.Authorization);
    }

    public async Task<CryptoApiKeyOperationAuthorizationResult> AuthorizeAsync(
        CryptoApiAuthenticatedClient authenticatedClient,
        string? aliasName,
        string? operation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authenticatedClient);

        string normalizedAliasName = NormalizeAliasName(aliasName, nameof(aliasName));
        string normalizedOperation = CryptoApiOperationPolicyDocumentCodec.NormalizeOperation(operation, nameof(operation));

        long authStateRevision = await _sharedStateStore.GetAuthStateRevisionAsync(cancellationToken);
        if (authStateRevision <= 0)
        {
            return Failed("Shared persistence is not configured.");
        }

        DateTimeOffset now = _timeProvider.GetUtcNow();
        if (_requestPathCache.TryGetAuthorizedOperation(authStateRevision, authenticatedClient.ClientId, normalizedAliasName, normalizedOperation, authenticatedClient, now, out CryptoApiAuthorizedKeyOperation cachedAuthorization))
        {
            return new CryptoApiKeyOperationAuthorizationResult(
                Succeeded: true,
                FailureReason: null,
                Authorization: cachedAuthorization);
        }

        CryptoApiSharedStateSnapshot snapshot = await _sharedStateStore.GetSnapshotAsync(cancellationToken);
        CryptoApiKeyOperationAuthorizationResult authorization = AuthorizeFromSnapshot(snapshot, authenticatedClient, normalizedAliasName, normalizedOperation);
        if (authorization.Succeeded && authorization.Authorization is not null)
        {
            _requestPathCache.SetAuthorizedOperation(authStateRevision, authenticatedClient.ClientId, authorization.Authorization);
        }

        return authorization;
    }
    private AuthenticatedClientAuthenticationResult AuthenticateClientFromSnapshot(
        CryptoApiSharedStateSnapshot snapshot,
        string normalizedKeyIdentifier,
        string normalizedSecret,
        DateTimeOffset now)
    {
        CryptoApiClientKeyRecord? key = snapshot.ClientKeys.FirstOrDefault(candidate => string.Equals(candidate.KeyIdentifier, normalizedKeyIdentifier, StringComparison.Ordinal));
        if (key is null)
        {
            return new AuthenticatedClientAuthenticationResult(false, "API key was not found.", null);
        }

        CryptoApiClientRecord? client = snapshot.Clients.FirstOrDefault(candidate => candidate.ClientId == key.ClientId);
        if (client is null)
        {
            return new AuthenticatedClientAuthenticationResult(false, "Owning API client was not found.", null);
        }

        if (!client.IsEnabled)
        {
            return new AuthenticatedClientAuthenticationResult(false, "API client is disabled.", null);
        }

        if (key.RevokedAtUtc is not null)
        {
            return new AuthenticatedClientAuthenticationResult(false, "API key has been revoked.", null);
        }

        if (!key.IsEnabled)
        {
            return new AuthenticatedClientAuthenticationResult(false, "API key is disabled.", null);
        }

        if (key.ExpiresAtUtc is DateTimeOffset expiresAtUtc && expiresAtUtc <= now)
        {
            return new AuthenticatedClientAuthenticationResult(false, "API key has expired.", null);
        }

        if (!_secretHasher.VerifySecret(normalizedSecret, key.SecretHash))
        {
            return new AuthenticatedClientAuthenticationResult(false, "API key secret is invalid.", null);
        }

        Guid[] boundPolicyIds = snapshot.ClientPolicyBindings
            .Where(binding => binding.ClientId == client.ClientId)
            .Select(binding => binding.PolicyId)
            .Distinct()
            .OrderBy(id => id)
            .ToArray();

        return new AuthenticatedClientAuthenticationResult(
            true,
            null,
            new AuthenticatedClientTemplate(
                new CryptoApiAuthenticatedClient(
                ClientId: client.ClientId,
                ClientName: client.ClientName,
                DisplayName: client.DisplayName,
                ApplicationType: client.ApplicationType,
                AuthenticationMode: client.AuthenticationMode,
                ClientKeyId: key.ClientKeyId,
                KeyIdentifier: key.KeyIdentifier,
                CredentialType: key.CredentialType,
                AuthenticatedAtUtc: now,
                ExpiresAtUtc: key.ExpiresAtUtc,
                BoundPolicyIds: boundPolicyIds),
                key));
    }

    private async Task RefreshLastUsedIfNeededAsync(
        long authStateRevision,
        CryptoApiClientKeyRecord key,
        string normalizedKeyIdentifier,
        string secretFingerprint,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (key.LastUsedAtUtc is DateTimeOffset lastUsedAtUtc && now - lastUsedAtUtc < _requestPathCache.LastUsedWriteInterval)
        {
            return;
        }

        await RefreshLastUsedIfNeededAsync(authStateRevision, key.ClientKeyId, normalizedKeyIdentifier, secretFingerprint, now, cancellationToken);
    }

    private async Task RefreshLastUsedIfNeededAsync(
        long authStateRevision,
        Guid clientKeyId,
        string normalizedKeyIdentifier,
        string secretFingerprint,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        if (!_requestPathCache.ShouldRefreshLastUsed(authStateRevision, normalizedKeyIdentifier, secretFingerprint, now))
        {
            return;
        }

        _ = await _sharedStateStore.TryTouchClientKeyLastUsedAsync(clientKeyId, now, _requestPathCache.LastUsedWriteInterval, cancellationToken);
        _requestPathCache.RecordLastUsedRefresh(authStateRevision, normalizedKeyIdentifier, secretFingerprint, now);
    }

    private CryptoApiKeyOperationAuthorizationResult AuthorizeFromSnapshot(
        CryptoApiSharedStateSnapshot snapshot,
        CryptoApiAuthenticatedClient authenticatedClient,
        string normalizedAliasName,
        string normalizedOperation)
    {
        CryptoApiClientRecord? client = snapshot.Clients.FirstOrDefault(candidate => candidate.ClientId == authenticatedClient.ClientId);
        if (client is null || !client.IsEnabled)
        {
            return Failed("Authenticated Crypto API client is no longer enabled.");
        }

        CryptoApiKeyAliasRecord? alias = snapshot.KeyAliases.FirstOrDefault(candidate => string.Equals(candidate.AliasName, normalizedAliasName, StringComparison.OrdinalIgnoreCase));
        if (alias is null)
        {
            return Failed("Requested key alias was not found.");
        }

        if (!alias.IsEnabled)
        {
            return Failed("Requested key alias is disabled.");
        }

        HashSet<Guid> clientPolicyIds = snapshot.ClientPolicyBindings
            .Where(binding => binding.ClientId == authenticatedClient.ClientId)
            .Select(binding => binding.PolicyId)
            .ToHashSet();

        HashSet<Guid> aliasPolicyIds = snapshot.KeyAliasPolicyBindings
            .Where(binding => binding.AliasId == alias.AliasId)
            .Select(binding => binding.PolicyId)
            .ToHashSet();

        Guid[] sharedPolicyIds = clientPolicyIds.Intersect(aliasPolicyIds).ToArray();
        if (sharedPolicyIds.Length == 0)
        {
            return Failed("No shared policy grants this client access to the requested key alias.");
        }

        List<CryptoApiMatchedPolicy> matchedPolicies = [];
        foreach (CryptoApiPolicyRecord policy in snapshot.Policies.Where(candidate => sharedPolicyIds.Contains(candidate.PolicyId) && candidate.IsEnabled))
        {
            CryptoApiOperationPolicyDocument document;
            try
            {
                document = CryptoApiOperationPolicyDocumentCodec.Deserialize(policy.DocumentJson);
            }
            catch (Exception ex) when (ex is InvalidOperationException or ArgumentException or JsonException)
            {
                return Failed($"Policy '{policy.PolicyName}' has an invalid document: {ex.Message}");
            }

            if (!CryptoApiOperationPolicyDocumentCodec.AllowsOperation(document, normalizedOperation))
            {
                continue;
            }

            matchedPolicies.Add(new CryptoApiMatchedPolicy(
                PolicyId: policy.PolicyId,
                PolicyName: policy.PolicyName,
                Revision: policy.Revision));
        }

        if (matchedPolicies.Count == 0)
        {
            return Failed("Requested operation is not allowed for this key alias.");
        }

        return new CryptoApiKeyOperationAuthorizationResult(
            Succeeded: true,
            FailureReason: null,
            Authorization: new CryptoApiAuthorizedKeyOperation(
                Client: authenticatedClient,
                Operation: normalizedOperation,
                AliasId: alias.AliasId,
                AliasName: alias.AliasName,
                ResolvedRoute: new CryptoApiResolvedKeyRoute(
                    DeviceRoute: alias.DeviceRoute,
                    SlotId: alias.SlotId,
                    ObjectLabel: alias.ObjectLabel,
                    ObjectIdHex: alias.ObjectIdHex),
                MatchedPolicies: matchedPolicies.OrderBy(policy => policy.PolicyName, StringComparer.OrdinalIgnoreCase).ToArray(),
                AuthorizedAtUtc: _timeProvider.GetUtcNow()));
    }

    private static CryptoApiRequestAuthorizationResult AuthenticationFailed(string reason)
        => new(
            Succeeded: false,
            FailureStatusCode: 401,
            FailureReason: reason,
            Authorization: null);

    private static CryptoApiRequestAuthorizationResult AuthorizationFailed(string reason)
        => new(
            Succeeded: false,
            FailureStatusCode: 403,
            FailureReason: reason,
            Authorization: null);

    private static CryptoApiKeyOperationAuthorizationResult Failed(string reason)
        => new(
            Succeeded: false,
            FailureReason: reason,
            Authorization: null);

    private static string NormalizeAliasName(string? value, string parameterName)
    {
        string normalized = string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException("Value is required.", parameterName)
            : value.Trim();

        foreach (char c in normalized)
        {
            if (!(char.IsLetterOrDigit(c) || c is '-' or '_' or '.'))
            {
                throw new ArgumentException("Only letters, digits, dash, underscore, and dot are allowed.", parameterName);
            }
        }

        return normalized;
    }

    private sealed record AuthenticatedClientTemplate(
        CryptoApiAuthenticatedClient Client,
        CryptoApiClientKeyRecord Key);

    private sealed record AuthenticatedClientAuthenticationResult(
        bool Succeeded,
        string? FailureReason,
        AuthenticatedClientTemplate? Template);
}
