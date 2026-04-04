using System.Text.Json;
using Pkcs11Wrapper.CryptoApi.Caching;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Access;

public sealed class CryptoApiKeyOperationAuthorizationService
{
    private readonly ICryptoApiSharedStateStore _sharedStateStore;
    private readonly ICryptoApiDistributedHotPathCache _distributedHotPathCache;
    private readonly TimeProvider _timeProvider;
    private readonly CryptoApiClientSecretHasher _secretHasher;
    private readonly CryptoApiRequestPathCache _requestPathCache;

    public CryptoApiKeyOperationAuthorizationService(
        ICryptoApiSharedStateStore sharedStateStore,
        ICryptoApiDistributedHotPathCache distributedHotPathCache,
        TimeProvider timeProvider,
        CryptoApiClientSecretHasher? secretHasher = null,
        CryptoApiRequestPathCache? requestPathCache = null)
    {
        _sharedStateStore = sharedStateStore;
        _distributedHotPathCache = distributedHotPathCache;
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
        CryptoApiAuthenticatedClient authenticatedClient;

        if (_requestPathCache.TryGetAuthenticatedClient(authStateRevision, normalizedKeyIdentifier, secretFingerprint, now, out CryptoApiAuthenticatedClient cachedClient))
        {
            authenticatedClient = cachedClient;
        }
        else
        {
            CryptoApiAuthenticatedClient? distributedClient = await _distributedHotPathCache.GetAuthenticatedClientAsync(
                authStateRevision,
                normalizedKeyIdentifier,
                secretFingerprint,
                now,
                cancellationToken);
            if (distributedClient is not null)
            {
                authenticatedClient = distributedClient;
                _requestPathCache.SetAuthenticatedClient(authStateRevision, normalizedKeyIdentifier, secretFingerprint, authenticatedClient, now);
            }
            else
            {
                CryptoApiClientAuthenticationState? authenticationState = await _sharedStateStore.GetClientAuthenticationStateAsync(normalizedKeyIdentifier, cancellationToken);
                AuthenticatedClientAuthenticationResult authentication = AuthenticateClient(authenticationState, normalizedSecret, now);
                if (!authentication.Succeeded || authentication.Template is null)
                {
                    return AuthenticationFailed(authentication.FailureReason ?? "The provided API credentials were rejected.");
                }

                authenticatedClient = authentication.Template.Client;
                await RefreshLastUsedIfNeededAsync(authStateRevision, authentication.Template.Key, normalizedKeyIdentifier, secretFingerprint, now, cancellationToken);
                _requestPathCache.SetAuthenticatedClient(authStateRevision, normalizedKeyIdentifier, secretFingerprint, authenticatedClient, now);
                await _distributedHotPathCache.SetAuthenticatedClientAsync(authStateRevision, normalizedKeyIdentifier, secretFingerprint, authenticatedClient, cancellationToken);
            }
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

        CryptoApiAuthorizedKeyOperation? distributedAuthorization = await _distributedHotPathCache.GetAuthorizedOperationAsync(
            authStateRevision,
            authenticatedClient.ClientId,
            normalizedAliasName,
            normalizedOperation,
            authenticatedClient,
            now,
            cancellationToken);
        if (distributedAuthorization is not null)
        {
            _requestPathCache.SetAuthorizedOperation(authStateRevision, authenticatedClient.ClientId, distributedAuthorization);
            return new CryptoApiRequestAuthorizationResult(
                Succeeded: true,
                FailureStatusCode: null,
                FailureReason: null,
                Authorization: distributedAuthorization);
        }

        CryptoApiKeyAuthorizationState authorizationState = await _sharedStateStore.GetKeyAuthorizationStateAsync(authenticatedClient.ClientId, normalizedAliasName, cancellationToken);
        CryptoApiKeyOperationAuthorizationResult authorization = Authorize(authorizationState, authenticatedClient, normalizedOperation);
        if (!authorization.Succeeded || authorization.Authorization is null)
        {
            return AuthorizationFailed(authorization.FailureReason ?? "The caller is not allowed to use the requested key alias or operation.");
        }

        _requestPathCache.SetAuthorizedOperation(authStateRevision, authenticatedClient.ClientId, authorization.Authorization);
        await _distributedHotPathCache.SetAuthorizedOperationAsync(authStateRevision, authenticatedClient.ClientId, authorization.Authorization, cancellationToken);
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

        CryptoApiAuthorizedKeyOperation? distributedAuthorization = await _distributedHotPathCache.GetAuthorizedOperationAsync(
            authStateRevision,
            authenticatedClient.ClientId,
            normalizedAliasName,
            normalizedOperation,
            authenticatedClient,
            now,
            cancellationToken);
        if (distributedAuthorization is not null)
        {
            _requestPathCache.SetAuthorizedOperation(authStateRevision, authenticatedClient.ClientId, distributedAuthorization);
            return new CryptoApiKeyOperationAuthorizationResult(
                Succeeded: true,
                FailureReason: null,
                Authorization: distributedAuthorization);
        }

        CryptoApiKeyAuthorizationState authorizationState = await _sharedStateStore.GetKeyAuthorizationStateAsync(authenticatedClient.ClientId, normalizedAliasName, cancellationToken);
        CryptoApiKeyOperationAuthorizationResult authorization = Authorize(authorizationState, authenticatedClient, normalizedOperation);
        if (authorization.Succeeded && authorization.Authorization is not null)
        {
            _requestPathCache.SetAuthorizedOperation(authStateRevision, authenticatedClient.ClientId, authorization.Authorization);
            await _distributedHotPathCache.SetAuthorizedOperationAsync(authStateRevision, authenticatedClient.ClientId, authorization.Authorization, cancellationToken);
        }

        return authorization;
    }

    private AuthenticatedClientAuthenticationResult AuthenticateClient(
        CryptoApiClientAuthenticationState? authenticationState,
        string normalizedSecret,
        DateTimeOffset now)
    {
        if (authenticationState is null)
        {
            return new AuthenticatedClientAuthenticationResult(false, "API key was not found.", null);
        }

        CryptoApiClientRecord client = authenticationState.Client;
        CryptoApiClientKeyRecord key = authenticationState.Key;

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
                BoundPolicyIds: authenticationState.BoundPolicyIds),
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

        if (_distributedHotPathCache.Enabled)
        {
            bool? leaseAcquired = await _distributedHotPathCache.TryAcquireLastUsedRefreshLeaseAsync(clientKeyId, now, _requestPathCache.LastUsedWriteInterval, cancellationToken);
            if (leaseAcquired is false)
            {
                _requestPathCache.RecordLastUsedRefresh(authStateRevision, normalizedKeyIdentifier, secretFingerprint, now);
                return;
            }
        }

        _ = await _sharedStateStore.TryTouchClientKeyLastUsedAsync(clientKeyId, now, _requestPathCache.LastUsedWriteInterval, cancellationToken);
        _requestPathCache.RecordLastUsedRefresh(authStateRevision, normalizedKeyIdentifier, secretFingerprint, now);
    }

    private CryptoApiKeyOperationAuthorizationResult Authorize(
        CryptoApiKeyAuthorizationState authorizationState,
        CryptoApiAuthenticatedClient authenticatedClient,
        string normalizedOperation)
    {
        CryptoApiClientRecord? client = authorizationState.Client;
        if (client is null || !client.IsEnabled)
        {
            return Failed("Authenticated Crypto API client is no longer enabled.");
        }

        CryptoApiKeyAliasRecord? alias = authorizationState.Alias;
        if (alias is null)
        {
            return Failed("Requested key alias was not found.");
        }

        if (!alias.IsEnabled)
        {
            return Failed("Requested key alias is disabled.");
        }

        if (authorizationState.SharedPolicies.Count == 0)
        {
            return Failed("No shared policy grants this client access to the requested key alias.");
        }

        List<CryptoApiMatchedPolicy> matchedPolicies = [];
        foreach (CryptoApiPolicyRecord policy in authorizationState.SharedPolicies)
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
