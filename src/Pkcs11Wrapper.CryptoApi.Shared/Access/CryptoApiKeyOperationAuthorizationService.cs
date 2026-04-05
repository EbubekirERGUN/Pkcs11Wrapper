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
    private readonly ICryptoApiRouteRegistry _routeRegistry;

    public CryptoApiKeyOperationAuthorizationService(
        ICryptoApiSharedStateStore sharedStateStore,
        ICryptoApiDistributedHotPathCache distributedHotPathCache,
        TimeProvider timeProvider,
        CryptoApiClientSecretHasher? secretHasher = null,
        CryptoApiRequestPathCache? requestPathCache = null,
        ICryptoApiRouteRegistry? routeRegistry = null)
    {
        _sharedStateStore = sharedStateStore;
        _distributedHotPathCache = distributedHotPathCache;
        _timeProvider = timeProvider;
        _secretHasher = secretHasher ?? new CryptoApiClientSecretHasher();
        _requestPathCache = requestPathCache ?? new CryptoApiRequestPathCache(timeProvider);
        _routeRegistry = routeRegistry ?? new CryptoApiLegacyRouteRegistry();
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
            CryptoApiAuthenticatedClient? resolvedClient = await AuthenticateClientAsync(authStateRevision, normalizedKeyIdentifier, normalizedSecret, secretFingerprint, now, cancellationToken);
            if (resolvedClient is null)
            {
                return AuthenticationFailed("API key id or secret is invalid.");
            }

            authenticatedClient = resolvedClient;
        }

        if (_requestPathCache.TryGetAuthorizedOperation(authStateRevision, authenticatedClient.ClientId, normalizedAliasName, normalizedOperation, authenticatedClient, now, out CryptoApiAuthorizedKeyOperation cachedAuthorization))
        {
            return Success(cachedAuthorization);
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
            return Success(distributedAuthorization);
        }

        CryptoApiKeyOperationAuthorizationResult authorization = await AuthorizeKeyOperationAsync(authenticatedClient, normalizedAliasName, normalizedOperation, cancellationToken);
        if (!authorization.Succeeded || authorization.Authorization is null)
        {
            return AuthorizationFailed(authorization.FailureReason ?? "Authorization failed.");
        }

        _requestPathCache.SetAuthorizedOperation(authStateRevision, authenticatedClient.ClientId, authorization.Authorization);
        await _distributedHotPathCache.SetAuthorizedOperationAsync(
            authStateRevision,
            authenticatedClient.ClientId,
            authorization.Authorization,
            cancellationToken);

        return Success(authorization.Authorization);
    }

    public Task<CryptoApiKeyOperationAuthorizationResult> AuthorizeAsync(
        CryptoApiAuthenticatedClient authenticatedClient,
        string aliasName,
        string operation,
        CancellationToken cancellationToken = default)
        => AuthorizeKeyOperationAsync(authenticatedClient, aliasName, operation, cancellationToken);

    private async Task<CryptoApiAuthenticatedClient?> AuthenticateClientAsync(
        long authStateRevision,
        string keyIdentifier,
        string secret,
        string secretFingerprint,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        CryptoApiAuthenticatedClient? distributedClient = await _distributedHotPathCache.GetAuthenticatedClientAsync(
            authStateRevision,
            keyIdentifier,
            secretFingerprint,
            now,
            cancellationToken);

        if (distributedClient is not null)
        {
            _requestPathCache.SetAuthenticatedClient(authStateRevision, keyIdentifier, secretFingerprint, distributedClient, distributedClient.AuthenticatedAtUtc);
            return distributedClient;
        }

        CryptoApiClientAuthenticationState? state = await _sharedStateStore.GetClientAuthenticationStateAsync(keyIdentifier, cancellationToken);
        if (state is null)
        {
            return null;
        }

        if (!state.Client.IsEnabled || !state.Key.IsEnabled)
        {
            return null;
        }

        if (state.Key.RevokedAtUtc is not null)
        {
            return null;
        }

        if (state.Key.ExpiresAtUtc is DateTimeOffset expiresAtUtc && expiresAtUtc <= now)
        {
            return null;
        }

        if (!_secretHasher.VerifySecret(secret, state.Key.SecretHash))
        {
            return null;
        }

        bool refreshed = false;
        if (_requestPathCache.ShouldRefreshLastUsed(authStateRevision, keyIdentifier, secretFingerprint, now))
        {
            refreshed = await TryRefreshLastUsedAsync(state.Key.ClientKeyId, now, cancellationToken);
            if (refreshed)
            {
                _requestPathCache.RecordLastUsedRefresh(authStateRevision, keyIdentifier, secretFingerprint, now);
            }
        }

        CryptoApiAuthenticatedClient authenticatedClient = new(
            ClientId: state.Client.ClientId,
            ClientName: state.Client.ClientName,
            DisplayName: state.Client.DisplayName,
            ApplicationType: state.Client.ApplicationType,
            AuthenticationMode: state.Client.AuthenticationMode,
            ClientKeyId: state.Key.ClientKeyId,
            KeyIdentifier: state.Key.KeyIdentifier,
            CredentialType: state.Key.CredentialType,
            BoundPolicyIds: state.BoundPolicyIds,
            AuthenticatedAtUtc: now,
            ExpiresAtUtc: state.Key.ExpiresAtUtc);

        _requestPathCache.SetAuthenticatedClient(authStateRevision, keyIdentifier, secretFingerprint, authenticatedClient, now);
        await _distributedHotPathCache.SetAuthenticatedClientAsync(authStateRevision, keyIdentifier, secretFingerprint, authenticatedClient, cancellationToken);
        return authenticatedClient;
    }

    private async Task<bool> TryRefreshLastUsedAsync(Guid clientKeyId, DateTimeOffset now, CancellationToken cancellationToken)
    {
        TimeSpan minimumInterval = _requestPathCache.LastUsedWriteInterval;
        bool? leaseAcquired = await _distributedHotPathCache.TryAcquireLastUsedRefreshLeaseAsync(clientKeyId, now, minimumInterval, cancellationToken);
        if (leaseAcquired == false)
        {
            return false;
        }

        return await _sharedStateStore.TryTouchClientKeyLastUsedAsync(clientKeyId, now, minimumInterval, cancellationToken);
    }

    public async Task<CryptoApiKeyOperationAuthorizationResult> AuthorizeKeyOperationAsync(
        CryptoApiAuthenticatedClient authenticatedClient,
        string aliasName,
        string operation,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(authenticatedClient);

        string normalizedAliasName = NormalizeAliasName(aliasName, nameof(aliasName));
        string normalizedOperation = CryptoApiOperationPolicyDocumentCodec.NormalizeOperation(operation, nameof(operation));

        CryptoApiKeyAuthorizationState authorizationState = await _sharedStateStore.GetKeyAuthorizationStateAsync(
            authenticatedClient.ClientId,
            normalizedAliasName,
            cancellationToken);

        CryptoApiClientRecord? client = authorizationState.Client;
        if (client is null)
        {
            return Failed("Authenticated client was not found in shared persistence.");
        }

        if (!client.IsEnabled)
        {
            return Failed("Authenticated client is disabled.");
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

        CryptoApiRoutePlanResolutionResult routePlanResult = _routeRegistry.Resolve(alias);
        if (!routePlanResult.Succeeded || routePlanResult.RoutePlan is null)
        {
            return Failed(routePlanResult.FailureReason ?? "No route plan could be resolved for the requested key alias.");
        }

        return new CryptoApiKeyOperationAuthorizationResult(
            Succeeded: true,
            FailureReason: null,
            Authorization: new CryptoApiAuthorizedKeyOperation(
                Client: authenticatedClient,
                Operation: normalizedOperation,
                AliasId: alias.AliasId,
                AliasName: alias.AliasName,
                RoutePlan: routePlanResult.RoutePlan,
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

    private static CryptoApiRequestAuthorizationResult Success(CryptoApiAuthorizedKeyOperation authorization)
        => new(
            Succeeded: true,
            FailureStatusCode: null,
            FailureReason: null,
            Authorization: authorization);

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
}
