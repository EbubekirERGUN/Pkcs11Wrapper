using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Clients;

public sealed class CryptoApiClientAuthenticationService(
    ICryptoApiSharedStateStore sharedStateStore,
    CryptoApiClientSecretHasher secretHasher,
    TimeProvider timeProvider)
{
    public async Task<CryptoApiClientAuthenticationResult> AuthenticateAsync(string? keyIdentifier, string? secret, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(keyIdentifier) || string.IsNullOrWhiteSpace(secret))
        {
            return Failed("API key id and secret are required.");
        }

        CryptoApiSharedStateStatus status = await sharedStateStore.GetStatusAsync(cancellationToken);
        if (!status.Configured)
        {
            return Failed("Shared persistence is not configured.");
        }

        CryptoApiSharedStateSnapshot snapshot = await sharedStateStore.GetSnapshotAsync(cancellationToken);
        CryptoApiClientKeyRecord? key = snapshot.ClientKeys.FirstOrDefault(candidate => string.Equals(candidate.KeyIdentifier, keyIdentifier.Trim(), StringComparison.Ordinal));
        if (key is null)
        {
            return Failed("API key was not found.");
        }

        CryptoApiClientRecord? client = snapshot.Clients.FirstOrDefault(candidate => candidate.ClientId == key.ClientId);
        if (client is null)
        {
            return Failed("Owning API client was not found.");
        }

        DateTimeOffset now = timeProvider.GetUtcNow();
        if (!client.IsEnabled)
        {
            return Failed("API client is disabled.");
        }

        if (key.RevokedAtUtc is not null)
        {
            return Failed("API key has been revoked.");
        }

        if (!key.IsEnabled)
        {
            return Failed("API key is disabled.");
        }

        if (key.ExpiresAtUtc is DateTimeOffset expiresAtUtc && expiresAtUtc <= now)
        {
            return Failed("API key has expired.");
        }

        if (!secretHasher.VerifySecret(secret.Trim(), key.SecretHash))
        {
            return Failed("API key secret is invalid.");
        }

        await sharedStateStore.UpsertClientKeyAsync(key with
        {
            LastUsedAtUtc = now,
            UpdatedAtUtc = now
        }, cancellationToken);

        Guid[] boundPolicyIds = snapshot.ClientPolicyBindings
            .Where(binding => binding.ClientId == client.ClientId)
            .Select(binding => binding.PolicyId)
            .Distinct()
            .OrderBy(id => id)
            .ToArray();

        return new CryptoApiClientAuthenticationResult(
            Succeeded: true,
            FailureReason: null,
            Client: new CryptoApiAuthenticatedClient(
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
                BoundPolicyIds: boundPolicyIds));
    }

    private static CryptoApiClientAuthenticationResult Failed(string reason)
        => new(
            Succeeded: false,
            FailureReason: reason,
            Client: null);
}
