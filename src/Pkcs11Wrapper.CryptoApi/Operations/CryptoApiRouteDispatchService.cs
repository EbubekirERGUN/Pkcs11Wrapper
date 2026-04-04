using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Configuration;

namespace Pkcs11Wrapper.CryptoApi.Operations;

public sealed class CryptoApiRouteDispatchService(
    IOptions<CryptoApiRuntimeOptions> runtimeOptions,
    TimeProvider timeProvider)
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _unhealthyUntilUtc = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeSpan _cooldown = TimeSpan.FromSeconds(Math.Max(runtimeOptions.Value.RouteFailureCooldownSeconds, 0));

    public T Execute<T>(CryptoApiAuthorizedKeyOperation authorization, Func<CryptoApiResolvedKeyRoute, T> handler)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(handler);

        if (authorization.RoutePlan.Candidates.Count == 0)
        {
            throw new CryptoApiOperationConfigurationException(
                $"No backend candidates are available for alias '{authorization.AliasName}'.");
        }

        DateTimeOffset now = timeProvider.GetUtcNow();
        IReadOnlyList<CryptoApiRouteCandidate> orderedCandidates = OrderCandidates(authorization.RoutePlan.Candidates, now);
        CryptoApiRouteCandidateUnavailableException? lastFailure = null;

        foreach (CryptoApiRouteCandidate candidate in orderedCandidates)
        {
            try
            {
                return handler(new CryptoApiResolvedKeyRoute(
                    DeviceRoute: candidate.DeviceRoute,
                    SlotId: candidate.SlotId,
                    ObjectLabel: authorization.RoutePlan.ObjectLabel,
                    ObjectIdHex: authorization.RoutePlan.ObjectIdHex));
            }
            catch (CryptoApiRouteCandidateUnavailableException ex)
            {
                lastFailure = ex;
                MarkUnhealthy(candidate, now);
            }
        }

        string routeGroupLabel = authorization.RoutePlan.RouteGroupName ?? authorization.AliasName;
        if (lastFailure is null)
        {
            throw new CryptoApiOperationConfigurationException(
                $"All routed backends failed for '{routeGroupLabel}'. No candidate produced a successful execution result.");
        }

        throw new CryptoApiOperationConfigurationException(
            $"All routed backends failed for '{routeGroupLabel}'. Last failure: {lastFailure.Message}",
            lastFailure);
    }

    private IReadOnlyList<CryptoApiRouteCandidate> OrderCandidates(IReadOnlyList<CryptoApiRouteCandidate> candidates, DateTimeOffset now)
    {
        List<CryptoApiRouteCandidate> healthy = [];
        List<CryptoApiRouteCandidate> coolingDown = [];

        foreach (CryptoApiRouteCandidate candidate in candidates)
        {
            if (IsCoolingDown(candidate, now))
            {
                coolingDown.Add(candidate);
            }
            else
            {
                healthy.Add(candidate);
            }
        }

        return [.. healthy, .. coolingDown];
    }

    private bool IsCoolingDown(CryptoApiRouteCandidate candidate, DateTimeOffset now)
    {
        if (_cooldown <= TimeSpan.Zero)
        {
            return false;
        }

        string key = CreateCandidateKey(candidate);
        return _unhealthyUntilUtc.TryGetValue(key, out DateTimeOffset untilUtc) && untilUtc > now;
    }

    private void MarkUnhealthy(CryptoApiRouteCandidate candidate, DateTimeOffset now)
    {
        if (_cooldown <= TimeSpan.Zero)
        {
            return;
        }

        _unhealthyUntilUtc[CreateCandidateKey(candidate)] = now.Add(_cooldown);
    }

    private static string CreateCandidateKey(CryptoApiRouteCandidate candidate)
        => $"{candidate.DeviceRoute ?? "default"}:{candidate.SlotId}:{candidate.Priority}";
}

public sealed class CryptoApiRouteCandidateUnavailableException : Exception
{
    public CryptoApiRouteCandidateUnavailableException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}
