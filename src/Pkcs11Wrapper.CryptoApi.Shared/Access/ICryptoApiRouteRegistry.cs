using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Access;

public interface ICryptoApiRouteRegistry
{
    CryptoApiRoutePlanResolutionResult Resolve(CryptoApiKeyAliasRecord alias);
}

public readonly record struct CryptoApiRoutePlanResolutionResult(
    bool Succeeded,
    string? FailureReason,
    CryptoApiRoutePlan? RoutePlan)
{
    public static CryptoApiRoutePlanResolutionResult Success(CryptoApiRoutePlan routePlan)
        => new(true, null, routePlan);

    public static CryptoApiRoutePlanResolutionResult Failure(string reason)
        => new(false, reason, null);
}

public sealed class CryptoApiLegacyRouteRegistry : ICryptoApiRouteRegistry
{
    public CryptoApiRoutePlanResolutionResult Resolve(CryptoApiKeyAliasRecord alias)
    {
        ArgumentNullException.ThrowIfNull(alias);

        if (!string.IsNullOrWhiteSpace(alias.RouteGroupName))
        {
            return CryptoApiRoutePlanResolutionResult.Failure(
                $"Route group '{alias.RouteGroupName}' is not configured on this Crypto API host.");
        }

        if (alias.SlotId is null)
        {
            return CryptoApiRoutePlanResolutionResult.Failure(
                $"Key alias '{alias.AliasName}' does not define a slot id or route group.");
        }

        return CryptoApiRoutePlanResolutionResult.Success(
            new CryptoApiRoutePlan(
                RouteGroupName: null,
                SelectionMode: "legacy-single-route",
                Candidates:
                [
                    new CryptoApiRouteCandidate(
                        DeviceRoute: alias.DeviceRoute,
                        SlotId: alias.SlotId.Value,
                        Priority: 0)
                ],
                ObjectLabel: alias.ObjectLabel,
                ObjectIdHex: alias.ObjectIdHex));
    }
}
