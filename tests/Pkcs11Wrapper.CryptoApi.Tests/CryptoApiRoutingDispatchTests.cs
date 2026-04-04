using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.Operations;
using Pkcs11Wrapper.CryptoApi.Runtime;
using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Tests;

public sealed class CryptoApiRoutingDispatchTests
{
    [Fact]
    public void ConfiguredRouteRegistryResolvesOrderedCandidatesForRouteGroupAliases()
    {
        CryptoApiConfiguredRouteRegistry registry = new(Options.Create(new CryptoApiRuntimeOptions
        {
            RouteGroups =
            [
                new CryptoApiRuntimeRouteGroupOptions
                {
                    Name = "payments-signers",
                    Backends =
                    [
                        new CryptoApiRuntimeRouteBackendOptions { BackendName = "hsm-secondary", SlotId = 9, Priority = 20 },
                        new CryptoApiRuntimeRouteBackendOptions { BackendName = "hsm-primary", SlotId = 7, Priority = 10 }
                    ]
                }
            ]
        }));

        CryptoApiKeyAliasRecord alias = new(
            AliasId: Guid.NewGuid(),
            AliasName: "payments-signer",
            RouteGroupName: "payments-signers",
            DeviceRoute: null,
            SlotId: null,
            ObjectLabel: "Payments key",
            ObjectIdHex: "A1B2",
            Notes: null,
            IsEnabled: true,
            CreatedAtUtc: DateTimeOffset.UtcNow,
            UpdatedAtUtc: DateTimeOffset.UtcNow);

        CryptoApiRoutePlanResolutionResult result = registry.Resolve(alias);

        Assert.True(result.Succeeded);
        CryptoApiRoutePlan plan = Assert.IsType<CryptoApiRoutePlan>(result.RoutePlan);
        Assert.Equal("payments-signers", plan.RouteGroupName);
        Assert.Collection(
            plan.Candidates,
            candidate =>
            {
                Assert.Equal("hsm-primary", candidate.DeviceRoute);
                Assert.Equal((ulong)7, candidate.SlotId);
                Assert.Equal(10, candidate.Priority);
            },
            candidate =>
            {
                Assert.Equal("hsm-secondary", candidate.DeviceRoute);
                Assert.Equal((ulong)9, candidate.SlotId);
                Assert.Equal(20, candidate.Priority);
            });
    }

    [Fact]
    public void RouteDispatchServiceFailsOverToNextCandidateAndThenCoolsDownFailingBackend()
    {
        AdjustableTimeProvider timeProvider = new();
        CryptoApiRouteDispatchService dispatcher = new(
            Options.Create(new CryptoApiRuntimeOptions { RouteFailureCooldownSeconds = 30 }),
            timeProvider);

        CryptoApiAuthorizedKeyOperation authorization = new(
            Client: new CryptoApiAuthenticatedClient(
                ClientId: Guid.NewGuid(),
                ClientName: "payments-gateway",
                DisplayName: "Payments Gateway",
                ApplicationType: "gateway",
                AuthenticationMode: "shared-secret",
                ClientKeyId: Guid.NewGuid(),
                KeyIdentifier: "kid-1",
                CredentialType: "api-key",
                AuthenticatedAtUtc: timeProvider.GetUtcNow(),
                ExpiresAtUtc: null,
                BoundPolicyIds: []),
            Operation: "sign",
            AliasId: Guid.NewGuid(),
            AliasName: "payments-signer",
            RoutePlan: new CryptoApiRoutePlan(
                RouteGroupName: "payments-signers",
                SelectionMode: "priority",
                Candidates:
                [
                    new CryptoApiRouteCandidate("hsm-primary", 7, 10),
                    new CryptoApiRouteCandidate("hsm-secondary", 9, 20)
                ],
                ObjectLabel: "Payments key",
                ObjectIdHex: "A1B2"),
            MatchedPolicies: [],
            AuthorizedAtUtc: timeProvider.GetUtcNow());

        List<string> attemptedRoutes = [];
        string result = dispatcher.Execute(authorization, route =>
        {
            attemptedRoutes.Add(route.DeviceRoute ?? "default");
            if (string.Equals(route.DeviceRoute, "hsm-primary", StringComparison.Ordinal))
            {
                throw new CryptoApiRouteCandidateUnavailableException("primary failed");
            }

            return route.DeviceRoute!;
        });

        Assert.Equal("hsm-secondary", result);
        Assert.Equal(["hsm-primary", "hsm-secondary"], attemptedRoutes);

        attemptedRoutes.Clear();
        string warmResult = dispatcher.Execute(authorization, route =>
        {
            attemptedRoutes.Add(route.DeviceRoute ?? "default");
            return route.DeviceRoute!;
        });

        Assert.Equal("hsm-secondary", warmResult);
        Assert.Equal(["hsm-secondary"], attemptedRoutes);

        timeProvider.Advance(TimeSpan.FromSeconds(31));
        attemptedRoutes.Clear();
        _ = dispatcher.Execute(authorization, route =>
        {
            attemptedRoutes.Add(route.DeviceRoute ?? "default");
            return route.DeviceRoute!;
        });

        Assert.Equal(["hsm-primary"], attemptedRoutes);
    }
}

internal sealed class AdjustableTimeProvider : TimeProvider
{
    private DateTimeOffset _utcNow = DateTimeOffset.UtcNow;

    public override DateTimeOffset GetUtcNow() => _utcNow;

    public void Advance(TimeSpan delta) => _utcNow = _utcNow.Add(delta);
}
