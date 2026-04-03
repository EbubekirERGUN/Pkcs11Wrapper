using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.Runtime;
using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.CryptoApi.Endpoints;

public static class CryptoApiRouteBuilderExtensions
{
    public static IEndpointRouteBuilder MapCryptoApiRoutes(this IEndpointRouteBuilder endpoints, CryptoApiHostOptions hostOptions)
    {
        string apiBasePath = CryptoApiHostDefaults.NormalizeBasePath(hostOptions.ApiBasePath);
        RouteGroupBuilder group = endpoints.MapGroup(apiBasePath)
            .WithTags("Crypto API");

        group.MapGet("/", static (CryptoApiRuntimeDescriptorProvider descriptorProvider) =>
        {
            CryptoApiRuntimeDescriptor descriptor = descriptorProvider.Describe();
            return TypedResults.Ok(new CryptoApiServiceDocument(
                descriptor.ServiceName,
                descriptor.InstanceId,
                descriptor.ApiBasePath,
                descriptor.DeploymentModel,
                "Machine-facing host for future sign/verify/encrypt/decrypt workflows. No local operator UI or per-node auth/policy files.",
                descriptor.CurrentSurface,
                descriptor.SharedPersistenceConfigured,
                descriptor.SharedPersistenceProvider,
                descriptor.SharedReadyAreas,
                new CryptoApiHealthLinks(CryptoApiHostDefaults.HealthLivePath, CryptoApiHostDefaults.HealthReadyPath),
                [
                    "Request authentication/authorization backed by shared client/key state",
                    "Concrete crypto operation endpoints",
                    "Request-scoped key resolution and policy enforcement backed by shared aliases/policies"
                ]));
        });

        group.MapGet("/runtime", static (CryptoApiRuntimeDescriptorProvider descriptorProvider)
            => TypedResults.Ok(descriptorProvider.Describe()));

        group.MapGet("/operations", static (CryptoApiRuntimeDescriptorProvider descriptorProvider) =>
        {
            CryptoApiRuntimeDescriptor descriptor = descriptorProvider.Describe();
            return TypedResults.Ok(new CryptoApiOperationSurfaceDocument(
                descriptor.ServiceName,
                descriptor.ApiBasePath,
                "Scaffold only. Concrete crypto request/response contracts will be added under this route space without turning the host into a stateful admin portal or relying on per-node local auth/policy files.",
                ["sign", "verify", "encrypt", "decrypt", "unwrap/wrap", "key metadata lookup"]));
        });

        group.MapGet("/shared-state", static async Task<IResult> (ICryptoApiSharedStateStore sharedStateStore, CancellationToken cancellationToken) =>
        {
            CryptoApiSharedStateStatus status = await sharedStateStore.GetStatusAsync(cancellationToken);
            return status.Configured
                ? Results.Ok(status)
                : Results.Problem(
                    title: "Shared persistence is not configured.",
                    detail: "Configure CryptoApiSharedPersistence:ConnectionString to enable shared API client/key, alias, and policy state.",
                    statusCode: StatusCodes.Status503ServiceUnavailable);
        });

        return endpoints;
    }

    private sealed record CryptoApiServiceDocument(
        string ServiceName,
        string InstanceId,
        string ApiBasePath,
        string DeploymentModel,
        string Boundary,
        IReadOnlyList<string> CurrentSurface,
        bool SharedPersistenceConfigured,
        string SharedPersistenceProvider,
        IReadOnlyList<string> SharedReadyAreas,
        CryptoApiHealthLinks Health,
        IReadOnlyList<string> PlannedExpansion);

    private sealed record CryptoApiHealthLinks(
        string Live,
        string Ready);

    private sealed record CryptoApiOperationSurfaceDocument(
        string ServiceName,
        string ApiBasePath,
        string Status,
        IReadOnlyList<string> PlannedOperations);
}
