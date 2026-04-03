using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.Runtime;

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
                "Machine-facing host for future sign/verify/encrypt/decrypt workflows. No local operator UI or persistent host state.",
                descriptor.CurrentSurface,
                new CryptoApiHealthLinks(CryptoApiHostDefaults.HealthLivePath, CryptoApiHostDefaults.HealthReadyPath),
                [
                    "Request authentication/authorization",
                    "Concrete crypto operation endpoints",
                    "Request-scoped key resolution and policy enforcement"
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
                "Scaffold only. Concrete crypto request/response contracts will be added under this route space without turning the host into a stateful admin portal.",
                ["sign", "verify", "encrypt", "decrypt", "unwrap/wrap", "key metadata lookup"]));
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
