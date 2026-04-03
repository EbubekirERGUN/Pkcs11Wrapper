using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Clients;
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
                    $"{CryptoApiAuthenticationDefaults.ApiKeyIdHeaderName}: public API key identifier",
                    $"{CryptoApiAuthenticationDefaults.ApiKeySecretHeaderName}: one-time revealed API key secret",
                    $"POST {descriptor.ApiBasePath}/operations/authorize for alias + operation policy checks",
                    "Concrete sign/verify/encrypt/decrypt request contracts that reuse the shared alias/policy model"
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
                "The first request-scoped alias-routing and policy-enforcement slice is live via POST /operations/authorize. Concrete crypto request/response contracts will be added under this route space without turning the host into a stateful admin portal or relying on per-node local auth/policy files.",
                ["sign", "verify", "encrypt", "decrypt", "unwrap/wrap", "key metadata lookup"],
                ["POST /operations/authorize"]));
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

        group.MapGet("/auth/self", static async Task<IResult> (HttpContext httpContext, CryptoApiClientAuthenticationService authenticationService, CancellationToken cancellationToken) =>
        {
            string? keyIdentifier = httpContext.Request.Headers[CryptoApiAuthenticationDefaults.ApiKeyIdHeaderName].ToString();
            string? secret = httpContext.Request.Headers[CryptoApiAuthenticationDefaults.ApiKeySecretHeaderName].ToString();
            CryptoApiClientAuthenticationResult result = await authenticationService.AuthenticateAsync(keyIdentifier, secret, cancellationToken);
            if (!result.Succeeded || result.Client is null)
            {
                return Results.Problem(
                    title: "API key authentication failed.",
                    detail: result.FailureReason,
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            return Results.Ok(new CryptoApiAuthenticatedClientDocument(
                result.Client.ClientId,
                result.Client.ClientName,
                result.Client.DisplayName,
                result.Client.ApplicationType,
                result.Client.AuthenticationMode,
                result.Client.ClientKeyId,
                result.Client.KeyIdentifier,
                result.Client.CredentialType,
                result.Client.AuthenticatedAtUtc,
                result.Client.ExpiresAtUtc,
                result.Client.BoundPolicyIds));
        });

        group.MapPost("/operations/authorize", static async Task<IResult> (
            HttpContext httpContext,
            CryptoApiAuthorizeKeyOperationRequest request,
            CryptoApiClientAuthenticationService authenticationService,
            CryptoApiKeyOperationAuthorizationService authorizationService,
            CancellationToken cancellationToken) =>
        {
            string? keyIdentifier = httpContext.Request.Headers[CryptoApiAuthenticationDefaults.ApiKeyIdHeaderName].ToString();
            string? secret = httpContext.Request.Headers[CryptoApiAuthenticationDefaults.ApiKeySecretHeaderName].ToString();
            CryptoApiClientAuthenticationResult authentication = await authenticationService.AuthenticateAsync(keyIdentifier, secret, cancellationToken);
            if (!authentication.Succeeded || authentication.Client is null)
            {
                return Results.Problem(
                    title: "API key authentication failed.",
                    detail: authentication.FailureReason,
                    statusCode: StatusCodes.Status401Unauthorized);
            }

            CryptoApiKeyOperationAuthorizationResult authorization;
            try
            {
                authorization = await authorizationService.AuthorizeAsync(
                    authentication.Client,
                    request.KeyAlias,
                    request.Operation,
                    cancellationToken);
            }
            catch (ArgumentException ex)
            {
                return Results.Problem(
                    title: "Invalid authorization request.",
                    detail: ex.Message,
                    statusCode: StatusCodes.Status400BadRequest);
            }

            if (!authorization.Succeeded || authorization.Authorization is null)
            {
                return Results.Problem(
                    title: "Key alias authorization failed.",
                    detail: authorization.FailureReason,
                    statusCode: StatusCodes.Status403Forbidden);
            }

            CryptoApiAuthorizedKeyOperation allowedOperation = authorization.Authorization;
            return Results.Ok(new CryptoApiAuthorizedKeyOperationDocument(
                Client: new CryptoApiAuthenticatedClientDocument(
                    allowedOperation.Client.ClientId,
                    allowedOperation.Client.ClientName,
                    allowedOperation.Client.DisplayName,
                    allowedOperation.Client.ApplicationType,
                    allowedOperation.Client.AuthenticationMode,
                    allowedOperation.Client.ClientKeyId,
                    allowedOperation.Client.KeyIdentifier,
                    allowedOperation.Client.CredentialType,
                    allowedOperation.Client.AuthenticatedAtUtc,
                    allowedOperation.Client.ExpiresAtUtc,
                    allowedOperation.Client.BoundPolicyIds),
                Authorization: new CryptoApiAuthorizedKeyOperationSummary(
                    Operation: allowedOperation.Operation,
                    AliasId: allowedOperation.AliasId,
                    AliasName: allowedOperation.AliasName,
                    AuthorizedAtUtc: allowedOperation.AuthorizedAtUtc),
                Policies: allowedOperation.MatchedPolicies
                    .Select(policy => new CryptoApiMatchedPolicyDocument(policy.PolicyId, policy.PolicyName, policy.Revision))
                    .ToArray()));
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
        IReadOnlyList<string> PlannedOperations,
        IReadOnlyList<string> CurrentEndpoints);

    private sealed record CryptoApiAuthenticatedClientDocument(
        Guid ClientId,
        string ClientName,
        string DisplayName,
        string ApplicationType,
        string AuthenticationMode,
        Guid ClientKeyId,
        string KeyIdentifier,
        string CredentialType,
        DateTimeOffset AuthenticatedAtUtc,
        DateTimeOffset? ExpiresAtUtc,
        IReadOnlyList<Guid> BoundPolicyIds);

    private sealed record CryptoApiAuthorizeKeyOperationRequest(
        string KeyAlias,
        string Operation);

    private sealed record CryptoApiAuthorizedKeyOperationDocument(
        CryptoApiAuthenticatedClientDocument Client,
        CryptoApiAuthorizedKeyOperationSummary Authorization,
        IReadOnlyList<CryptoApiMatchedPolicyDocument> Policies);

    private sealed record CryptoApiAuthorizedKeyOperationSummary(
        string Operation,
        Guid AliasId,
        string AliasName,
        DateTimeOffset AuthorizedAtUtc);

    private sealed record CryptoApiMatchedPolicyDocument(
        Guid PolicyId,
        string PolicyName,
        int Revision);
}
