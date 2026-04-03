using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.Native;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.Operations;
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
                "Machine-facing host for customer-facing sign/verify/random workflows backed by shared API-key auth, alias routing, and policy checks. No local operator UI or per-node auth/policy files.",
                descriptor.CurrentSurface,
                descriptor.SharedPersistenceConfigured,
                descriptor.SharedPersistenceProvider,
                descriptor.SharedReadyAreas,
                new CryptoApiHealthLinks(CryptoApiHostDefaults.HealthLivePath, CryptoApiHostDefaults.HealthReadyPath),
                [
                    $"{CryptoApiAuthenticationDefaults.ApiKeyIdHeaderName}: public API key identifier",
                    $"{CryptoApiAuthenticationDefaults.ApiKeySecretHeaderName}: one-time revealed API key secret",
                    $"POST {descriptor.ApiBasePath}/operations/sign with {{ keyAlias, algorithm, payloadBase64 }}",
                    $"POST {descriptor.ApiBasePath}/operations/verify with {{ keyAlias, algorithm, payloadBase64, signatureBase64 }}",
                    $"POST {descriptor.ApiBasePath}/operations/random with {{ keyAlias, length }}"
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
                "Customer-facing v1 sign/verify/random routes are live and reuse the shared API-key, alias-routing, and policy-enforcement model.",
                ["sign", "verify", "random"],
                ["key metadata lookup", "encrypt", "decrypt", "wrap", "unwrap"],
                ["POST /operations/authorize", "POST /operations/sign", "POST /operations/verify", "POST /operations/random"]));
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
            AuthenticationAttempt authentication = await AuthenticateAsync(httpContext, authenticationService, cancellationToken);
            if (authentication.Error is not null)
            {
                return authentication.Error;
            }

            CryptoApiAuthenticatedClient client = authentication.Client!;
            return Results.Ok(ToAuthenticatedClientDocument(client));
        });

        group.MapPost("/operations/authorize", static async Task<IResult> (
            HttpContext httpContext,
            CryptoApiAuthorizeKeyOperationRequest request,
            CryptoApiClientAuthenticationService authenticationService,
            CryptoApiKeyOperationAuthorizationService authorizationService,
            CancellationToken cancellationToken) =>
        {
            AuthorizationAttempt authorization = await AuthenticateAndAuthorizeAsync(
                httpContext,
                request.KeyAlias,
                request.Operation,
                authenticationService,
                authorizationService,
                cancellationToken);

            if (authorization.Error is not null)
            {
                return authorization.Error;
            }

            CryptoApiAuthorizedKeyOperation allowedOperation = authorization.Authorization!;
            return Results.Ok(new CryptoApiAuthorizedKeyOperationDocument(
                Client: ToAuthenticatedClientDocument(allowedOperation.Client),
                Authorization: new CryptoApiAuthorizedKeyOperationSummary(
                    Operation: allowedOperation.Operation,
                    AliasId: allowedOperation.AliasId,
                    AliasName: allowedOperation.AliasName,
                    AuthorizedAtUtc: allowedOperation.AuthorizedAtUtc),
                Policies: allowedOperation.MatchedPolicies
                    .Select(policy => new CryptoApiMatchedPolicyDocument(policy.PolicyId, policy.PolicyName, policy.Revision))
                    .ToArray()));
        });

        group.MapPost("/operations/sign", static async Task<IResult> (
            HttpContext httpContext,
            CryptoApiSignRequest request,
            CryptoApiClientAuthenticationService authenticationService,
            CryptoApiKeyOperationAuthorizationService authorizationService,
            ICryptoApiCustomerOperationService operationService,
            CancellationToken cancellationToken) =>
        {
            AuthorizationAttempt authorization = await AuthenticateAndAuthorizeAsync(
                httpContext,
                request.KeyAlias,
                "sign",
                authenticationService,
                authorizationService,
                cancellationToken);

            if (authorization.Error is not null)
            {
                return authorization.Error;
            }

            try
            {
                CryptoApiSignOperationResult result = operationService.Sign(authorization.Authorization!, request.Algorithm, request.PayloadBase64);
                return Results.Ok(new
                {
                    authorization.Authorization!.AliasName,
                    result.Algorithm,
                    SignatureBase64 = Convert.ToBase64String(result.Signature),
                    SignatureLength = result.Signature.Length,
                    SignedAtUtc = result.CompletedAtUtc
                });
            }
            catch (Exception ex)
            {
                return CreateOperationProblem("Sign request failed.", ex);
            }
        });

        group.MapPost("/operations/verify", static async Task<IResult> (
            HttpContext httpContext,
            CryptoApiVerifyRequest request,
            CryptoApiClientAuthenticationService authenticationService,
            CryptoApiKeyOperationAuthorizationService authorizationService,
            ICryptoApiCustomerOperationService operationService,
            CancellationToken cancellationToken) =>
        {
            AuthorizationAttempt authorization = await AuthenticateAndAuthorizeAsync(
                httpContext,
                request.KeyAlias,
                "verify",
                authenticationService,
                authorizationService,
                cancellationToken);

            if (authorization.Error is not null)
            {
                return authorization.Error;
            }

            try
            {
                CryptoApiVerifyOperationResult result = operationService.Verify(authorization.Authorization!, request.Algorithm, request.PayloadBase64, request.SignatureBase64);
                return Results.Ok(new
                {
                    authorization.Authorization!.AliasName,
                    result.Algorithm,
                    result.Verified,
                    VerifiedAtUtc = result.CompletedAtUtc
                });
            }
            catch (Exception ex)
            {
                return CreateOperationProblem("Verify request failed.", ex);
            }
        });

        group.MapPost("/operations/random", static async Task<IResult> (
            HttpContext httpContext,
            CryptoApiRandomRequest request,
            CryptoApiClientAuthenticationService authenticationService,
            CryptoApiKeyOperationAuthorizationService authorizationService,
            ICryptoApiCustomerOperationService operationService,
            CancellationToken cancellationToken) =>
        {
            AuthorizationAttempt authorization = await AuthenticateAndAuthorizeAsync(
                httpContext,
                request.KeyAlias,
                "random",
                authenticationService,
                authorizationService,
                cancellationToken);

            if (authorization.Error is not null)
            {
                return authorization.Error;
            }

            try
            {
                CryptoApiRandomOperationResult result = operationService.GenerateRandom(authorization.Authorization!, request.Length);
                return Results.Ok(new
                {
                    authorization.Authorization!.AliasName,
                    request.Length,
                    RandomBase64 = Convert.ToBase64String(result.RandomBytes),
                    GeneratedAtUtc = result.CompletedAtUtc
                });
            }
            catch (Exception ex)
            {
                return CreateOperationProblem("Random request failed.", ex);
            }
        });

        return endpoints;
    }

    private static async Task<AuthenticationAttempt> AuthenticateAsync(
        HttpContext httpContext,
        CryptoApiClientAuthenticationService authenticationService,
        CancellationToken cancellationToken)
    {
        string? keyIdentifier = httpContext.Request.Headers[CryptoApiAuthenticationDefaults.ApiKeyIdHeaderName].ToString();
        string? secret = httpContext.Request.Headers[CryptoApiAuthenticationDefaults.ApiKeySecretHeaderName].ToString();
        CryptoApiClientAuthenticationResult result = await authenticationService.AuthenticateAsync(keyIdentifier, secret, cancellationToken);
        if (!result.Succeeded || result.Client is null)
        {
            return new AuthenticationAttempt(
                null,
                Results.Problem(
                    title: "API key authentication failed.",
                    detail: result.FailureReason,
                    statusCode: StatusCodes.Status401Unauthorized));
        }

        return new AuthenticationAttempt(result.Client, null);
    }

    private static async Task<AuthorizationAttempt> AuthenticateAndAuthorizeAsync(
        HttpContext httpContext,
        string? keyAlias,
        string? operation,
        CryptoApiClientAuthenticationService authenticationService,
        CryptoApiKeyOperationAuthorizationService authorizationService,
        CancellationToken cancellationToken)
    {
        AuthenticationAttempt authentication = await AuthenticateAsync(httpContext, authenticationService, cancellationToken);
        if (authentication.Error is not null)
        {
            return new AuthorizationAttempt(null, authentication.Error);
        }

        try
        {
            CryptoApiKeyOperationAuthorizationResult authorization = await authorizationService.AuthorizeAsync(
                authentication.Client!,
                keyAlias,
                operation,
                cancellationToken);

            if (!authorization.Succeeded || authorization.Authorization is null)
            {
                return new AuthorizationAttempt(
                    null,
                    Results.Problem(
                        title: "Key alias authorization failed.",
                        detail: authorization.FailureReason,
                        statusCode: StatusCodes.Status403Forbidden));
            }

            return new AuthorizationAttempt(authorization.Authorization, null);
        }
        catch (ArgumentException ex)
        {
            return new AuthorizationAttempt(
                null,
                Results.Problem(
                    title: "Invalid authorization request.",
                    detail: ex.Message,
                    statusCode: StatusCodes.Status400BadRequest));
        }
    }

    private static IResult CreateOperationProblem(string title, Exception exception)
        => exception switch
        {
            ArgumentException ex => Results.Problem(title: title, detail: ex.Message, statusCode: StatusCodes.Status400BadRequest),
            CryptoApiOperationConfigurationException ex => Results.Problem(title: title, detail: ex.Message, statusCode: StatusCodes.Status503ServiceUnavailable),
            CryptoApiOperationExecutionException ex => Results.Problem(title: title, detail: ex.Message, statusCode: StatusCodes.Status422UnprocessableEntity),
            Pkcs11Exception ex => Results.Problem(title: title, detail: ex.Message, statusCode: StatusCodes.Status422UnprocessableEntity),
            InvalidOperationException ex => Results.Problem(title: title, detail: ex.Message, statusCode: StatusCodes.Status422UnprocessableEntity),
            _ => Results.Problem(title: title, detail: "The Crypto API host could not complete the request.", statusCode: StatusCodes.Status500InternalServerError)
        };

    private static CryptoApiAuthenticatedClientDocument ToAuthenticatedClientDocument(CryptoApiAuthenticatedClient client)
        => new(
            client.ClientId,
            client.ClientName,
            client.DisplayName,
            client.ApplicationType,
            client.AuthenticationMode,
            client.ClientKeyId,
            client.KeyIdentifier,
            client.CredentialType,
            client.AuthenticatedAtUtc,
            client.ExpiresAtUtc,
            client.BoundPolicyIds);

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
        IReadOnlyList<string> CurrentOperations,
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

    private sealed record CryptoApiSignRequest(
        string KeyAlias,
        string Algorithm,
        string PayloadBase64);

    private sealed record CryptoApiVerifyRequest(
        string KeyAlias,
        string Algorithm,
        string PayloadBase64,
        string SignatureBase64);

    private sealed record CryptoApiRandomRequest(
        string KeyAlias,
        int Length);

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

    private sealed record AuthenticationAttempt(
        CryptoApiAuthenticatedClient? Client,
        IResult? Error);

    private sealed record AuthorizationAttempt(
        CryptoApiAuthorizedKeyOperation? Authorization,
        IResult? Error);
}
