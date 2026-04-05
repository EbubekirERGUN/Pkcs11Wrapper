using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Pkcs11Wrapper.CryptoApi.Clients;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.Observability;

namespace Pkcs11Wrapper.CryptoApi.RateLimiting;

public static class CryptoApiRateLimitingExtensions
{
    public const string AuthenticationPolicyName = "crypto-api-authentication";
    public const string OperationsPolicyName = "crypto-api-operations";
    public const string InstanceLocalMode = "instance-local";

    public static RateLimiterOptions ConfigureCryptoApiPolicies(this RateLimiterOptions options, CryptoApiRateLimitingOptions settings, CryptoApiMetrics? metrics = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(settings);

        options.OnRejected = async (context, cancellationToken) =>
        {
            CryptoApiRateLimitScopeMetadata metadata = context.HttpContext.GetEndpoint()?.Metadata.GetMetadata<CryptoApiRateLimitScopeMetadata>()
                ?? new CryptoApiRateLimitScopeMetadata("customer-api", 1L);

            metrics?.RecordRateLimitRejection(metadata.Scope);

            Dictionary<string, object?> extensions = new(StringComparer.Ordinal)
            {
                ["scope"] = metadata.Scope,
                ["mode"] = InstanceLocalMode
            };

            long retryAfterSeconds = Math.Max(1L, metadata.RetryAfterSeconds);
            if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out TimeSpan retryAfter))
            {
                retryAfterSeconds = Math.Max(1L, (long)Math.Ceiling(retryAfter.TotalSeconds));
            }

            context.HttpContext.Response.Headers.RetryAfter = retryAfterSeconds.ToString(CultureInfo.InvariantCulture);
            extensions["retryAfterSeconds"] = retryAfterSeconds;

            IResult result = Results.Problem(
                title: "Rate limit exceeded.",
                detail: "The built-in Crypto API rate limiter rejected the request. Wait for the retry interval and try again.",
                statusCode: StatusCodes.Status429TooManyRequests,
                extensions: extensions);

            await result.ExecuteAsync(context.HttpContext);
        };

        options.AddPolicy(AuthenticationPolicyName, httpContext => CreateSlidingWindowPartition(httpContext, settings.Enabled, settings.Authentication));
        options.AddPolicy(OperationsPolicyName, httpContext => CreateSlidingWindowPartition(httpContext, settings.Enabled, settings.Operations));

        return options;
    }

    public static TBuilder WithCryptoApiRateLimitScope<TBuilder>(this TBuilder builder, string scope, long retryAfterSeconds)
        where TBuilder : IEndpointConventionBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrWhiteSpace(scope);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(retryAfterSeconds);

        builder.WithMetadata(new CryptoApiRateLimitScopeMetadata(scope.Trim(), retryAfterSeconds));
        return builder;
    }

    private static RateLimitPartition<string> CreateSlidingWindowPartition(
        HttpContext httpContext,
        bool enabled,
        CryptoApiSlidingWindowRateLimitOptions settings)
    {
        string partitionKey = ResolvePartitionKey(httpContext);
        if (!enabled)
        {
            return RateLimitPartition.GetNoLimiter(partitionKey);
        }

        return RateLimitPartition.GetSlidingWindowLimiter(
            partitionKey,
            _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = settings.PermitLimit,
                Window = TimeSpan.FromSeconds(settings.WindowSeconds),
                SegmentsPerWindow = settings.SegmentsPerWindow,
                QueueLimit = settings.QueueLimit,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                AutoReplenishment = true
            });
    }

    private static string ResolvePartitionKey(HttpContext httpContext)
    {
        string? presentedKeyId = httpContext.Request.Headers[CryptoApiAuthenticationDefaults.ApiKeyIdHeaderName].ToString();
        if (!string.IsNullOrWhiteSpace(presentedKeyId))
        {
            return $"api-key:{NormalizePartitionToken(presentedKeyId)}";
        }

        string? remoteIp = httpContext.Connection.RemoteIpAddress?.ToString();
        if (!string.IsNullOrWhiteSpace(remoteIp))
        {
            return $"remote-ip:{remoteIp}";
        }

        return "anonymous";
    }

    private static string NormalizePartitionToken(string value)
    {
        string trimmed = value.Trim();
        if (trimmed.Length <= 96 && trimmed.All(static c => !char.IsControl(c)))
        {
            return trimmed;
        }

        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(trimmed));
        return Convert.ToHexString(hash);
    }

    private sealed record CryptoApiRateLimitScopeMetadata(string Scope, long RetryAfterSeconds);
}
