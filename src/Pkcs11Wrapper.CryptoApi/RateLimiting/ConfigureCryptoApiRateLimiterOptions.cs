using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Configuration;

namespace Pkcs11Wrapper.CryptoApi.RateLimiting;

internal sealed class ConfigureCryptoApiRateLimiterOptions(
    IOptions<CryptoApiRateLimitingOptions> settings) : IConfigureOptions<RateLimiterOptions>
{
    public void Configure(RateLimiterOptions options)
        => options.ConfigureCryptoApiPolicies(settings.Value);
}
