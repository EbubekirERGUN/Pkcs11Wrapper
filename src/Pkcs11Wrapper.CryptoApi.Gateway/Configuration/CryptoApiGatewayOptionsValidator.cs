using Microsoft.Extensions.Options;

namespace Pkcs11Wrapper.CryptoApi.Gateway.Configuration;

public sealed class CryptoApiGatewayOptionsValidator : IValidateOptions<CryptoApiGatewayOptions>
{
    public ValidateOptionsResult Validate(string? name, CryptoApiGatewayOptions options)
    {
        try
        {
            CryptoApiGatewayOptionsLoader.Normalize(options);
            CryptoApiGatewayOptionsLoader.Validate(options);
            return ValidateOptionsResult.Success;
        }
        catch (Exception ex)
        {
            return ValidateOptionsResult.Fail(ex.Message);
        }
    }
}
