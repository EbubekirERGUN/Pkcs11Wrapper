namespace Pkcs11Wrapper.CryptoApi.Configuration;

public sealed class CryptoApiRuntimeOptions
{
    public const string SectionName = "CryptoApiRuntime";

    public string? ModulePath { get; set; }

    public string? UserPin { get; set; }

    public bool DisableHttpsRedirection { get; set; }
}
