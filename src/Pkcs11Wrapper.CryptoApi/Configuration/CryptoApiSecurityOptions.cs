namespace Pkcs11Wrapper.CryptoApi.Configuration;

public sealed class CryptoApiSecurityOptions
{
    public const string SectionName = "CryptoApiSecurity";

    public bool ExposeDetailedErrors { get; set; }

    public bool ExposeSharedStateDetails { get; set; }
}
