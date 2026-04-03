namespace Pkcs11Wrapper.CryptoApi.Configuration;

public sealed class CryptoApiHostOptions
{
    public const string SectionName = "CryptoApiHost";

    public string ServiceName { get; set; } = CryptoApiHostDefaults.DefaultServiceName;

    public string ApiBasePath { get; set; } = CryptoApiHostDefaults.DefaultApiBasePath;
}
