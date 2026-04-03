namespace Pkcs11Wrapper.CryptoApi.SharedState;

public static class CryptoApiSharedStateConstants
{
    public const int SchemaVersion = 1;

    public static IReadOnlyList<string> SharedReadyAreas { get; } =
    [
        "API clients and client keys",
        "key aliases",
        "policy documents",
        "client-to-policy bindings",
        "alias-to-policy bindings"
    ];
}
