namespace Pkcs11Wrapper.CryptoApi.SharedState;

public static class CryptoApiSharedStateConstants
{
    public const int SchemaVersion = 3;

    public static IReadOnlyList<string> SharedReadyAreas { get; } =
    [
        "API clients and client keys",
        "API key hashing, rotation, and revocation metadata",
        "key aliases",
        "policy documents",
        "client-to-policy bindings",
        "alias-to-policy bindings"
    ];
}
