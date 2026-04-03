namespace Pkcs11Wrapper.CryptoApi.Runtime;

public sealed record CryptoApiRuntimeDescriptor(
    string ServiceName,
    string InstanceId,
    string ApiBasePath,
    string DeploymentModel,
    DateTimeOffset StartedAtUtc,
    bool ModuleConfigured,
    IReadOnlyList<string> CurrentSurface);
