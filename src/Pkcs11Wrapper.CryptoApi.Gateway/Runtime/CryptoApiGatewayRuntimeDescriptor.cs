namespace Pkcs11Wrapper.CryptoApi.Gateway.Runtime;

public sealed record CryptoApiGatewayRuntimeDescriptor(
    string ServiceName,
    string InstanceId,
    string ClusterId,
    string ApiBasePath,
    string DeploymentModel,
    string LoadBalancingPolicy,
    string CorrelationIdHeaderName,
    long? MaxRequestBodySizeBytes,
    bool ActiveHealthChecksEnabled,
    int ConfiguredDestinationCount,
    DateTimeOffset StartedAtUtc,
    IReadOnlyList<string> CurrentSurface,
    IReadOnlyList<string> Notes);
