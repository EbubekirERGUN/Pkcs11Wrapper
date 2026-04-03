using Microsoft.Extensions.Options;
using Pkcs11Wrapper.CryptoApi.Configuration;
using Pkcs11Wrapper.CryptoApi.Runtime;

namespace Pkcs11Wrapper.CryptoApi.Tests;

public sealed class CryptoApiConfigurationTests
{
    [Theory]
    [InlineData(null, "/api/v1")]
    [InlineData("", "/api/v1")]
    [InlineData("api/v1", "/api/v1")]
    [InlineData("/api/v1/", "/api/v1")]
    [InlineData(" /internal/crypto/ ", "/internal/crypto")]
    public void NormalizeBasePathReturnsExpectedValue(string? configuredPath, string expected)
    {
        string actual = CryptoApiHostDefaults.NormalizeBasePath(configuredPath);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void RuntimeDescriptorProviderReportsStatelessBoundaryAndSharedPersistenceMetadata()
    {
        CryptoApiRuntimeDescriptorProvider provider = new(
            Options.Create(new CryptoApiHostOptions
            {
                ServiceName = "Pkcs11Wrapper.CryptoApi",
                ApiBasePath = "api/crypto"
            }),
            Options.Create(new CryptoApiRuntimeOptions
            {
                ModulePath = "/opt/pkcs11/lib/libvendorpkcs11.so"
            }),
            Options.Create(new CryptoApiSharedPersistenceOptions
            {
                Provider = "Sqlite",
                ConnectionString = "Data Source=/tmp/pkcs11wrapper-cryptoapi-shared.db"
            }),
            TimeProvider.System);

        CryptoApiRuntimeDescriptor descriptor = provider.Describe();

        Assert.Equal("Pkcs11Wrapper.CryptoApi", descriptor.ServiceName);
        Assert.Equal("/api/crypto", descriptor.ApiBasePath);
        Assert.Equal("stateless", descriptor.DeploymentModel);
        Assert.True(descriptor.ModuleConfigured);
        Assert.True(descriptor.SharedPersistenceConfigured);
        Assert.Equal("Sqlite", descriptor.SharedPersistenceProvider);
        Assert.Contains("API clients and client keys", descriptor.SharedReadyAreas);
        Assert.Contains("API key hashing, rotation, and revocation metadata", descriptor.SharedReadyAreas);
        Assert.Contains("GET /api/crypto/shared-state", descriptor.CurrentSurface);
        Assert.Contains("GET /api/crypto/auth/self", descriptor.CurrentSurface);
        Assert.Contains("POST /api/crypto/operations/authorize", descriptor.CurrentSurface);
        Assert.Contains("POST /api/crypto/operations/sign", descriptor.CurrentSurface);
        Assert.Contains("POST /api/crypto/operations/verify", descriptor.CurrentSurface);
        Assert.Contains("POST /api/crypto/operations/random", descriptor.CurrentSurface);
        Assert.NotEqual(default, descriptor.StartedAtUtc);
        Assert.False(string.IsNullOrWhiteSpace(descriptor.InstanceId));
    }
}
