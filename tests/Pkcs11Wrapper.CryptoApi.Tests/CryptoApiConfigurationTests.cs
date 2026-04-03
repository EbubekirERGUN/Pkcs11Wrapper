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
    public void RuntimeDescriptorProviderReportsStatelessBoundaryAndConfiguredModuleFlag()
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
            TimeProvider.System);

        CryptoApiRuntimeDescriptor descriptor = provider.Describe();

        Assert.Equal("Pkcs11Wrapper.CryptoApi", descriptor.ServiceName);
        Assert.Equal("/api/crypto", descriptor.ApiBasePath);
        Assert.Equal("stateless", descriptor.DeploymentModel);
        Assert.True(descriptor.ModuleConfigured);
        Assert.Contains("GET /api/crypto/runtime", descriptor.CurrentSurface);
        Assert.NotEqual(default, descriptor.StartedAtUtc);
        Assert.False(string.IsNullOrWhiteSpace(descriptor.InstanceId));
    }
}
