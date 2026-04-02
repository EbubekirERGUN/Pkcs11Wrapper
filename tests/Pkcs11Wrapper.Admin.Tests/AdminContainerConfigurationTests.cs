using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;
using Pkcs11Wrapper.Admin.Infrastructure;
using Pkcs11Wrapper.Admin.Web.Configuration;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class AdminContainerConfigurationTests
{
    [Fact]
    public void ResolveStorageRootPrefersConfiguredPath()
    {
        string resolved = AdminHostDefaults.ResolveStorageRoot("/tmp/custom-admin-root", "/workspace/src/Pkcs11Wrapper.Admin.Web");

        Assert.Equal("/tmp/custom-admin-root", resolved);
    }

    [Fact]
    public void ResolveStorageRootUsesContainerDefaultWhenRunningInContainer()
    {
        string? previous = Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER");
        Environment.SetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER", "true");

        try
        {
            string resolved = AdminHostDefaults.ResolveStorageRoot(null, "/workspace/src/Pkcs11Wrapper.Admin.Web");
            Assert.Equal(AdminHostDefaults.ContainerDataRoot, resolved);
        }
        finally
        {
            Environment.SetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER", previous);
        }
    }

    [Fact]
    public async Task BootstrapDeviceSeederSeedsConfiguredModuleWhenStoreIsEmpty()
    {
        string rootPath = CreateTempDirectory();

        try
        {
            JsonDeviceProfileStore store = new(new AdminStorageOptions { DataRoot = rootPath });
            DeviceProfileService deviceProfiles = new(store);
            AdminBootstrapDeviceSeeder seeder = new(
                Options.Create(new AdminBootstrapDeviceOptions
                {
                    Name = "Container SoftHSM",
                    ModulePath = "/opt/pkcs11/lib/libsofthsm2.so",
                    DefaultTokenLabel = "ci-token",
                    Notes = "Seeded from env",
                    VendorId = "softhsm",
                    VendorName = "SoftHSM",
                    VendorProfileId = "softHsm-demo",
                    VendorProfileName = "SoftHSM demo",
                    IsEnabled = true
                }),
                deviceProfiles,
                NullLogger<AdminBootstrapDeviceSeeder>.Instance);

            await seeder.EnsureSeedDataAsync();

            IReadOnlyList<HsmDeviceProfile> profiles = await store.GetAllAsync();
            HsmDeviceProfile profile = Assert.Single(profiles);
            Assert.Equal("Container SoftHSM", profile.Name);
            Assert.Equal("/opt/pkcs11/lib/libsofthsm2.so", profile.ModulePath);
            Assert.Equal("ci-token", profile.DefaultTokenLabel);
            Assert.Equal("SoftHSM", profile.Vendor?.VendorName);
            Assert.Equal("softhsm-demo", profile.Vendor?.ProfileId);
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task BootstrapDeviceSeederDoesNotOverrideExistingProfiles()
    {
        string rootPath = CreateTempDirectory();

        try
        {
            JsonDeviceProfileStore store = new(new AdminStorageOptions { DataRoot = rootPath });
            DeviceProfileService deviceProfiles = new(store);
            await store.SaveAllAsync([
                new HsmDeviceProfile(
                    Guid.NewGuid(),
                    "Persisted device",
                    "/persisted/libpkcs11.so",
                    "persisted-token",
                    null,
                    true,
                    DateTimeOffset.UtcNow,
                    DateTimeOffset.UtcNow)
            ]);

            AdminBootstrapDeviceSeeder seeder = new(
                Options.Create(new AdminBootstrapDeviceOptions
                {
                    Name = "Container SoftHSM",
                    ModulePath = "/opt/pkcs11/lib/libsofthsm2.so"
                }),
                deviceProfiles,
                NullLogger<AdminBootstrapDeviceSeeder>.Instance);

            await seeder.EnsureSeedDataAsync();

            IReadOnlyList<HsmDeviceProfile> profiles = await store.GetAllAsync();
            HsmDeviceProfile profile = Assert.Single(profiles);
            Assert.Equal("Persisted device", profile.Name);
            Assert.Equal("/persisted/libpkcs11.so", profile.ModulePath);
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }

    private static string CreateTempDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), "pkcs11wrapper-admin-container-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
