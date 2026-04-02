using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.Admin.Infrastructure;
using Pkcs11Wrapper.Admin.Web.Configuration;
using Pkcs11Wrapper.Admin.Web.Health;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class AdminHealthCheckTests
{
    [Fact]
    public async Task StorageHealthCheckReportsHealthyWhenWritableDirectoriesAreAvailable()
    {
        string rootPath = CreateTempDirectory();

        try
        {
            AdminStorageHealthCheck healthCheck = CreateHealthCheck(rootPath);

            HealthCheckResult result = await healthCheck.CheckHealthAsync(new HealthCheckContext());

            Assert.Equal(HealthStatus.Healthy, result.Status);
            Assert.True(Directory.Exists(AdminHostDefaults.GetKeysRoot(rootPath)));
            Assert.True(Directory.Exists(AdminHostDefaults.GetHomeRoot(rootPath)));
            Assert.True(Directory.Exists(AdminHostDefaults.GetTempRoot(rootPath)));
        }
        finally
        {
            Directory.Delete(rootPath, recursive: true);
        }
    }

    [Fact]
    public async Task StorageHealthCheckReportsUnhealthyWhenStorageRootIsAFile()
    {
        string parentPath = CreateTempDirectory();
        string filePath = Path.Combine(parentPath, "not-a-directory");
        await File.WriteAllTextAsync(filePath, "occupied");

        try
        {
            AdminStorageHealthCheck healthCheck = CreateHealthCheck(filePath);

            HealthCheckResult result = await healthCheck.CheckHealthAsync(new HealthCheckContext());

            Assert.Equal(HealthStatus.Unhealthy, result.Status);
        }
        finally
        {
            Directory.Delete(parentPath, recursive: true);
        }
    }

    private static AdminStorageHealthCheck CreateHealthCheck(string dataRoot)
        => new(Options.Create(new AdminStorageOptions { DataRoot = dataRoot }));

    private static string CreateTempDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), "pkcs11wrapper-admin-health-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
