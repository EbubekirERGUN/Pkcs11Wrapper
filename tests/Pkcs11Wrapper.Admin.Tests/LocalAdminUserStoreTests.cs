using Microsoft.Extensions.Options;
using Pkcs11Wrapper.Admin.Infrastructure;
using Pkcs11Wrapper.Admin.Web.Configuration;
using Pkcs11Wrapper.Admin.Web.Security;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class LocalAdminUserStoreTests
{
    [Fact]
    public async Task EnsureSeedDataAsyncUsesConfiguredBootstrapCredentials()
    {
        string rootPath = Path.Combine(Path.GetTempPath(), "pkcs11wrapper-admin-user-store-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(rootPath);

        try
        {
            LocalAdminUserStore store = new(
                Options.Create(new AdminStorageOptions { DataRoot = rootPath }),
                Options.Create(new LocalAdminBootstrapOptions
                {
                    UserName = "ci-admin",
                    Password = "AdminE2E!Pass123"
                }));

            await store.EnsureSeedDataAsync();

            (bool success, var user) = await store.ValidateCredentialsAsync("ci-admin", "AdminE2E!Pass123");
            BootstrapCredentialStatus bootstrap = await store.GetBootstrapStatusAsync();
            string bootstrapFile = await File.ReadAllTextAsync(Path.Combine(rootPath, "bootstrap-admin.txt"));

            Assert.True(success);
            Assert.NotNull(user);
            Assert.Equal("ci-admin", user.UserName);
            Assert.True(bootstrap.NoticeExists);
            Assert.Equal("ci-admin", bootstrap.UserName);
            Assert.Contains("username: ci-admin", bootstrapFile, StringComparison.Ordinal);
            Assert.Contains("password: AdminE2E!Pass123", bootstrapFile, StringComparison.Ordinal);
        }
        finally
        {
            if (Directory.Exists(rootPath))
            {
                Directory.Delete(rootPath, recursive: true);
            }
        }
    }
}
