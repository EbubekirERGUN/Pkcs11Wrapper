using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.SharedState;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class AdminCryptoApiAccessRegistrationTests
{
    [Fact]
    public async Task AdminHostRegistersSharedStateServicesWithoutDistributedCacheOverrides()
    {
        string rootPath = CreateTempDirectory();
        await using WebApplicationFactory<Program> factory = CreateFactory(rootPath);

        try
        {
            using IServiceScope scope = factory.Services.CreateScope();
            ICryptoApiSharedStateStore sharedStateStore = scope.ServiceProvider.GetRequiredService<ICryptoApiSharedStateStore>();
            CryptoApiKeyAccessManagementService accessManagement = scope.ServiceProvider.GetRequiredService<CryptoApiKeyAccessManagementService>();

            Assert.NotNull(sharedStateStore);
            Assert.NotNull(accessManagement);
        }
        finally
        {
            DeleteDirectory(rootPath);
        }
    }

    private static WebApplicationFactory<Program> CreateFactory(string rootPath)
        => new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Development");
                builder.ConfigureAppConfiguration((_, configurationBuilder) =>
                {
                    configurationBuilder.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["AdminStorage:DataRoot"] = rootPath,
                        ["AdminRuntime:DisableHttpsRedirection"] = "true",
                        ["CryptoApiSharedPersistence:Provider"] = "Postgres",
                        ["CryptoApiSharedPersistence:ConnectionString"] = string.Empty,
                        ["CryptoApiSharedPersistence:AutoInitialize"] = "true"
                    });
                });
            });

    private static string CreateTempDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), "pkcs11wrapper-admin-cryptoapi-access-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static void DeleteDirectory(string path)
    {
        if (Directory.Exists(path))
        {
            Directory.Delete(path, recursive: true);
        }
    }
}
