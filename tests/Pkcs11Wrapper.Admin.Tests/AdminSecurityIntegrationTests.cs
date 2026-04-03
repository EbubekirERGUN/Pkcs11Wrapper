using System.Net;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Pkcs11Wrapper.Admin.Web.Components;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class AdminSecurityIntegrationTests
{
    [Fact]
    public async Task LoginPageIncludesResponseHardeningHeaders()
    {
        string rootPath = CreateTempDirectory();
        await using WebApplicationFactory<App> factory = CreateFactory(rootPath);

        try
        {
            using HttpClient client = factory.CreateClient();
            using HttpResponseMessage response = await client.GetAsync("/login");

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("DENY", GetSingleHeaderValue(response.Headers, "X-Frame-Options"));
            Assert.Equal("nosniff", GetSingleHeaderValue(response.Headers, "X-Content-Type-Options"));
            Assert.Equal("no-referrer", GetSingleHeaderValue(response.Headers, "Referrer-Policy"));
            Assert.Equal("no-store, max-age=0", GetSingleHeaderValue(response.Headers, "Cache-Control"));
        }
        finally
        {
            DeleteDirectory(rootPath);
        }
    }

    [Fact]
    public async Task LoginRejectsPostWithoutAntiforgeryToken()
    {
        string rootPath = CreateTempDirectory();
        await using WebApplicationFactory<App> factory = CreateFactory(rootPath);

        try
        {
            using HttpClient client = factory.CreateClient();
            using FormUrlEncodedContent content = new([
                new KeyValuePair<string, string>("username", "admin"),
                new KeyValuePair<string, string>("password", "wrong-password"),
                new KeyValuePair<string, string>("returnUrl", "/")
            ]);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

            using HttpResponseMessage response = await client.PostAsync("/account/login", content);
            string body = await response.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Contains("missing a valid antiforgery token", body, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            DeleteDirectory(rootPath);
        }
    }

    private static WebApplicationFactory<App> CreateFactory(string rootPath)
        => new WebApplicationFactory<App>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Development");
                builder.ConfigureAppConfiguration((_, configurationBuilder) =>
                {
                    configurationBuilder.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["AdminStorage:DataRoot"] = rootPath,
                        ["AdminRuntime:DisableHttpsRedirection"] = "true"
                    });
                });
            });

    private static string GetSingleHeaderValue(HttpResponseHeaders headers, string name)
        => Assert.Single(headers.GetValues(name));

    private static string CreateTempDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), "pkcs11wrapper-admin-security-tests", Guid.NewGuid().ToString("N"));
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
