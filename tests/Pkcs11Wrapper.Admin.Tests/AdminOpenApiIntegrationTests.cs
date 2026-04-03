using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Pkcs11Wrapper.Admin.Web.OpenApi;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class AdminOpenApiIntegrationTests
{
    [Fact]
    public async Task DevelopmentOpenApiDocumentDescribesOnlyMappedAdminHttpEndpoints()
    {
        string rootPath = CreateTempDirectory();
        await using WebApplicationFactory<Program> factory = CreateFactory(rootPath, "Development");

        try
        {
            using HttpClient client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false
            });
            using HttpResponseMessage response = await client.GetAsync(AdminOpenApiExtensions.DefaultDocumentPath);

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            await using Stream payload = await response.Content.ReadAsStreamAsync();
            using JsonDocument document = await JsonDocument.ParseAsync(payload);
            JsonElement paths = document.RootElement.GetProperty("paths");

            string[] expectedPaths =
            [
                "/account/login",
                "/account/logout",
                "/configuration/export",
                "/health/live",
                "/health/ready",
                "/telemetry/export"
            ];

            string[] actualPaths = paths.EnumerateObject().Select(static path => path.Name).OrderBy(static path => path, StringComparer.Ordinal).ToArray();
            Assert.Equal(expectedPaths.OrderBy(static path => path, StringComparer.Ordinal), actualPaths);

            JsonElement loginOperation = paths.GetProperty("/account/login").GetProperty("post");
            Assert.True(loginOperation.GetProperty("requestBody").GetProperty("content").TryGetProperty("application/x-www-form-urlencoded", out _));
            Assert.True(loginOperation.GetProperty("responses").TryGetProperty("302", out _));
            Assert.True(loginOperation.GetProperty("responses").TryGetProperty("400", out _));

            JsonElement configurationExport = paths.GetProperty("/configuration/export").GetProperty("get");
            Assert.Contains("authenticated admin cookie session", configurationExport.GetProperty("description").GetString(), StringComparison.OrdinalIgnoreCase);
            Assert.True(configurationExport.GetProperty("responses").TryGetProperty("200", out _));
            Assert.True(configurationExport.GetProperty("responses").TryGetProperty("302", out _));
        }
        finally
        {
            DeleteDirectory(rootPath);
        }
    }

    [Fact]
    public async Task DevelopmentSwaggerUiIsAvailable()
    {
        string rootPath = CreateTempDirectory();
        await using WebApplicationFactory<Program> factory = CreateFactory(rootPath, "Development");

        try
        {
            using HttpClient client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false
            });
            using HttpResponseMessage response = await client.GetAsync($"{AdminOpenApiExtensions.DefaultSwaggerPath}/index.html");
            string body = await response.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
            Assert.Contains("HTML for static distribution bundle", body, StringComparison.Ordinal);
        }
        finally
        {
            DeleteDirectory(rootPath);
        }
    }

    [Fact]
    public async Task ProductionDoesNotExposeOpenApiOrSwaggerUi()
    {
        string rootPath = CreateTempDirectory();
        await using WebApplicationFactory<Program> factory = CreateFactory(rootPath, Environments.Production);

        try
        {
            using HttpClient client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false
            });

            using HttpResponseMessage openApiResponse = await client.GetAsync(AdminOpenApiExtensions.DefaultDocumentPath);
            using HttpResponseMessage swaggerResponse = await client.GetAsync($"{AdminOpenApiExtensions.DefaultSwaggerPath}/index.html");

            Assert.Equal(HttpStatusCode.NotFound, openApiResponse.StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, swaggerResponse.StatusCode);
        }
        finally
        {
            DeleteDirectory(rootPath);
        }
    }

    private static WebApplicationFactory<Program> CreateFactory(string rootPath, string environmentName)
        => new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment(environmentName);
                builder.ConfigureAppConfiguration((_, configurationBuilder) =>
                {
                    configurationBuilder.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["AdminStorage:DataRoot"] = rootPath,
                        ["AdminRuntime:DisableHttpsRedirection"] = "true"
                    });
                });
            });

    private static string CreateTempDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), "pkcs11wrapper-admin-openapi-tests", Guid.NewGuid().ToString("N"));
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
