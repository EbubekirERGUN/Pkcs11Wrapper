using System.Net;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;
using Pkcs11Wrapper.Admin.Web.Components;
using Pkcs11Wrapper.Admin.Web.Configuration;
using Pkcs11Wrapper.Admin.Web.Security;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed partial class AdminAccessibilityIntegrationTests
{
    private const string BootstrapUserName = "admin";
    private const string BootstrapPassword = "Accessibility!Bootstrap123";

    [Fact]
    public async Task LoginPageIncludesSkipLinkAndAccessibleLoginForm()
    {
        string rootPath = CreateTempDirectory();
        await using WebApplicationFactory<App> factory = CreateFactory(rootPath);

        try
        {
            await SeedAccessibilitySmokeDataAsync(factory);

            using HttpClient client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                HandleCookies = true
            });

            using HttpResponseMessage response = await client.GetAsync("/login");
            string html = await response.Content.ReadAsStringAsync();

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Contains("href=\"#admin-main-content\"", html, StringComparison.Ordinal);
            Assert.Contains("id=\"admin-main-content\"", html, StringComparison.Ordinal);
            Assert.Contains("aria-labelledby=\"admin-section-title\"", html, StringComparison.Ordinal);
            Assert.Contains("aria-label=\"Primary admin navigation\"", html, StringComparison.Ordinal);
            Assert.Contains("aria-label=\"Username\"", html, StringComparison.Ordinal);
            Assert.Contains("aria-label=\"Password\"", html, StringComparison.Ordinal);
            Assert.Contains("aria-live=\"polite\"", html, StringComparison.Ordinal);
        }
        finally
        {
            DeleteDirectory(rootPath);
        }
    }

    [Fact]
    public async Task AuthenticatedAdminPagesRenderAccessibilityBaselineMarkup()
    {
        string rootPath = CreateTempDirectory();
        await using WebApplicationFactory<App> factory = CreateAuthenticatedFactory(rootPath);

        try
        {
            using HttpClient client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                AllowAutoRedirect = false,
                HandleCookies = true
            });

            string devices = await GetHtmlAsync(client, "/devices");
            Assert.Contains("aria-label=\"Device name\"", devices, StringComparison.Ordinal);
            Assert.Contains("aria-label=\"Device status filter\"", devices, StringComparison.Ordinal);

            string users = await GetHtmlAsync(client, "/users");
            Assert.Contains("aria-label=\"Username\"", users, StringComparison.Ordinal);
            Assert.Contains("aria-label=\"Search local users\"", users, StringComparison.Ordinal);
            Assert.Contains("Local admin users with assigned roles, creation time, current-session markers, bootstrap status markers, and management actions.", users, StringComparison.Ordinal);

            string configuration = await GetHtmlAsync(client, "/configuration");
            Assert.Contains("aria-label=\"Configuration import file\"", configuration, StringComparison.Ordinal);
            Assert.Contains("aria-label=\"Configuration import mode\"", configuration, StringComparison.Ordinal);

            string keys = await GetHtmlAsync(client, "/keys");
            Assert.Contains("aria-label=\"Keys device\"", keys, StringComparison.Ordinal);
            Assert.Contains("aria-label=\"Remember PIN in protected local storage\"", keys, StringComparison.Ordinal);

            string sessions = await GetHtmlAsync(client, "/sessions");
            Assert.Contains("aria-label=\"Search tracked sessions\"", sessions, StringComparison.Ordinal);
            Assert.Contains("aria-label=\"Session sort order\"", sessions, StringComparison.Ordinal);

            string telemetry = await GetHtmlAsync(client, "/telemetry");
            Assert.Contains("aria-label=\"Search telemetry entries\"", telemetry, StringComparison.Ordinal);
            Assert.Contains("aria-label=\"Telemetry page size\"", telemetry, StringComparison.Ordinal);

            string audit = await GetHtmlAsync(client, "/audit");
            Assert.Contains("aria-label=\"Search audit logs\"", audit, StringComparison.Ordinal);
            Assert.Contains("Filtered audit log entries including timestamp, actor, roles, category, action, target, outcome, and details.", audit, StringComparison.Ordinal);
            Assert.Matches(RoleWithLiveRegionRegex(), audit);
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
                builder.UseEnvironment(Environments.Development);
                builder.ConfigureAppConfiguration((_, configurationBuilder) =>
                {
                    configurationBuilder.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["AdminStorage:DataRoot"] = rootPath,
                        ["AdminRuntime:DisableHttpsRedirection"] = "true",
                        ["LocalAdminBootstrap:UserName"] = BootstrapUserName,
                        ["LocalAdminBootstrap:Password"] = BootstrapPassword,
                        ["AdminBootstrapDevice:ModulePath"] = "/opt/pkcs11/mock/libpkcs11.so",
                        ["AdminBootstrapDevice:Name"] = "Bootstrap mock device",
                        ["AdminBootstrapDevice:DefaultTokenLabel"] = "bootstrap-token"
                    });
                });
            });

    private static WebApplicationFactory<App> CreateAuthenticatedFactory(string rootPath)
        => CreateFactory(rootPath)
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureTestServices(services =>
                {
                    services.AddAuthentication(options =>
                    {
                        options.DefaultAuthenticateScheme = TestAdminAuthHandler.SchemeName;
                        options.DefaultChallengeScheme = TestAdminAuthHandler.SchemeName;
                        options.DefaultScheme = TestAdminAuthHandler.SchemeName;
                    }).AddScheme<AuthenticationSchemeOptions, TestAdminAuthHandler>(TestAdminAuthHandler.SchemeName, _ => { });

                    services.PostConfigure<AdminBootstrapDeviceOptions>(options =>
                    {
                        options.ModulePath = "/opt/pkcs11/mock/libpkcs11.so";
                        options.Name = "Bootstrap mock device";
                        options.DefaultTokenLabel = "bootstrap-token";
                    });
                });
            });

    private static async Task<string> GetHtmlAsync(HttpClient client, string path)
    {
        using HttpResponseMessage response = await client.GetAsync(path);
        string html = await response.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return html;
    }

    private static async Task SeedAccessibilitySmokeDataAsync(WebApplicationFactory<App> factory)
    {
        using IServiceScope scope = factory.Services.CreateScope();

        LocalAdminUserStore userStore = scope.ServiceProvider.GetRequiredService<LocalAdminUserStore>();
        await userStore.EnsureSeedDataAsync();

        DeviceProfileService deviceProfiles = scope.ServiceProvider.GetRequiredService<DeviceProfileService>();
        if ((await deviceProfiles.GetAllAsync()).Count == 0)
        {
            await deviceProfiles.UpsertAsync(
                id: null,
                new HsmDeviceProfileInput
                {
                    Name = "Accessibility smoke device",
                    ModulePath = "/opt/pkcs11/mock/libpkcs11.so",
                    DefaultTokenLabel = "smoke-token",
                    Notes = "Seeded for accessibility smoke coverage.",
                    IsEnabled = true
                });
        }

        AuditLogService auditLog = scope.ServiceProvider.GetRequiredService<AuditLogService>();
        await auditLog.WriteAsync("AccessibilitySmoke", "Seed", "admin-accessibility", "Success", "Seeded representative admin accessibility smoke data.");
    }

    private static string CreateTempDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), "pkcs11wrapper-admin-accessibility-tests", Guid.NewGuid().ToString("N"));
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

    [GeneratedRegex("role=\"(?:status|alert)\"[^>]*aria-live=\"(?:polite|assertive)\"", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RoleWithLiveRegionRegex();

    private sealed class TestAdminAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
    {
        public const string SchemeName = "TestAdmin";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            Claim[] claims =
            [
                new(ClaimTypes.Name, "accessibility-admin"),
                new(ClaimTypes.Role, AdminRoles.Admin),
                new(ClaimTypes.Role, AdminRoles.Operator),
                new(ClaimTypes.Role, AdminRoles.Viewer)
            ];

            ClaimsIdentity identity = new(claims, SchemeName);
            ClaimsPrincipal principal = new(identity);
            AuthenticationTicket ticket = new(principal, SchemeName);
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
    }
}
