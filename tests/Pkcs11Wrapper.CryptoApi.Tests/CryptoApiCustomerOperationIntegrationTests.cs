using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Pkcs11Wrapper;
using Pkcs11Wrapper.CryptoApi.Access;
using Pkcs11Wrapper.CryptoApi.Clients;

namespace Pkcs11Wrapper.CryptoApi.Tests;

[Collection(CryptoApiSoftHsmCollection.Name)]
public sealed class CryptoApiCustomerOperationIntegrationTests
{
    [Fact]
    public async Task SignVerifyAndRandomEndpointsExecuteAgainstSoftHsm()
    {
        if (!SoftHsmTestContext.IsSupported())
        {
            return;
        }

        await using SoftHsmTestContext context = await SoftHsmTestContext.CreateAsync();
        if (!context.CanExecuteInProcess)
        {
            return;
        }

        await using WebApplicationFactory<Program> factory = CreateFactory(context);

        SeededAccess access = await SeedAuthorizedAccessAsync(factory, context);

        HttpClient httpClient = factory.CreateClient();
        httpClient.DefaultRequestHeaders.Add("X-Api-Key-Id", access.Key.KeyIdentifier);
        httpClient.DefaultRequestHeaders.Add("X-Api-Key-Secret", access.Key.Secret);

        byte[] payload = Encoding.UTF8.GetBytes("customer-facing crypto api");
        string payloadBase64 = Convert.ToBase64String(payload);

        using HttpResponseMessage signResponse = await httpClient.PostAsync(
            "/api/v1/operations/sign",
            CreateJsonContent($"{{\"keyAlias\":\"{context.AliasName}\",\"algorithm\":\"RS256\",\"payloadBase64\":\"{payloadBase64}\"}}"));

        string signContent = await signResponse.Content.ReadAsStringAsync();
        Assert.True(signResponse.StatusCode == HttpStatusCode.OK, signContent);
        using JsonDocument signJson = JsonDocument.Parse(signContent);
        string? signatureBase64 = signJson.RootElement.GetProperty("signatureBase64").GetString();
        Assert.False(string.IsNullOrWhiteSpace(signatureBase64));
        byte[] signature = Convert.FromBase64String(signatureBase64!);
        Assert.NotEmpty(signature);

        using HttpResponseMessage verifyResponse = await httpClient.PostAsync(
            "/api/v1/operations/verify",
            CreateJsonContent($"{{\"keyAlias\":\"{context.AliasName}\",\"algorithm\":\"RS256\",\"payloadBase64\":\"{payloadBase64}\",\"signatureBase64\":\"{signatureBase64}\"}}"));

        Assert.Equal(HttpStatusCode.OK, verifyResponse.StatusCode);
        using JsonDocument verifyJson = JsonDocument.Parse(await verifyResponse.Content.ReadAsStringAsync());
        Assert.True(verifyJson.RootElement.GetProperty("verified").GetBoolean());
        Assert.Equal("RS256", verifyJson.RootElement.GetProperty("algorithm").GetString());

        using HttpResponseMessage randomResponse = await httpClient.PostAsync(
            "/api/v1/operations/random",
            CreateJsonContent($"{{\"keyAlias\":\"{context.AliasName}\",\"length\":32}}"));

        Assert.Equal(HttpStatusCode.OK, randomResponse.StatusCode);
        using JsonDocument randomJson = JsonDocument.Parse(await randomResponse.Content.ReadAsStringAsync());
        byte[] random = Convert.FromBase64String(randomJson.RootElement.GetProperty("randomBase64").GetString()!);
        Assert.Equal(32, random.Length);
        Assert.Contains(random, static value => value != 0);
    }

    private static async Task<SeededAccess> SeedAuthorizedAccessAsync(WebApplicationFactory<Program> factory, SoftHsmTestContext context)
    {
        using IServiceScope scope = factory.Services.CreateScope();
        CryptoApiClientManagementService clientManagement = scope.ServiceProvider.GetRequiredService<CryptoApiClientManagementService>();
        CryptoApiKeyAccessManagementService accessManagement = scope.ServiceProvider.GetRequiredService<CryptoApiKeyAccessManagementService>();

        CryptoApiManagedClient client = await clientManagement.CreateClientAsync(new CreateCryptoApiClientRequest(
            ClientName: $"integration-{Guid.NewGuid():N}",
            DisplayName: "Integration Client",
            ApplicationType: "gateway",
            Notes: null));
        CryptoApiCreatedClientKey key = await clientManagement.CreateClientKeyAsync(new CreateCryptoApiClientKeyRequest(client.ClientId, "primary", null));
        CryptoApiManagedPolicy policy = await accessManagement.CreatePolicyAsync(new CreateCryptoApiPolicyRequest(
            PolicyName: "softHsm-sign-verify-random",
            Description: null,
            AllowedOperations: ["sign", "verify", "random"]));
        CryptoApiManagedKeyAlias alias = await accessManagement.CreateKeyAliasAsync(new CreateCryptoApiKeyAliasRequest(
            AliasName: context.AliasName,
            DeviceRoute: "softhsm-test",
            SlotId: (ulong)context.SlotId.Value,
            ObjectLabel: context.ObjectLabel,
            ObjectIdHex: context.ObjectIdHex,
            Notes: null));
        await accessManagement.ReplaceClientPoliciesAsync(client.ClientId, [policy.PolicyId]);
        await accessManagement.ReplaceKeyAliasPoliciesAsync(alias.AliasId, [policy.PolicyId]);
        return new SeededAccess(client, key, alias, policy);
    }

    private static WebApplicationFactory<Program> CreateFactory(SoftHsmTestContext context)
        => new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.UseEnvironment("Development");
                builder.ConfigureAppConfiguration((_, configurationBuilder) =>
                {
                    configurationBuilder.AddInMemoryCollection(new Dictionary<string, string?>
                    {
                        ["CryptoApiHost:ServiceName"] = "Pkcs11Wrapper.CryptoApi.IntegrationTests",
                        ["CryptoApiHost:ApiBasePath"] = "/api/v1",
                        ["CryptoApiRuntime:DisableHttpsRedirection"] = "true",
                        ["CryptoApiRuntime:ModulePath"] = context.ModulePath,
                        ["CryptoApiRuntime:UserPin"] = context.UserPin,
                        ["CryptoApiSharedPersistence:Provider"] = "Sqlite",
                        ["CryptoApiSharedPersistence:ConnectionString"] = $"Data Source={context.DatabasePath}",
                        ["CryptoApiSharedPersistence:AutoInitialize"] = "true"
                    });
                });
            });

    private static StringContent CreateJsonContent(string json)
        => new(json, Encoding.UTF8, "application/json");

    private sealed record SeededAccess(
        CryptoApiManagedClient Client,
        CryptoApiCreatedClientKey Key,
        CryptoApiManagedKeyAlias Alias,
        CryptoApiManagedPolicy Policy);

    private sealed class SoftHsmTestContext : IAsyncDisposable
    {
        private const string SoftHsmConfEnvironmentVariable = "SOFTHSM2_CONF";

        private SoftHsmTestContext(
            string rootPath,
            string modulePath,
            string? previousConfigPath,
            string tokenLabel,
            string soPin,
            string userPin,
            Pkcs11SlotId slotId,
            bool canExecuteInProcess,
            string aliasName,
            string objectLabel,
            string objectIdHex,
            string databasePath)
        {
            RootPath = rootPath;
            ModulePath = modulePath;
            PreviousConfigPath = previousConfigPath;
            TokenLabel = tokenLabel;
            SoPin = soPin;
            UserPin = userPin;
            SlotId = slotId;
            CanExecuteInProcess = canExecuteInProcess;
            AliasName = aliasName;
            ObjectLabel = objectLabel;
            ObjectIdHex = objectIdHex;
            DatabasePath = databasePath;
        }

        public string RootPath { get; }

        public string ModulePath { get; }

        public string? PreviousConfigPath { get; }

        public string TokenLabel { get; }

        public string SoPin { get; }

        public string UserPin { get; }

        public Pkcs11SlotId SlotId { get; }

        public bool CanExecuteInProcess { get; }

        public string AliasName { get; }

        public string ObjectLabel { get; }

        public string ObjectIdHex { get; }

        public string DatabasePath { get; }

        public static bool IsSupported()
            => FindModulePath() is not null && CommandExists("softhsm2-util");

        public static async Task<SoftHsmTestContext> CreateAsync()
        {
            string modulePath = FindModulePath() ?? throw new InvalidOperationException("SoftHSM module path could not be resolved.");
            string rootPath = Path.Combine(Path.GetTempPath(), $"pkcs11wrapper-cryptoapi-softhsm-{Guid.NewGuid():N}");
            string tokenDirectory = Path.Combine(rootPath, "tokens");
            Directory.CreateDirectory(tokenDirectory);

            string configPath = Path.Combine(rootPath, "softhsm2.conf");
            await File.WriteAllTextAsync(configPath, $"directories.tokendir = {tokenDirectory}{Environment.NewLine}objectstore.backend = file{Environment.NewLine}log.level = ERROR{Environment.NewLine}");

            string? previousConfigPath = Environment.GetEnvironmentVariable(SoftHsmConfEnvironmentVariable);
            Environment.SetEnvironmentVariable(SoftHsmConfEnvironmentVariable, configPath);

            string tokenLabel = $"crypto-api-{Guid.NewGuid():N}"[..24];
            string soPin = "12345678";
            string userPin = "98765432";
            string objectLabel = "payments-key";
            string objectIdHex = "A1B2C3D4";

            _ = await RunProcessAsync(
                "softhsm2-util",
                ["--init-token", "--free", "--label", tokenLabel, "--so-pin", soPin, "--pin", userPin],
                configPath);

            _ = await RunProcessAsync(
                "pkcs11-tool",
                [
                    "--module", modulePath,
                    "--token-label", tokenLabel,
                    "--login",
                    "--pin", userPin,
                    "--keypairgen",
                    "--key-type", "rsa:2048",
                    "--usage-sign",
                    "--id", objectIdHex,
                    "--label", objectLabel
                ],
                configPath);

            bool canExecuteInProcess = TryResolveSlotIdFromModule(modulePath, tokenLabel, out Pkcs11SlotId slotId);
            string databasePath = Path.Combine(rootPath, "crypto-api.db");
            return new SoftHsmTestContext(rootPath, modulePath, previousConfigPath, tokenLabel, soPin, userPin, slotId, canExecuteInProcess, "payments-signer", objectLabel, objectIdHex, databasePath);
        }

        public ValueTask DisposeAsync()
        {
            Environment.SetEnvironmentVariable(SoftHsmConfEnvironmentVariable, PreviousConfigPath);

            try
            {
                DeleteDatabaseArtifacts(DatabasePath);
            }
            catch
            {
            }

            try
            {
                if (Directory.Exists(RootPath))
                {
                    Directory.Delete(RootPath, recursive: true);
                }
            }
            catch
            {
            }

            return ValueTask.CompletedTask;
        }

        private static bool TryResolveSlotIdFromModule(string modulePath, string tokenLabel, out Pkcs11SlotId slotId)
        {
            using Pkcs11Module module = Pkcs11Module.Load(modulePath);
            module.Initialize();

            int slotCount = module.GetSlotCount(tokenPresentOnly: false);
            Pkcs11SlotId[] slots = new Pkcs11SlotId[slotCount];
            module.TryGetSlots(slots, out int written, tokenPresentOnly: false);

            for (int i = 0; i < written; i++)
            {
                if (module.TryGetTokenInfo(slots[i], out Pkcs11TokenInfo tokenInfo)
                    && string.Equals(tokenInfo.Label.Trim(), tokenLabel, StringComparison.Ordinal))
                {
                    slotId = slots[i];
                    return true;
                }
            }

            slotId = default;
            return false;
        }

        private static string? FindModulePath()
        {
            string? configured = Pkcs11ModulePathDefaults.GetDefaultSoftHsmModulePath();
            string[] candidates =
            [
                configured ?? string.Empty,
                "/usr/lib/libsofthsm2.so",
                "/usr/lib/pkcs11/libsofthsm2.so",
                "/usr/lib/softhsm/libsofthsm2.so"
            ];

            return candidates
                .Where(candidate => !string.IsNullOrWhiteSpace(candidate))
                .FirstOrDefault(File.Exists);
        }

        private static bool CommandExists(string commandName)
        {
            string? path = Environment.GetEnvironmentVariable("PATH");
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            foreach (string directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                string candidate = Path.Combine(directory, commandName);
                if (File.Exists(candidate))
                {
                    return true;
                }
            }

            return false;
        }

        private static async Task<ProcessResult> RunProcessAsync(string fileName, IReadOnlyList<string> arguments, string configPath)
        {
            ProcessStartInfo startInfo = new(fileName)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };

            foreach (string argument in arguments)
            {
                startInfo.ArgumentList.Add(argument);
            }

            startInfo.Environment[SoftHsmConfEnvironmentVariable] = configPath;

            using Process process = Process.Start(startInfo) ?? throw new InvalidOperationException($"Could not start '{fileName}'.");
            string stdout = await process.StandardOutput.ReadToEndAsync();
            string stderr = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException($"Command '{fileName} {string.Join(' ', arguments)}' failed with exit code {process.ExitCode}.{Environment.NewLine}STDOUT:{Environment.NewLine}{stdout}{Environment.NewLine}STDERR:{Environment.NewLine}{stderr}");
            }

            return new ProcessResult(stdout, stderr);
        }

        private static void DeleteDatabaseArtifacts(string databasePath)
        {
            string walPath = databasePath + "-wal";
            string shmPath = databasePath + "-shm";

            if (File.Exists(databasePath)) File.Delete(databasePath);
            if (File.Exists(walPath)) File.Delete(walPath);
            if (File.Exists(shmPath)) File.Delete(shmPath);
        }

        private sealed record ProcessResult(string StandardOutput, string StandardError);
    }
}
