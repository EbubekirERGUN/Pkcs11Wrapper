using System.Globalization;

namespace Pkcs11Wrapper.CryptoApiPerf;

internal sealed record CryptoApiPerfOptions(
    string ProfileName,
    TimeSpan WarmUpDuration,
    TimeSpan BombingDuration,
    int SingleInstanceCopies,
    int MultiInstanceCopies,
    string SharedPersistenceConnectionString,
    string SingleBaseUrl,
    string MultiBaseUrl,
    string ModulePath,
    string TokenLabel,
    string UserPin,
    string SignObjectLabel,
    string SignObjectIdHex,
    string ResultsRoot,
    string? CanonicalMarkdownPath,
    string? CanonicalJsonPath)
{
    public static CryptoApiPerfOptions Parse(string[] args)
    {
        Dictionary<string, string> values = ParseArguments(args);

        string profileName = GetOptional(values, "profile") ?? "baseline";
        PerfProfile profile = PerfProfile.Resolve(profileName);

        return new CryptoApiPerfOptions(
            ProfileName: profile.Name,
            WarmUpDuration: profile.WarmUpDuration,
            BombingDuration: profile.BombingDuration,
            SingleInstanceCopies: profile.SingleInstanceCopies,
            MultiInstanceCopies: profile.MultiInstanceCopies,
            SharedPersistenceConnectionString: GetRequired(values, "shared-connection-string", "PKCS11_CRYPTO_API_PERF_SHARED_CONNECTION_STRING"),
            SingleBaseUrl: NormalizeBaseUrl(GetRequired(values, "single-base-url", "PKCS11_CRYPTO_API_PERF_SINGLE_BASE_URL")),
            MultiBaseUrl: NormalizeBaseUrl(GetRequired(values, "multi-base-url", "PKCS11_CRYPTO_API_PERF_MULTI_BASE_URL")),
            ModulePath: GetRequired(values, "module-path", "PKCS11_MODULE_PATH"),
            TokenLabel: GetRequired(values, "token-label", "PKCS11_TOKEN_LABEL"),
            UserPin: GetRequired(values, "user-pin", "PKCS11_USER_PIN"),
            SignObjectLabel: GetRequired(values, "sign-object-label", "PKCS11_SIGN_FIND_LABEL"),
            SignObjectIdHex: NormalizeHex(GetRequired(values, "sign-object-id-hex", "PKCS11_SIGN_FIND_ID_HEX")),
            ResultsRoot: GetOptional(values, "results-root")
                ?? Environment.GetEnvironmentVariable("PKCS11_CRYPTO_API_PERF_RESULTS_ROOT")
                ?? Path.Combine(ResolveRepoRoot(), "artifacts", "crypto-api-perf", "latest"),
            CanonicalMarkdownPath: GetOptional(values, "canonical-markdown") ?? Environment.GetEnvironmentVariable("PKCS11_CRYPTO_API_PERF_CANONICAL_MARKDOWN_PATH"),
            CanonicalJsonPath: GetOptional(values, "canonical-json") ?? Environment.GetEnvironmentVariable("PKCS11_CRYPTO_API_PERF_CANONICAL_JSON_PATH"));
    }

    private static Dictionary<string, string> ParseArguments(string[] args)
    {
        Dictionary<string, string> values = new(StringComparer.OrdinalIgnoreCase);

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];
            if (!arg.StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Unexpected argument '{arg}'. Expected --name value pairs.");
            }

            string key = arg[2..];
            if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Argument '{arg}' requires a value.");
            }

            values[key] = args[++i];
        }

        return values;
    }

    private static string GetRequired(IReadOnlyDictionary<string, string> values, string argumentName, string environmentName)
        => GetOptional(values, argumentName)
            ?? Environment.GetEnvironmentVariable(environmentName)
            ?? throw new InvalidOperationException($"Missing required value --{argumentName} or environment variable {environmentName}.");

    private static string? GetOptional(IReadOnlyDictionary<string, string> values, string argumentName)
        => values.TryGetValue(argumentName, out string? value) && !string.IsNullOrWhiteSpace(value)
            ? value.Trim()
            : null;

    private static string NormalizeBaseUrl(string value)
        => value.TrimEnd('/');

    private static string NormalizeHex(string value)
    {
        char[] filtered = value.Trim()
            .Where(static c => !char.IsWhiteSpace(c) && c is not '-' and not ':')
            .ToArray();

        if (filtered.Length == 0 || filtered.Length % 2 != 0)
        {
            throw new InvalidOperationException("Sign object id hex must contain an even number of hexadecimal characters.");
        }

        foreach (char c in filtered)
        {
            if (!Uri.IsHexDigit(c))
            {
                throw new InvalidOperationException("Sign object id hex must contain only hexadecimal characters.");
            }
        }

        return new string(filtered).ToUpperInvariant();
    }

    private static string ResolveRepoRoot()
    {
        string? fromEnvironment = Environment.GetEnvironmentVariable("PKCS11_CRYPTO_API_PERF_REPO_ROOT");
        if (!string.IsNullOrWhiteSpace(fromEnvironment))
        {
            return fromEnvironment;
        }

        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Pkcs11Wrapper.sln")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Unable to resolve the repository root for Crypto API performance output.");
    }

    private sealed record PerfProfile(
        string Name,
        TimeSpan WarmUpDuration,
        TimeSpan BombingDuration,
        int SingleInstanceCopies,
        int MultiInstanceCopies)
    {
        public static PerfProfile Resolve(string profileName)
            => profileName.Trim().ToLowerInvariant() switch
            {
                "quick" => new PerfProfile("quick", TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(10), 4, 8),
                "ci" => new PerfProfile("ci", TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(15), 4, 8),
                "baseline" => new PerfProfile("baseline", TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(30), 8, 16),
                _ => throw new ArgumentException(string.Create(CultureInfo.InvariantCulture, $"Unsupported profile '{profileName}'. Supported values: quick, ci, baseline."))
            };
    }
}
