namespace Pkcs11Wrapper.Admin.Web.Configuration;

public static class AdminHostDefaults
{
    public const string ContainerDataRoot = "/var/lib/pkcs11wrapper-admin";
    public const string ContainerModuleMountRoot = "/opt/pkcs11/lib";
    public const string KeysDirectoryName = "keys";
    public const string HomeDirectoryName = "home";
    public const string TempDirectoryName = "tmp";
    public const string HealthLivePath = "/health/live";
    public const string HealthReadyPath = "/health/ready";
    public const string DefaultContainerHealthCheckUrl = "http://127.0.0.1:8080/health/ready";

    public static string ResolveStorageRoot(string? configuredDataRoot, string contentRootPath)
    {
        if (!string.IsNullOrWhiteSpace(configuredDataRoot))
        {
            return configuredDataRoot.Trim();
        }

        return IsRunningInContainer()
            ? ContainerDataRoot
            : Path.Combine(contentRootPath, "App_Data");
    }

    public static bool IsRunningInContainer()
    {
        string? value = Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER");
        if (string.Equals(value, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(value, "1", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return File.Exists("/.dockerenv");
    }

    public static string GetKeysRoot(string dataRoot)
        => Path.Combine(dataRoot, KeysDirectoryName);

    public static string GetHomeRoot(string dataRoot)
        => Path.Combine(dataRoot, HomeDirectoryName);

    public static string GetTempRoot(string dataRoot)
        => Path.Combine(dataRoot, TempDirectoryName);
}
