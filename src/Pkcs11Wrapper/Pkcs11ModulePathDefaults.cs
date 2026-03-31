namespace Pkcs11Wrapper;

public static class Pkcs11ModulePathDefaults
{
    public static IReadOnlyList<string> GetSoftHsmModuleCandidates()
        => GetSoftHsmModuleCandidates(GetCurrentPlatform());

    public static string? GetDefaultSoftHsmModulePath()
    {
        string[] candidates = GetSoftHsmModuleCandidates(GetCurrentPlatform());
        return candidates.Length == 0 ? null : candidates[0];
    }

    internal static string[] GetSoftHsmModuleCandidates(Pkcs11KnownPlatform platform)
        => platform switch
        {
            Pkcs11KnownPlatform.Windows => ["softhsm2-x64.dll", "softhsm2.dll"],
            Pkcs11KnownPlatform.Linux => ["libsofthsm2.so"],
            Pkcs11KnownPlatform.MacOS => ["libsofthsm2.dylib", "softhsm2.dylib"],
            _ => []
        };

    internal static Pkcs11KnownPlatform GetCurrentPlatform()
    {
        if (OperatingSystem.IsWindows())
        {
            return Pkcs11KnownPlatform.Windows;
        }

        if (OperatingSystem.IsLinux())
        {
            return Pkcs11KnownPlatform.Linux;
        }

        if (OperatingSystem.IsMacOS())
        {
            return Pkcs11KnownPlatform.MacOS;
        }

        return Pkcs11KnownPlatform.Other;
    }
}

internal enum Pkcs11KnownPlatform
{
    Other = 0,
    Linux = 1,
    Windows = 2,
    MacOS = 3
}
