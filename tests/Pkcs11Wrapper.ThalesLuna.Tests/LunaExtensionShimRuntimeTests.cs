using Pkcs11Wrapper;
using Pkcs11Wrapper.Native;
using Pkcs11Wrapper.Native.Interop;
using Pkcs11Wrapper.ThalesLuna;
using Pkcs11Wrapper.ThalesLuna.Native;

namespace Pkcs11Wrapper.ThalesLuna.Tests;

[Collection(LunaRuntimeCollection.Name)]
public sealed class LunaExtensionShimRuntimeTests
{
    [Fact]
    public void ManagedAndNativeTryLoadReturnFalseWhenCaExportIsMissing()
    {
        string? shimPath = ResolvePkcs11V3ShimPath();
        if (string.IsNullOrWhiteSpace(shimPath) || !File.Exists(shimPath))
        {
            return;
        }

        using Pkcs11NativeModule nativeModule = Pkcs11NativeModule.Load(shimPath);
        Assert.False(LunaNativeModule.TryLoad(nativeModule, out LunaNativeModule? nativeLuna));
        Assert.Null(nativeLuna);

        using Pkcs11Module module = Pkcs11Module.Load(shimPath);
        Assert.False(LunaExtensions.TryLoad(module, out LunaExtensions? luna));
        Assert.Null(luna);
    }

    [Fact]
    public void ManagedAndNativeTryLoadBootstrapFunctionListWhenExportExists()
    {
        string? shimPath = ResolveLunaShimPath();
        if (string.IsNullOrWhiteSpace(shimPath) || !File.Exists(shimPath))
        {
            return;
        }

        using Pkcs11NativeModule nativeModule = Pkcs11NativeModule.Load(shimPath);
        Assert.True(LunaNativeModule.TryLoad(nativeModule, out LunaNativeModule? nativeLuna));
        using LunaNativeModule activeNativeLuna = nativeLuna!;
        Assert.True(activeNativeLuna.IsAvailable);
        Assert.Equal(new CK_VERSION(1, 0), activeNativeLuna.FunctionListVersion);
        Assert.Equal(
            new LunaNativeCapabilities(
                HasFunctionList: true,
                HasHighAvailability: false,
                HasCloning: false,
                HasPolicy: false,
                HasPedMofn: false,
                HasContainers: false,
                HasKeys: false),
            activeNativeLuna.Capabilities);

        using Pkcs11Module module = Pkcs11Module.Load(shimPath);
        module.Initialize();

        Assert.True(LunaExtensions.TryLoad(module, out LunaExtensions? luna));
        using LunaExtensions activeLuna = luna!;
        Assert.True(activeLuna.IsAvailable);
        Assert.Equal(new CK_VERSION(1, 0), activeLuna.FunctionListVersion);
        Assert.Equal(
            new LunaCapabilities(
                HasFunctionList: true,
                HasHighAvailability: false,
                HasCloning: false,
                HasPolicy: false,
                HasPedMofn: false,
                HasContainers: false,
                HasKeys: false),
            activeLuna.Capabilities);
        Assert.False(activeLuna.HighAvailability.IsAvailable);
        Assert.False(activeLuna.Cloning.IsAvailable);
        Assert.False(activeLuna.Policy.IsAvailable);
        Assert.False(activeLuna.PedMofn.IsAvailable);
        Assert.False(activeLuna.Containers.IsAvailable);
        Assert.False(activeLuna.Keys.IsAvailable);
    }

    [Fact]
    public void TryLoadReturnsFalseWhenCaGetFunctionListReportsNotSupported()
    {
        string? shimPath = ResolveUnsupportedLunaShimPath();
        if (string.IsNullOrWhiteSpace(shimPath) || !File.Exists(shimPath))
        {
            return;
        }

        using Pkcs11NativeModule nativeModule = Pkcs11NativeModule.Load(shimPath);
        Assert.False(LunaNativeModule.TryLoad(nativeModule, out LunaNativeModule? nativeLuna));
        Assert.Null(nativeLuna);

        using Pkcs11Module module = Pkcs11Module.Load(shimPath);
        Assert.False(LunaExtensions.TryLoad(module, out LunaExtensions? luna));
        Assert.Null(luna);
    }

    [Fact]
    public void TryLoadThrowsWhenCaGetFunctionListReturnsNullTable()
    {
        string? shimPath = ResolveNullPointerLunaShimPath();
        if (string.IsNullOrWhiteSpace(shimPath) || !File.Exists(shimPath))
        {
            return;
        }

        using Pkcs11NativeModule nativeModule = Pkcs11NativeModule.Load(shimPath);
        InvalidOperationException nativeException = Assert.Throws<InvalidOperationException>(() => LunaNativeModule.TryLoad(nativeModule, out _));
        Assert.Contains("null Luna extension function table", nativeException.Message, StringComparison.Ordinal);

        using Pkcs11Module module = Pkcs11Module.Load(shimPath);
        InvalidOperationException managedException = Assert.Throws<InvalidOperationException>(() => LunaExtensions.TryLoad(module, out _));
        Assert.Contains("null Luna extension function table", managedException.Message, StringComparison.Ordinal);
    }

    private static string? ResolveLunaShimPath()
    {
        if (!OperatingSystem.IsLinux())
        {
            return null;
        }

        string? configuredPath = Environment.GetEnvironmentVariable("PKCS11_LUNA_SHIM_PATH");
        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            return configuredPath;
        }

        return ResolveArtifactPath("artifacts", "test-fixtures", "luna-extension-shim", "libpkcs11-luna-extension-shim.so");
    }

    private static string? ResolveUnsupportedLunaShimPath()
    {
        if (!OperatingSystem.IsLinux())
        {
            return null;
        }

        return ResolveArtifactPath("artifacts", "test-fixtures", "luna-extension-shim", "libpkcs11-luna-extension-shim-unsupported.so");
    }

    private static string? ResolveNullPointerLunaShimPath()
    {
        if (!OperatingSystem.IsLinux())
        {
            return null;
        }

        return ResolveArtifactPath("artifacts", "test-fixtures", "luna-extension-shim", "libpkcs11-luna-extension-shim-null-pointer.so");
    }

    private static string? ResolvePkcs11V3ShimPath()
    {
        if (!OperatingSystem.IsLinux())
        {
            return null;
        }

        string? configuredPath = Environment.GetEnvironmentVariable("PKCS11_V3_SHIM_PATH");
        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            return configuredPath;
        }

        return ResolveArtifactPath("artifacts", "test-fixtures", "pkcs11-v3-shim", "libpkcs11-v3-shim.so");
    }

    private static string? ResolveArtifactPath(params string[] relativeSegments)
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Pkcs11Wrapper.sln")))
            {
                return Path.Combine([current.FullName, .. relativeSegments]);
            }

            current = current.Parent;
        }

        return null;
    }
}
