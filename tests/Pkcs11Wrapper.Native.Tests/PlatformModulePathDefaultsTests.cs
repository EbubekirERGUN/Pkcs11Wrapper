using Pkcs11Wrapper;

namespace Pkcs11Wrapper.Native.Tests;

public sealed class PlatformModulePathDefaultsTests
{
    [Fact]
    public void SoftHsmCandidatesMatchKnownPlatforms()
    {
        Assert.Equal(["libsofthsm2.so"], Pkcs11ModulePathDefaults.GetSoftHsmModuleCandidates(Pkcs11KnownPlatform.Linux));
        Assert.Equal(["softhsm2-x64.dll", "softhsm2.dll"], Pkcs11ModulePathDefaults.GetSoftHsmModuleCandidates(Pkcs11KnownPlatform.Windows));
        Assert.Equal(["libsofthsm2.dylib", "softhsm2.dylib"], Pkcs11ModulePathDefaults.GetSoftHsmModuleCandidates(Pkcs11KnownPlatform.MacOS));
        Assert.Empty(Pkcs11ModulePathDefaults.GetSoftHsmModuleCandidates(Pkcs11KnownPlatform.Other));
    }

    [Fact]
    public void DefaultSoftHsmModulePathMatchesFirstCandidateForCurrentPlatform()
    {
        Pkcs11KnownPlatform platform = Pkcs11ModulePathDefaults.GetCurrentPlatform();
        string[] candidates = Pkcs11ModulePathDefaults.GetSoftHsmModuleCandidates(platform);
        string? defaultPath = Pkcs11ModulePathDefaults.GetDefaultSoftHsmModulePath();

        if (candidates.Length == 0)
        {
            Assert.Null(defaultPath);
        }
        else
        {
            Assert.Equal(candidates[0], defaultPath);
        }
    }
}
