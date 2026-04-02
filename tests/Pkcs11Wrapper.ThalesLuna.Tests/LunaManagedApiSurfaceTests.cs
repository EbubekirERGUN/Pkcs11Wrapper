using System.Reflection;
using Pkcs11Wrapper;
using Pkcs11Wrapper.ThalesLuna;
using Pkcs11Wrapper.Native;
using Pkcs11Wrapper.ThalesLuna.Cloning;
using Pkcs11Wrapper.ThalesLuna.Containers;
using Pkcs11Wrapper.ThalesLuna.HighAvailability;
using Pkcs11Wrapper.ThalesLuna.Keys;
using Pkcs11Wrapper.ThalesLuna.Native;
using Pkcs11Wrapper.ThalesLuna.PedMofn;
using Pkcs11Wrapper.ThalesLuna.Policy;

namespace Pkcs11Wrapper.ThalesLuna.Tests;

public sealed class LunaManagedApiSurfaceTests
{
    [Fact]
    public void ManagedAndNativeBootstrapApisAreExposed()
    {
        MethodInfo? managedTryLoad = typeof(LunaExtensions).GetMethod(
            nameof(LunaExtensions.TryLoad),
            BindingFlags.Public | BindingFlags.Static,
            [typeof(Pkcs11Module), typeof(LunaExtensions).MakeByRefType()]);

        MethodInfo? nativeTryLoad = typeof(LunaNativeModule).GetMethod(
            nameof(LunaNativeModule.TryLoad),
            BindingFlags.Public | BindingFlags.Static,
            [typeof(Pkcs11NativeModule), typeof(LunaNativeModule).MakeByRefType()]);

        Assert.NotNull(managedTryLoad);
        Assert.True(managedTryLoad!.GetParameters()[1].IsOut);
        Assert.NotNull(nativeTryLoad);
        Assert.True(nativeTryLoad!.GetParameters()[1].IsOut);

        Assert.NotNull(typeof(LunaExtensions).GetProperty(nameof(LunaExtensions.FunctionListVersion)));
        Assert.NotNull(typeof(LunaExtensions).GetProperty(nameof(LunaExtensions.Capabilities)));
        Assert.NotNull(typeof(LunaExtensions).GetProperty(nameof(LunaExtensions.HighAvailability)));
        Assert.NotNull(typeof(LunaExtensions).GetProperty(nameof(LunaExtensions.Cloning)));
        Assert.NotNull(typeof(LunaExtensions).GetProperty(nameof(LunaExtensions.Policy)));
        Assert.NotNull(typeof(LunaExtensions).GetProperty(nameof(LunaExtensions.PedMofn)));
        Assert.NotNull(typeof(LunaExtensions).GetProperty(nameof(LunaExtensions.Containers)));
        Assert.NotNull(typeof(LunaExtensions).GetProperty(nameof(LunaExtensions.Keys)));
        Assert.NotNull(typeof(LunaNativeModule).GetProperty(nameof(LunaNativeModule.FunctionListVersion)));
        Assert.NotNull(typeof(LunaNativeModule).GetProperty(nameof(LunaNativeModule.Capabilities)));
    }

    [Fact]
    public void CapabilityRecordsAndFamilyFacadesExposeConservativeDefaults()
    {
        LunaCapabilities managed = new(
            HasFunctionList: true,
            HasHighAvailability: false,
            HasCloning: false,
            HasPolicy: false,
            HasPedMofn: false,
            HasContainers: false,
            HasKeys: false);

        LunaNativeCapabilities native = new(
            HasFunctionList: true,
            HasHighAvailability: false,
            HasCloning: false,
            HasPolicy: false,
            HasPedMofn: false,
            HasContainers: false,
            HasKeys: false);

        Assert.True(managed.HasFunctionList);
        Assert.True(native.HasFunctionList);
        Assert.False(managed.HasHighAvailability);
        Assert.False(native.HasKeys);

        Assert.Equal("Pkcs11Wrapper.ThalesLuna.HighAvailability", typeof(LunaHighAvailabilityExtensions).Namespace);
        Assert.Equal("Pkcs11Wrapper.ThalesLuna.Cloning", typeof(LunaCloningExtensions).Namespace);
        Assert.Equal("Pkcs11Wrapper.ThalesLuna.Policy", typeof(LunaPolicyExtensions).Namespace);
        Assert.Equal("Pkcs11Wrapper.ThalesLuna.PedMofn", typeof(LunaPedMofnExtensions).Namespace);
        Assert.Equal("Pkcs11Wrapper.ThalesLuna.Containers", typeof(LunaContainerExtensions).Namespace);
        Assert.Equal("Pkcs11Wrapper.ThalesLuna.Keys", typeof(LunaKeyExtensions).Namespace);
    }
}
