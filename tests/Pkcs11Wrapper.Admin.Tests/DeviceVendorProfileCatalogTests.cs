using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Web.Components.Shared;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class DeviceVendorProfileCatalogTests
{
    private static readonly HsmDeviceVendorMetadata LunaVendor = new(
        "thales",
        "Thales",
        "luna-standard",
        "Luna / standard PKCS#11");

    private static readonly HsmDeviceVendorMetadata EntrustVendor = new(
        "entrust",
        "Entrust",
        "nshield-standard",
        "nShield / standard PKCS#11");

    private static readonly HsmDeviceVendorMetadata UtimacoVendor = new(
        "utimaco",
        "Utimaco",
        "standard",
        "Standard PKCS#11");

    private static readonly HsmDeviceVendorMetadata CustomVendor = new(
        "custom-vendor",
        "Custom Vendor",
        "custom-profile",
        "Custom profile");

    [Fact]
    public void GetSelectionId_ReturnsKnownLunaProfileSelection()
    {
        string selectionId = DeviceVendorProfileCatalog.GetSelectionId(LunaVendor);

        Assert.Equal("thales-luna-standard", selectionId);
    }

    [Fact]
    public void GetGuidance_ReturnsLunaSpecificSummaryAndHints()
    {
        DeviceVendorGuidance guidance = DeviceVendorProfileCatalog.GetGuidance(LunaVendor);

        Assert.True(guidance.IsKnownProfile);
        Assert.False(guidance.IsVendorNeutral);
        Assert.Equal("Thales", guidance.Title);
        Assert.Equal("Luna / standard PKCS#11", guidance.ProfileName);
        Assert.Contains("Luna client/runtime", guidance.Summary, StringComparison.Ordinal);
        Assert.Equal(3, guidance.Hints.Count);
        Assert.Contains(guidance.Hints, hint => hint.Body.Contains("cklog or ckshim", StringComparison.Ordinal));
        Assert.Contains(guidance.Hints, hint => hint.Body.Contains("token/policy dependent", StringComparison.Ordinal));
        Assert.Contains(guidance.Hints, hint => hint.Title.Contains("CA_*", StringComparison.Ordinal) || hint.Body.Contains("CA_*", StringComparison.Ordinal));
    }

    [Fact]
    public void GetSelectionId_ReturnsKnownEntrustProfileSelection()
    {
        string selectionId = DeviceVendorProfileCatalog.GetSelectionId(EntrustVendor);

        Assert.Equal("entrust-nshield-standard", selectionId);
    }

    [Fact]
    public void GetGuidance_ReturnsEntrustSpecificSummaryAndHints()
    {
        DeviceVendorGuidance guidance = DeviceVendorProfileCatalog.GetGuidance(EntrustVendor);

        Assert.True(guidance.IsKnownProfile);
        Assert.False(guidance.IsVendorNeutral);
        Assert.Equal("Entrust", guidance.Title);
        Assert.Equal("nShield / standard PKCS#11", guidance.ProfileName);
        Assert.Contains("Entrust nShield", guidance.Summary, StringComparison.Ordinal);
        Assert.Equal(3, guidance.Hints.Count);
        Assert.Contains(guidance.Hints, hint => hint.Body.Contains("Security World", StringComparison.Ordinal));
        Assert.Contains(guidance.Hints, hint => hint.Body.Contains("module actually exposes", StringComparison.Ordinal));
        Assert.Contains(guidance.Hints, hint => hint.Body.Contains("Vendor-native provisioning", StringComparison.Ordinal));
    }

    [Fact]
    public void GetSelectionId_ReturnsKnownUtimacoProfileSelection()
    {
        string selectionId = DeviceVendorProfileCatalog.GetSelectionId(UtimacoVendor);

        Assert.Equal("utimaco-standard", selectionId);
    }

    [Fact]
    public void GetGuidance_ReturnsUtimacoSpecificSummaryAndHints()
    {
        DeviceVendorGuidance guidance = DeviceVendorProfileCatalog.GetGuidance(UtimacoVendor);

        Assert.True(guidance.IsKnownProfile);
        Assert.False(guidance.IsVendorNeutral);
        Assert.Equal("Utimaco", guidance.Title);
        Assert.Equal("Standard PKCS#11", guidance.ProfileName);
        Assert.Contains("Utimaco PKCS#11 module", guidance.Summary, StringComparison.Ordinal);
        Assert.Equal(3, guidance.Hints.Count);
        Assert.Contains(guidance.Hints, hint => hint.Body.Contains("same machine", StringComparison.Ordinal));
        Assert.Contains(guidance.Hints, hint => hint.Body.Contains("PKCS#11 Lab", StringComparison.Ordinal));
        Assert.Contains(guidance.Hints, hint => hint.Body.Contains("dedicated vendor tooling", StringComparison.Ordinal));
    }

    [Fact]
    public void GetGuidance_ReturnsVendorNeutralGuidanceForNullVendor()
    {
        DeviceVendorGuidance guidance = DeviceVendorProfileCatalog.GetGuidance(null);

        Assert.False(guidance.IsKnownProfile);
        Assert.True(guidance.IsVendorNeutral);
        Assert.Equal("Vendor-neutral profile", guidance.Title);
        Assert.Null(guidance.ProfileName);
        Assert.Equal(3, guidance.Hints.Count);
        Assert.Contains(guidance.Hints, hint => hint.Body.Contains("host/container", StringComparison.Ordinal));
    }

    [Fact]
    public void GetSelectionId_ReturnsCustomSelectionForUnknownVendor()
    {
        string selectionId = DeviceVendorProfileCatalog.GetSelectionId(CustomVendor);

        Assert.Equal(DeviceVendorProfileCatalog.CustomSelectionId, selectionId);
    }

    [Fact]
    public void GetGuidance_ReturnsCustomVendorGuidanceForUnknownVendor()
    {
        DeviceVendorGuidance guidance = DeviceVendorProfileCatalog.GetGuidance(CustomVendor);

        Assert.False(guidance.IsKnownProfile);
        Assert.False(guidance.IsVendorNeutral);
        Assert.Equal("Custom Vendor", guidance.Title);
        Assert.Equal("Custom profile", guidance.ProfileName);
        Assert.Equal(3, guidance.Hints.Count);
        Assert.Contains(guidance.Hints, hint => hint.Body.Contains("Improve operator context", StringComparison.OrdinalIgnoreCase) || hint.Body.Contains("improve operator context", StringComparison.OrdinalIgnoreCase));
    }
}
