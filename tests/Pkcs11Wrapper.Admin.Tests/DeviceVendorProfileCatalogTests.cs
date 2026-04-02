using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Web.Components.Shared;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class DeviceVendorProfileCatalogTests
{
    private static readonly HsmDeviceVendorMetadata GoogleVendor = new(
        "google",
        "Google Cloud",
        "cloud-kms-kmsp11",
        "Cloud KMS / Cloud HSM via kmsp11");

    [Fact]
    public void GetSelectionId_ReturnsKnownGoogleProfileSelection()
    {
        string selectionId = DeviceVendorProfileCatalog.GetSelectionId(GoogleVendor);

        Assert.Equal("google-cloud-kms-kmsp11", selectionId);
    }

    [Fact]
    public void GetGuidance_ReturnsGoogleSpecificSummaryAndHints()
    {
        DeviceVendorGuidance guidance = DeviceVendorProfileCatalog.GetGuidance(GoogleVendor);

        Assert.True(guidance.IsKnownProfile);
        Assert.False(guidance.IsVendorNeutral);
        Assert.Equal("Google Cloud", guidance.Title);
        Assert.Equal("Cloud KMS / Cloud HSM via kmsp11", guidance.ProfileName);
        Assert.Contains("indirect PKCS#11", guidance.Summary);
        Assert.Equal(3, guidance.Hints.Count);
        Assert.Contains(guidance.Hints, hint => hint.Body.Contains("KMS_PKCS11_CONFIG", StringComparison.Ordinal));
        Assert.Contains(guidance.Hints, hint => hint.Body.Contains("PIN is ignored", StringComparison.Ordinal));
        Assert.Contains(guidance.Hints, hint => hint.Body.Contains("Cloud KMS lifecycle/control-plane", StringComparison.Ordinal));
    }
}
