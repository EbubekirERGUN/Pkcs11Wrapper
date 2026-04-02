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

    private static readonly HsmDeviceVendorMetadata OracleVendor = new(
        "oracle",
        "Oracle",
        "oci-dedicated-kms-standard",
        "OCI Dedicated KMS / standard PKCS#11");

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

    [Fact]
    public void GetSelectionId_ReturnsKnownOracleProfileSelection()
    {
        string selectionId = DeviceVendorProfileCatalog.GetSelectionId(OracleVendor);

        Assert.Equal("oracle-oci-dedicated-kms-standard", selectionId);
    }

    [Fact]
    public void GetGuidance_ReturnsOracleSpecificSummaryAndHints()
    {
        DeviceVendorGuidance guidance = DeviceVendorProfileCatalog.GetGuidance(OracleVendor);

        Assert.True(guidance.IsKnownProfile);
        Assert.False(guidance.IsVendorNeutral);
        Assert.Equal("Oracle", guidance.Title);
        Assert.Equal("OCI Dedicated KMS / standard PKCS#11", guidance.ProfileName);
        Assert.Contains("Dedicated KMS", guidance.Summary);
        Assert.Equal(3, guidance.Hints.Count);
        Assert.Contains(guidance.Hints, hint => hint.Body.Contains("oci-hsm-pkcs11", StringComparison.Ordinal));
        Assert.Contains(guidance.Hints, hint => hint.Body.Contains("username:password", StringComparison.Ordinal));
        Assert.Contains(guidance.Hints, hint => hint.Body.Contains("Windows CNG/KSP", StringComparison.Ordinal));
    }
}
