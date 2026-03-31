using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Web.Components.Pages;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class KeyObjectListViewTests
{
    [Fact]
    public void ApplyFiltersByCapabilityAndSearch()
    {
        HsmKeyObjectSummary[] keys =
        [
            new(Guid.NewGuid(), 1, 10, "signing-rsa", "A1", "Private Key", "RSA", false, false, true, false, false, false),
            new(Guid.NewGuid(), 1, 11, "encrypt-aes", "A2", "Secret Key", "AES", true, true, false, false, false, false),
            new(Guid.NewGuid(), 1, 12, "wrap-aes", "A3", "Secret Key", "AES", false, false, false, false, true, true)
        ];

        IReadOnlyList<HsmKeyObjectSummary> filtered = KeyObjectListView.Apply(keys, "aes", "all", "wrap", "handle");

        Assert.Single(filtered);
        Assert.Equal((nuint)12, filtered[0].Handle);
    }

    [Fact]
    public void ApplySortsByCapabilityCountDescending()
    {
        HsmKeyObjectSummary[] keys =
        [
            new(Guid.NewGuid(), 1, 10, "a", "A1", "Secret Key", "AES", true, false, false, false, false, false),
            new(Guid.NewGuid(), 1, 11, "b", "A2", "Secret Key", "AES", true, true, false, false, false, false),
            new(Guid.NewGuid(), 1, 12, "c", "A3", "Secret Key", "AES", true, true, false, false, true, false)
        ];

        IReadOnlyList<HsmKeyObjectSummary> sorted = KeyObjectListView.Apply(keys, null, "all", "all", "capability");

        Assert.Equal((nuint)12, sorted[0].Handle);
        Assert.Equal((nuint)11, sorted[1].Handle);
        Assert.Equal((nuint)10, sorted[2].Handle);
    }
}
