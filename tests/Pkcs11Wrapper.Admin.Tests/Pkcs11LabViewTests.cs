using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Web.Components.Pages;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class Pkcs11LabViewTests
{
    [Theory]
    [InlineData(Pkcs11LabOperation.ModuleInfo, Pkcs11LabOperationCategory.Diagnostics)]
    [InlineData(Pkcs11LabOperation.SignData, Pkcs11LabOperationCategory.Crypto)]
    [InlineData(Pkcs11LabOperation.WrapKey, Pkcs11LabOperationCategory.Objects)]
    [InlineData(Pkcs11LabOperation.ReadAttribute, Pkcs11LabOperationCategory.Attributes)]
    public void GetCategoryReturnsExpectedBucket(Pkcs11LabOperation operation, Pkcs11LabOperationCategory expected)
        => Assert.Equal(expected, Pkcs11LabView.GetCategory(operation));

    [Fact]
    public void ApplyHistoryFiltersCanFilterByStatusAndCategory()
    {
        Pkcs11LabHistoryListItem[] items =
        [
            new(DateTimeOffset.UtcNow.AddMinutes(-2), Pkcs11LabOperation.ModuleInfo, "module ok", true, 2, Pkcs11LabArtifactKind.None, null, null),
            new(DateTimeOffset.UtcNow.AddMinutes(-1), Pkcs11LabOperation.SignData, "sign fail", false, 7, Pkcs11LabArtifactKind.None, null, null),
            new(DateTimeOffset.UtcNow, Pkcs11LabOperation.WrapKey, "wrap ok", true, 9, Pkcs11LabArtifactKind.WrappedKey, "55", "ABCD")
        ];

        IReadOnlyList<Pkcs11LabHistoryListItem> filtered = Pkcs11LabView.ApplyHistoryFilters(items, null, "success", "objects");

        Assert.Single(filtered);
        Assert.Equal(Pkcs11LabOperation.WrapKey, filtered[0].Operation);
    }

    [Fact]
    public void ApplyHistoryFiltersSearchesAcrossSummaryAndCreatedHandle()
    {
        Pkcs11LabHistoryListItem[] items =
        [
            new(DateTimeOffset.UtcNow.AddMinutes(-1), Pkcs11LabOperation.EncryptData, "ciphertext ready", true, 5, Pkcs11LabArtifactKind.Ciphertext, null, "CAFE"),
            new(DateTimeOffset.UtcNow, Pkcs11LabOperation.UnwrapAesKey, "created aes handle", true, 11, Pkcs11LabArtifactKind.None, "701", null)
        ];

        IReadOnlyList<Pkcs11LabHistoryListItem> filtered = Pkcs11LabView.ApplyHistoryFilters(items, "701", "all", "all");

        Assert.Single(filtered);
        Assert.Equal(Pkcs11LabOperation.UnwrapAesKey, filtered[0].Operation);
    }
}
