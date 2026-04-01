using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class HsmAdminKeyPageBrowserTests
{
    [Fact]
    public void ReadStreamingHandlePageFromHandlesStopsAfterFirstPagePlusLookahead()
    {
        int reads = 0;
        KeyObjectPageRequest request = new()
        {
            SortMode = "handle",
            PageSize = 25,
            SearchText = null
        };

        HsmKeyObjectPage page = HsmAdminKeyPageBrowser.ReadStreamingHandlePageFromHandles(
            Enumerable.Range(1, 1000).Select(value => (nuint)value),
            handle =>
            {
                reads++;
                return new HsmKeyObjectSummary(Guid.Empty, 1, handle, $"key-{handle}", handle.ToString(), "Secret Key", "AES", true, true, false, false, false, false);
            },
            request);

        Assert.Equal(25, page.Items.Count);
        Assert.True(page.HasNextPage);
        Assert.Equal(26, reads);
        Assert.Equal(26, page.SummaryReadCount);
        Assert.Equal((nuint)1, page.Items[0].Handle);
        Assert.Equal((nuint)25, page.Items[^1].Handle);
    }

    [Fact]
    public void ReadStreamingHandlePageFromHandlesRespectsCursorWithoutMaterializingWholeSlot()
    {
        int reads = 0;
        KeyObjectPageRequest request = new()
        {
            SortMode = "handle",
            PageSize = 25,
            Cursor = "h:25"
        };

        HsmKeyObjectPage page = HsmAdminKeyPageBrowser.ReadStreamingHandlePageFromHandles(
            Enumerable.Range(1, 1000).Select(value => (nuint)value),
            handle =>
            {
                reads++;
                return new HsmKeyObjectSummary(Guid.Empty, 1, handle, $"key-{handle}", handle.ToString(), "Secret Key", "AES", true, true, false, false, false, false);
            },
            request);

        Assert.Equal(25, page.Items.Count);
        Assert.True(page.HasNextPage);
        Assert.Equal(51, reads);
        Assert.Equal((nuint)26, page.Items[0].Handle);
        Assert.Equal((nuint)50, page.Items[^1].Handle);
    }
}
