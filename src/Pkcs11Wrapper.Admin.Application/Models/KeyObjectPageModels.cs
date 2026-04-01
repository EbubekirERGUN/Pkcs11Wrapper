using System.ComponentModel.DataAnnotations;

namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed class KeyObjectPageRequest
{
    public string? LabelFilter { get; set; }

    public string? SearchText { get; set; }

    public string ClassFilter { get; set; } = "all";

    public string CapabilityFilter { get; set; } = "all";

    public string SortMode { get; set; } = "handle";

    [Range(1, 100)]
    public int PageSize { get; set; } = 25;

    public string? Cursor { get; set; }
}

public sealed record HsmKeyObjectPage(
    IReadOnlyList<HsmKeyObjectSummary> Items,
    int PageSize,
    string SortMode,
    string? Cursor,
    string? NextCursor,
    bool HasNextPage,
    int ScannedHandleCount,
    int SummaryReadCount,
    bool UsedStreamingCursor);
