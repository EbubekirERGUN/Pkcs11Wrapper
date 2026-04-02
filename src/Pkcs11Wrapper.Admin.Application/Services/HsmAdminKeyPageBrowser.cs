using System.Globalization;
using System.Text;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Services;

internal static class HsmAdminKeyPageBrowser
{
    private const string HandleCursorPrefix = "h:";
    private const string OffsetCursorPrefix = "o:";

    public static HsmKeyObjectPage ReadPage(Guid deviceId, nuint slotIdValue, Pkcs11Session session, KeyObjectPageRequest request)
        => string.Equals(request.SortMode, "handle", StringComparison.OrdinalIgnoreCase)
            ? ReadStreamingHandlePage(deviceId, slotIdValue, session, request)
            : ReadSortedFallbackPage(deviceId, slotIdValue, session, request);

    internal static HsmKeyObjectPage ReadStreamingHandlePageFromHandles(IEnumerable<nuint> handles, Func<nuint, HsmKeyObjectSummary> summaryReader, KeyObjectPageRequest request)
    {
        nuint? cursorHandle = DecodeHandleCursor(request.Cursor);
        bool collect = cursorHandle is null;
        int scanned = 0;
        int summaryReads = 0;
        List<HsmKeyObjectSummary> items = [];

        foreach (nuint handle in handles)
        {
            scanned++;
            HsmKeyObjectSummary summary = summaryReader(handle);
            summaryReads++;

            if (!HsmKeyObjectQuery.MatchesSearch(summary, request.SearchText))
            {
                continue;
            }

            if (!collect)
            {
                if (summary.Handle == cursorHandle)
                {
                    collect = true;
                }

                continue;
            }

            if (items.Count == request.PageSize)
            {
                string nextCursor = EncodeHandleCursor(items[^1].Handle);
                return new HsmKeyObjectPage(items, request.PageSize, request.SortMode, request.Cursor, nextCursor, true, scanned, summaryReads, true);
            }

            items.Add(summary);
        }

        return new HsmKeyObjectPage(items, request.PageSize, request.SortMode, request.Cursor, null, false, scanned, summaryReads, true);
    }

    public static Pkcs11ObjectSearchParameters BuildSearch(KeyObjectPageRequest request)
    {
        byte[] label = string.IsNullOrWhiteSpace(request.LabelFilter)
            ? []
            : Encoding.UTF8.GetBytes(request.LabelFilter.Trim());

        Pkcs11ObjectSearchParametersBuilder builder = Pkcs11ObjectSearchParameters.CreateBuilder();
        if (label.Length != 0)
        {
            builder = builder.WithLabel(label);
        }

        Pkcs11ObjectClass? objectClass = request.ClassFilter.ToLowerInvariant() switch
        {
            "secretkey" => Pkcs11ObjectClasses.SecretKey,
            "privatekey" => Pkcs11ObjectClasses.PrivateKey,
            "publickey" => Pkcs11ObjectClasses.PublicKey,
            "data" => Pkcs11ObjectClasses.Data,
            _ => null
        };

        if (objectClass is not null)
        {
            builder = builder.WithObjectClass(objectClass.Value);
        }

        builder = request.CapabilityFilter.ToLowerInvariant() switch
        {
            "encrypt" => builder.RequireEncrypt(),
            "decrypt" => builder.RequireDecrypt(),
            "sign" => builder.RequireSign(),
            "verify" => builder.RequireVerify(),
            "wrap" => builder.RequireWrap(),
            "unwrap" => builder.RequireUnwrap(),
            _ => builder
        };

        return builder.Build();
    }

    private static HsmKeyObjectPage ReadStreamingHandlePage(Guid deviceId, nuint slotIdValue, Pkcs11Session session, KeyObjectPageRequest request)
    {
        Pkcs11ObjectSearchParameters search = BuildSearch(request);
        nuint? cursorHandle = DecodeHandleCursor(request.Cursor);
        bool collect = cursorHandle is null;
        int scanned = 0;
        int summaryReads = 0;
        List<HsmKeyObjectSummary> items = [];
        string? nextCursor = null;
        bool hasNextPage = false;

        session.VisitObjects(search, handle =>
        {
            scanned++;
            HsmKeyObjectSummary summary = HsmAdminObjectCatalog.ReadObjectSummary(deviceId, slotIdValue, session, handle);
            summaryReads++;

            if (!HsmKeyObjectQuery.MatchesSearch(summary, request.SearchText))
            {
                return true;
            }

            if (!collect)
            {
                if (summary.Handle == cursorHandle)
                {
                    collect = true;
                }

                return true;
            }

            items.Add(summary);
            if (items.Count <= request.PageSize)
            {
                return true;
            }

            items.RemoveAt(items.Count - 1);
            nextCursor = EncodeHandleCursor(items[^1].Handle);
            hasNextPage = true;
            return false;
        });

        return new HsmKeyObjectPage(items, request.PageSize, request.SortMode, request.Cursor, nextCursor, hasNextPage, scanned, summaryReads, true);
    }

    private static HsmKeyObjectPage ReadSortedFallbackPage(Guid deviceId, nuint slotIdValue, Pkcs11Session session, KeyObjectPageRequest request)
    {
        Pkcs11ObjectSearchParameters search = BuildSearch(request);
        List<Pkcs11ObjectHandle> handles = HsmAdminObjectCatalog.EnumerateObjectHandles(session, search);
        List<HsmKeyObjectSummary> summaries = new(handles.Count);
        foreach (Pkcs11ObjectHandle handle in handles)
        {
            summaries.Add(HsmAdminObjectCatalog.ReadObjectSummary(deviceId, slotIdValue, session, handle));
        }

        IReadOnlyList<HsmKeyObjectSummary> ordered = HsmKeyObjectQuery.Apply(summaries, request.SearchText, request.ClassFilter, request.CapabilityFilter, request.SortMode);
        int offset = DecodeOffsetCursor(request.Cursor);
        IReadOnlyList<HsmKeyObjectSummary> page = ordered.Skip(offset).Take(request.PageSize).ToArray();
        bool hasNextPage = offset + page.Count < ordered.Count;
        string? nextCursor = hasNextPage ? EncodeOffsetCursor(offset + page.Count) : null;
        return new HsmKeyObjectPage(page, request.PageSize, request.SortMode, request.Cursor, nextCursor, hasNextPage, handles.Count, summaries.Count, false);
    }

    private static string EncodeHandleCursor(nuint handle)
        => string.Create(CultureInfo.InvariantCulture, $"{HandleCursorPrefix}{handle}");

    private static nuint? DecodeHandleCursor(string? cursor)
    {
        if (string.IsNullOrWhiteSpace(cursor) || !cursor.StartsWith(HandleCursorPrefix, StringComparison.Ordinal))
        {
            return null;
        }

        return nuint.TryParse(cursor[HandleCursorPrefix.Length..], NumberStyles.None, CultureInfo.InvariantCulture, out nuint handle)
            ? handle
            : null;
    }

    private static string EncodeOffsetCursor(int offset)
        => string.Create(CultureInfo.InvariantCulture, $"{OffsetCursorPrefix}{offset}");

    private static int DecodeOffsetCursor(string? cursor)
    {
        if (string.IsNullOrWhiteSpace(cursor) || !cursor.StartsWith(OffsetCursorPrefix, StringComparison.Ordinal))
        {
            return 0;
        }

        return int.TryParse(cursor[OffsetCursorPrefix.Length..], NumberStyles.None, CultureInfo.InvariantCulture, out int offset)
            ? Math.Max(offset, 0)
            : 0;
    }
}
