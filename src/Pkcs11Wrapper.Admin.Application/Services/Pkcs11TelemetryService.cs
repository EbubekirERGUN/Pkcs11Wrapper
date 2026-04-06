using System.Diagnostics;
using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Native;

namespace Pkcs11Wrapper.Admin.Application.Services;

public sealed class Pkcs11TelemetryService(IPkcs11TelemetryStore store, IAdminActorContext actorContext, AdminPkcs11TelemetryOptions options)
{
    private const string ExportFormat = "Pkcs11Wrapper.Admin.Pkcs11Telemetry";
    private const int ExportSchemaVersion = 1;

    public async Task<IReadOnlyList<AdminPkcs11TelemetryEntry>> GetRecentAsync(AdminPkcs11TelemetryQuery? query = null, CancellationToken cancellationToken = default)
    {
        AdminPkcs11TelemetryQuery effectiveQuery = NormalizeQuery(query ?? new());
        IReadOnlyList<AdminPkcs11TelemetryEntry> entries = await store.ReadRecentAsync(effectiveQuery.Take, cancellationToken);
        return Pkcs11TelemetryQueryEvaluator.Apply(entries, effectiveQuery, DateTimeOffset.UtcNow);
    }

    public Task<AdminPkcs11TelemetryStorageStatus> GetStorageStatusAsync(CancellationToken cancellationToken = default)
        => store.GetStorageStatusAsync(cancellationToken);

    public async Task<AdminPkcs11TelemetryExportBundle> ExportAsync(AdminPkcs11TelemetryQuery? query = null, CancellationToken cancellationToken = default)
    {
        AdminPkcs11TelemetryQuery effectiveQuery = NormalizeExportQuery(query ?? new(Take: GetNormalizedExportMaxEntries()));
        IReadOnlyList<AdminPkcs11TelemetryEntry> retainedEntries = await store.ReadAllAsync(cancellationToken);
        IReadOnlyList<AdminPkcs11TelemetryEntry> fullyFiltered = Pkcs11TelemetryQueryEvaluator.Apply(retainedEntries, effectiveQuery with { Take = int.MaxValue }, DateTimeOffset.UtcNow);
        AdminPkcs11TelemetryEntry[] entries = [.. fullyFiltered.Take(effectiveQuery.Take)];
        AdminPkcs11TelemetryStorageStatus storageStatus = await store.GetStorageStatusAsync(cancellationToken);

        return new(
            ExportFormat,
            ExportSchemaVersion,
            DateTimeOffset.UtcNow,
            RedactedOnly: true,
            MayBeTruncated: fullyFiltered.Count > entries.Length,
            EntryCount: entries.Length,
            Filters: effectiveQuery,
            StorageStatus: storageStatus,
            Entries: entries);
    }

    public IPkcs11OperationTelemetryListener CreateListener(HsmDeviceProfile device)
        => new AdminPkcs11TelemetryListener(store, device, actorContext.GetCurrent(), Activity.Current?.TraceId.ToString());

    private AdminPkcs11TelemetryQuery NormalizeQuery(AdminPkcs11TelemetryQuery query)
        => query with
        {
            Take = NormalizeTake(query.Take, defaultTake: 500),
            MinDurationMilliseconds = NormalizeMinDuration(query.MinDurationMilliseconds)
        };

    private AdminPkcs11TelemetryQuery NormalizeExportQuery(AdminPkcs11TelemetryQuery query)
        => query with
        {
            Take = NormalizeTake(query.Take, defaultTake: GetNormalizedExportMaxEntries()),
            MinDurationMilliseconds = NormalizeMinDuration(query.MinDurationMilliseconds)
        };

    private int NormalizeTake(int take, int defaultTake)
    {
        int exportMaxEntries = GetNormalizedExportMaxEntries();
        if (take <= 0)
        {
            return Math.Min(defaultTake, exportMaxEntries);
        }

        return Math.Min(take, exportMaxEntries);
    }

    private int GetNormalizedExportMaxEntries()
        => options.ExportMaxEntries <= 0 ? 5000 : options.ExportMaxEntries;

    private static double? NormalizeMinDuration(double? minDurationMilliseconds)
        => minDurationMilliseconds.HasValue && minDurationMilliseconds.Value > 0
            ? minDurationMilliseconds.Value
            : null;

    private static async Task AppendEntryFireAndForgetAsync(IPkcs11TelemetryStore store, AdminPkcs11TelemetryEntry entry)
    {
        try
        {
            await store.AppendAsync(entry).ConfigureAwait(false);
        }
        catch
        {
        }
    }

    private sealed class AdminPkcs11TelemetryListener(IPkcs11TelemetryStore store, HsmDeviceProfile device, AdminActorInfo actor, string? activityTraceId) : IPkcs11OperationTelemetryListener
    {
        public void OnOperationCompleted(in Pkcs11OperationTelemetryEvent operationEvent)
        {
            AdminPkcs11TelemetryEntry entry = new(
                Guid.NewGuid(),
                DateTimeOffset.UtcNow,
                device.Id,
                device.Name,
                operationEvent.OperationName,
                operationEvent.NativeOperationName,
                operationEvent.Status.ToString(),
                operationEvent.Duration.TotalMilliseconds,
                operationEvent.ReturnValue?.ToString(),
                operationEvent.SlotId.HasValue ? (ulong)operationEvent.SlotId.Value : null,
                operationEvent.SessionHandle.HasValue ? (ulong)operationEvent.SessionHandle.Value : null,
                operationEvent.MechanismType.HasValue ? (ulong)operationEvent.MechanismType.Value : null,
                operationEvent.Exception?.GetType().Name,
                string.IsNullOrWhiteSpace(actor.Name) ? null : actor.Name,
                string.IsNullOrWhiteSpace(actor.AuthenticationType) ? null : actor.AuthenticationType,
                string.IsNullOrWhiteSpace(actor.SessionId) ? null : actor.SessionId,
                string.IsNullOrWhiteSpace(activityTraceId) ? actor.SessionId : activityTraceId,
                [.. operationEvent.Fields.Select(field => new AdminPkcs11TelemetryField(field.Name, field.Classification.ToString(), field.Value))]);

            _ = AppendEntryFireAndForgetAsync(store, entry);
        }
    }
}
