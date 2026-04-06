using System.Text;
using System.Text.Json;
using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Infrastructure;

public sealed class JsonLinePkcs11TelemetryStore(AdminStorageOptions storageOptions, AdminPkcs11TelemetryOptions? telemetryOptions = null) : IPkcs11TelemetryStore
{
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    private readonly SemaphoreSlim _mutex = new(1, 1);
    private readonly AdminPkcs11TelemetryOptions _telemetryOptions = telemetryOptions ?? new();

    public async Task AppendAsync(AdminPkcs11TelemetryEntry entry, CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            string path = GetActivePath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            await EnforceRetentionAsync(cancellationToken);

            string line = JsonSerializer.Serialize(entry, AdminJsonContext.Default.AdminPkcs11TelemetryEntry) + Environment.NewLine;
            int lineBytes = Encoding.UTF8.GetByteCount(line);
            await RotateIfNeededForAppendAsync(lineBytes, cancellationToken);

            await using FileStream stream = new(path, FileMode.Append, FileAccess.Write, FileShare.Read, 64 * 1024, FileOptions.Asynchronous);
            await using StreamWriter writer = new(stream, Utf8NoBom, leaveOpen: true);
            await writer.WriteAsync(line.AsMemory(), cancellationToken);
            await writer.FlushAsync(cancellationToken);

            await EnforceRetentionAsync(cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<AdminPkcs11TelemetryEntry>> ReadRecentAsync(int take, CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await EnforceRetentionAsync(cancellationToken);
            return await ReadEntriesAsync(Math.Max(1, take), cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<AdminPkcs11TelemetryEntry>> ReadAllAsync(CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await EnforceRetentionAsync(cancellationToken);
            return await ReadEntriesAsync(null, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<AdminPkcs11TelemetryStorageStatus> GetStorageStatusAsync(CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            await EnforceRetentionAsync(cancellationToken);
            string activePath = GetActivePath();
            string[] retainedPaths = GetRetainedFilesNewestFirst();
            long activeFileBytes = 0;
            int archivedCount = 0;
            long retainedBytes = 0;
            foreach (string path in retainedPaths)
            {
                FileInfo info = new(path);
                if (!info.Exists) continue;
                retainedBytes += info.Length;
                if (string.Equals(info.FullName, activePath, StringComparison.Ordinal))
                    activeFileBytes = info.Length;
                else
                    archivedCount++;
            }

            return new(
                ActiveFileBytes: activeFileBytes,
                ArchivedFileCount: archivedCount,
                RetainedFileCount: retainedPaths.Length,
                RetainedBytes: retainedBytes,
                ActiveFileMaxBytes: GetNormalizedActiveFileMaxBytes(),
                RetentionDays: GetNormalizedRetentionDays(),
                MaxArchivedFiles: GetNormalizedMaxArchivedFiles(),
                ExportMaxEntries: GetNormalizedExportMaxEntries());
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<IReadOnlyList<AdminPkcs11TelemetryEntry>> ReadEntriesAsync(int? take, CancellationToken cancellationToken)
    {
        if (take is int newestTake)
        {
            return await ReadNewestEntriesAsync(Math.Max(1, newestTake), cancellationToken);
        }

        return await ReadAllEntriesAsync(cancellationToken);
    }

    private async Task<IReadOnlyList<AdminPkcs11TelemetryEntry>> ReadNewestEntriesAsync(int take, CancellationToken cancellationToken)
    {
        List<AdminPkcs11TelemetryEntry> entries = [];
        foreach (string path in GetRetainedFilesNewestFirst())
        {
            if (!File.Exists(path))
            {
                continue;
            }

            IReadOnlyList<AdminPkcs11TelemetryEntry> fileEntries = await ReadNewestEntriesFromFileAsync(path, take - entries.Count, cancellationToken);
            entries.AddRange(fileEntries);
            if (entries.Count >= take)
            {
                return SortEntries(entries);
            }
        }

        return SortEntries(entries);
    }

    private async Task<IReadOnlyList<AdminPkcs11TelemetryEntry>> ReadAllEntriesAsync(CancellationToken cancellationToken)
    {
        List<AdminPkcs11TelemetryEntry> entries = [];
        foreach (string path in GetRetainedFilesNewestFirst())
        {
            if (!File.Exists(path))
            {
                continue;
            }

            await foreach (string line in ReadLinesAsync(path, cancellationToken))
            {
                entries.Add(DeserializeEntry(line, path));
            }
        }

        return SortEntries(entries);
    }

    private static async Task<IReadOnlyList<AdminPkcs11TelemetryEntry>> ReadNewestEntriesFromFileAsync(string path, int take, CancellationToken cancellationToken)
    {
        if (take <= 0)
        {
            return [];
        }

        Queue<string> tail = new(take + 1);
        await foreach (string line in ReadLinesAsync(path, cancellationToken))
        {
            tail.Enqueue(line);
            if (tail.Count > take)
            {
                tail.Dequeue();
            }
        }

        AdminPkcs11TelemetryEntry[] entries = new AdminPkcs11TelemetryEntry[tail.Count];
        int i = entries.Length - 1;
        foreach (string line in tail)
        {
            entries[i--] = DeserializeEntry(line, path);
        }

        return entries;
    }

    private static async IAsyncEnumerable<string> ReadLinesAsync(string path, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await using FileStream stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using StreamReader reader = new(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            string trimmed = line.Trim();
            if (!string.IsNullOrWhiteSpace(trimmed))
            {
                yield return trimmed;
            }
        }
    }

    private async Task RotateIfNeededForAppendAsync(int incomingLineBytes, CancellationToken cancellationToken)
    {
        string activePath = GetActivePath();
        if (!File.Exists(activePath))
        {
            return;
        }

        FileInfo activeInfo = new(activePath);
        if (activeInfo.Length == 0)
        {
            return;
        }

        if (activeInfo.Length + incomingLineBytes <= GetNormalizedActiveFileMaxBytes())
        {
            return;
        }

        string archivePath = CreateArchivePath();
        File.Move(activePath, archivePath);
    }

    private async Task EnforceRetentionAsync(CancellationToken cancellationToken)
    {
        string directory = GetDirectoryPath();
        if (!Directory.Exists(directory))
        {
            return;
        }

        DateTimeOffset nowUtc = DateTimeOffset.UtcNow;
        int retentionDays = GetNormalizedRetentionDays();
        if (retentionDays > 0)
        {
            DateTime cutoff = nowUtc.AddDays(-retentionDays).UtcDateTime;
            foreach (string path in GetRetainedFilesNewestFirst())
            {
                FileInfo info = new(path);
                if (info.Exists && info.LastWriteTimeUtc < cutoff)
                {
                    info.Delete();
                }
            }
        }

        string activePath = GetActivePath();
        string[] archives = GetArchivePathsNewestFirst();
        int maxArchivedFiles = GetNormalizedMaxArchivedFiles();
        if (archives.Length > maxArchivedFiles)
        {
            for (int i = maxArchivedFiles; i < archives.Length; i++)
            {
                if (File.Exists(archives[i]))
                {
                    File.Delete(archives[i]);
                }
            }
        }

        if (File.Exists(activePath))
        {
            FileInfo active = new(activePath);
            if (active.Length == 0 && archives.Length > 0)
            {
                active.Delete();
            }
        }
    }

    private string[] GetRetainedFilesNewestFirst()
    {
        string activePath = GetActivePath();
        string[] archives = GetArchivePathsNewestFirst();
        bool activeExists = File.Exists(activePath);
        if (!activeExists)
        {
            return archives;
        }

        string[] result = new string[archives.Length + 1];
        result[0] = activePath;
        archives.CopyTo(result, 1);
        return result;
    }

    private string[] GetArchivePathsNewestFirst()
    {
        string directory = GetDirectoryPath();
        if (!Directory.Exists(directory))
        {
            return [];
        }

        return Directory.EnumerateFiles(directory, GetArchiveSearchPattern(), SearchOption.TopDirectoryOnly)
            .OrderByDescending(path => Path.GetFileName(path), StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private string CreateArchivePath()
    {
        string directory = GetDirectoryPath();
        string fileNameWithoutExtension = Path.GetFileNameWithoutExtension(storageOptions.TelemetryLogFileName);
        string extension = Path.GetExtension(storageOptions.TelemetryLogFileName);
        string timestamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmssfff");
        string candidate = Path.Combine(directory, $"{fileNameWithoutExtension}-{timestamp}{extension}");
        int suffix = 1;
        while (File.Exists(candidate))
        {
            candidate = Path.Combine(directory, $"{fileNameWithoutExtension}-{timestamp}-{suffix:D2}{extension}");
            suffix++;
        }

        return candidate;
    }

    private string GetArchiveSearchPattern()
        => $"{Path.GetFileNameWithoutExtension(storageOptions.TelemetryLogFileName)}-*{Path.GetExtension(storageOptions.TelemetryLogFileName)}";

    private string GetActivePath()
        => Path.Combine(storageOptions.DataRoot, storageOptions.TelemetryLogFileName);

    private string GetDirectoryPath()
        => Path.GetDirectoryName(GetActivePath())!;

    private long GetNormalizedActiveFileMaxBytes()
        => _telemetryOptions.ActiveFileMaxBytes <= 0 ? 1 * 1024 * 1024 : _telemetryOptions.ActiveFileMaxBytes;

    private int GetNormalizedRetentionDays()
        => _telemetryOptions.RetentionDays < 0 ? 0 : _telemetryOptions.RetentionDays;

    private int GetNormalizedMaxArchivedFiles()
        => _telemetryOptions.MaxArchivedFiles < 0 ? 0 : _telemetryOptions.MaxArchivedFiles;

    private int GetNormalizedExportMaxEntries()
        => _telemetryOptions.ExportMaxEntries <= 0 ? 5000 : _telemetryOptions.ExportMaxEntries;

    private static IReadOnlyList<AdminPkcs11TelemetryEntry> SortEntries(IEnumerable<AdminPkcs11TelemetryEntry> entries)
        => entries
            .OrderByDescending(entry => entry.TimestampUtc)
            .ThenBy(entry => entry.DeviceName, StringComparer.Ordinal)
            .ThenBy(entry => entry.OperationName, StringComparer.Ordinal)
            .ToArray();

    private static AdminPkcs11TelemetryEntry DeserializeEntry(string line, string path)
    {
        try
        {
            return JsonSerializer.Deserialize(line, AdminJsonContext.Default.AdminPkcs11TelemetryEntry)
                ?? throw new InvalidOperationException($"Telemetry log '{path}' contains an unreadable JSON line.");
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException($"Telemetry log '{path}' contains an unreadable JSON line.", ex);
        }
    }
}
