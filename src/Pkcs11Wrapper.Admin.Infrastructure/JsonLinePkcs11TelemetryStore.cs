using System.Text;
using System.Text.Json;
using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Infrastructure;

public sealed class JsonLinePkcs11TelemetryStore(AdminStorageOptions storageOptions, AdminPkcs11TelemetryOptions? telemetryOptions = null) : IPkcs11TelemetryStore
{
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
            await using StreamWriter writer = new(stream, Encoding.UTF8, leaveOpen: true);
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
            FileInfo[] retainedFiles = GetRetainedFilesNewestFirst().Select(path => new FileInfo(path)).ToArray();
            FileInfo? activeFile = retainedFiles.FirstOrDefault(file => string.Equals(file.FullName, activePath, StringComparison.Ordinal));

            return new(
                ActiveFileBytes: activeFile?.Exists == true ? activeFile.Length : 0,
                ArchivedFileCount: retainedFiles.Count(file => !string.Equals(file.FullName, activePath, StringComparison.Ordinal)),
                RetainedFileCount: retainedFiles.Length,
                RetainedBytes: retainedFiles.Where(file => file.Exists).Sum(file => file.Length),
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
        List<AdminPkcs11TelemetryEntry> entries = [];
        foreach (string path in GetRetainedFilesNewestFirst())
        {
            if (!File.Exists(path))
            {
                continue;
            }

            string[] lines = await File.ReadAllLinesAsync(path, cancellationToken);
            for (int index = lines.Length - 1; index >= 0; index--)
            {
                string line = lines[index].Trim();
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                entries.Add(DeserializeEntry(line, path));
                if (take.HasValue && entries.Count >= take.Value)
                {
                    return SortEntries(entries);
                }
            }
        }

        return SortEntries(entries);
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
        await Task.Run(() => File.Move(activePath, archivePath), cancellationToken);
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
            DateTimeOffset cutoff = nowUtc.AddDays(-retentionDays);
            foreach (string path in GetRetainedFilesNewestFirst())
            {
                FileInfo info = new(path);
                if (info.Exists && info.LastWriteTimeUtc < cutoff.UtcDateTime)
                {
                    await Task.Run(() => info.Delete(), cancellationToken);
                }
            }
        }

        string activePath = GetActivePath();
        string[] archives = GetArchivePathsNewestFirst();
        int maxArchivedFiles = GetNormalizedMaxArchivedFiles();
        if (archives.Length > maxArchivedFiles)
        {
            foreach (string path in archives.Skip(maxArchivedFiles))
            {
                if (File.Exists(path))
                {
                    await Task.Run(() => File.Delete(path), cancellationToken);
                }
            }
        }

        if (File.Exists(activePath))
        {
            FileInfo active = new(activePath);
            if (active.Length == 0 && GetArchivePathsNewestFirst().Length > 0)
            {
                await Task.Run(() => active.Delete(), cancellationToken);
            }
        }
    }

    private string[] GetRetainedFilesNewestFirst()
    {
        string activePath = GetActivePath();
        List<string> files = [];
        if (File.Exists(activePath))
        {
            files.Add(activePath);
        }

        files.AddRange(GetArchivePathsNewestFirst());
        return [.. files];
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
