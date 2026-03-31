using System.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Infrastructure;

public sealed class JsonLineAuditLogStore(AdminStorageOptions options) : IAuditLogStore
{
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public async Task AppendAsync(AdminAuditLogEntry entry, CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            string path = GetPath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            AdminAuditLogEntry normalized = await CreateNormalizedEntryAsync(path, entry, cancellationToken);
            string line = JsonSerializer.Serialize(normalized, AdminJsonContext.Default.AdminAuditLogEntry) + Environment.NewLine;
            await File.AppendAllTextAsync(path, line, Encoding.UTF8, cancellationToken);
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<IReadOnlyList<AdminAuditLogEntry>> ReadRecentAsync(int take, CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            string path = GetPath();
            if (!File.Exists(path))
            {
                return [];
            }

            string[] lines = await File.ReadAllLinesAsync(path, cancellationToken);
            return lines
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Reverse()
                .Take(Math.Max(1, take))
                .Select(line => JsonSerializer.Deserialize(line, AdminJsonContext.Default.AdminAuditLogEntry))
                .OfType<AdminAuditLogEntry>()
                .ToArray();
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task<AuditIntegrityStatus> VerifyIntegrityAsync(CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            string path = GetPath();
            if (!File.Exists(path))
            {
                return new AuditIntegrityStatus(true, 0, null, "Audit log is empty.", null);
            }

            string[] lines = await File.ReadAllLinesAsync(path, cancellationToken);
            AdminAuditLogEntry? previous = null;
            int checkedEntries = 0;

            foreach (string line in lines.Where(x => !string.IsNullOrWhiteSpace(x)))
            {
                AdminAuditLogEntry? entry = JsonSerializer.Deserialize(line, AdminJsonContext.Default.AdminAuditLogEntry);
                if (entry is null)
                {
                    return new AuditIntegrityStatus(false, checkedEntries, previous?.Sequence.ToString(), "Audit chain contains an unreadable entry.", "Unreadable audit JSON line.");
                }

                checkedEntries++;
                string expectedPreviousHash = previous?.EntryHash ?? "GENESIS";
                if (!string.Equals(entry.PreviousHash, expectedPreviousHash, StringComparison.Ordinal))
                {
                    return new AuditIntegrityStatus(false, checkedEntries, entry.Sequence.ToString(), "Audit chain is broken.", $"Entry {entry.Sequence} previous-hash mismatch.");
                }

                string expectedHash = ComputeHash(entry with { EntryHash = string.Empty });
                if (!string.Equals(entry.EntryHash, expectedHash, StringComparison.Ordinal))
                {
                    return new AuditIntegrityStatus(false, checkedEntries, entry.Sequence.ToString(), "Audit chain hash verification failed.", $"Entry {entry.Sequence} hash mismatch.");
                }

                previous = entry;
            }

            return new AuditIntegrityStatus(true, checkedEntries, previous?.Sequence.ToString(), $"Verified {checkedEntries} chained audit entr{(checkedEntries == 1 ? "y" : "ies") }.", null);
        }
        finally
        {
            _mutex.Release();
        }
    }

    private string GetPath() => Path.Combine(options.DataRoot, options.AuditLogFileName);

    private static async Task<AdminAuditLogEntry> CreateNormalizedEntryAsync(string path, AdminAuditLogEntry entry, CancellationToken cancellationToken)
    {
        AdminAuditLogEntry? previous = null;
        if (File.Exists(path))
        {
            string[] lines = await File.ReadAllLinesAsync(path, cancellationToken);
            string? lastLine = lines.LastOrDefault(x => !string.IsNullOrWhiteSpace(x));
            if (!string.IsNullOrWhiteSpace(lastLine))
            {
                previous = JsonSerializer.Deserialize(lastLine, AdminJsonContext.Default.AdminAuditLogEntry);
            }
        }

        AdminAuditLogEntry candidate = entry with
        {
            Sequence = (previous?.Sequence ?? 0) + 1,
            PreviousHash = previous?.EntryHash ?? "GENESIS",
            EntryHash = string.Empty,
            ActorRoles = entry.ActorRoles.OrderBy(x => x, StringComparer.Ordinal).ToArray()
        };

        return candidate with { EntryHash = ComputeHash(candidate) };
    }

    private static string ComputeHash(AdminAuditLogEntry entry)
    {
        string canonical = string.Join('|',
            entry.Id,
            entry.TimestampUtc.ToUnixTimeMilliseconds(),
            entry.Actor,
            string.Join(',', entry.ActorRoles),
            entry.AuthenticationType,
            entry.Category,
            entry.Action,
            entry.Target,
            entry.Outcome,
            entry.Details,
            entry.Sequence,
            entry.PreviousHash,
            entry.RemoteIp,
            entry.SessionId,
            entry.UserAgent,
            entry.MachineName);

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
