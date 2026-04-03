using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Infrastructure;

public sealed class JsonLineAuditLogStore(AdminStorageOptions options) : IAuditLogStore
{
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private AuditTailState? _tailState;

    public async Task AppendAsync(AdminAuditLogEntry entry, CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            string path = GetPath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);

            _tailState ??= await ReadTailStateAsync(path, cancellationToken);
            AdminAuditLogEntry normalized = CreateNormalizedEntry(entry, _tailState);
            string line = JsonSerializer.Serialize(normalized, AdminJsonContext.Default.AdminAuditLogEntry) + Environment.NewLine;

            await using FileStream stream = new(path, FileMode.Append, FileAccess.Write, FileShare.Read, 64 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough);
            await using StreamWriter writer = new(stream, Utf8NoBom, leaveOpen: true);
            await writer.WriteAsync(line.AsMemory(), cancellationToken);
            await writer.FlushAsync(cancellationToken);
            await stream.FlushAsync(cancellationToken);
            stream.Flush(flushToDisk: true);

            _tailState = new AuditTailState(normalized.Sequence, normalized.EntryHash);
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

            return (await ReadTailLinesAsync(path, Math.Max(1, take), cancellationToken))
                .Select(line => DeserializeEntry(line, path))
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

            await using FileStream stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using StreamReader reader = new(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            AdminAuditLogEntry? previous = null;
            int checkedEntries = 0;

            while (await reader.ReadLineAsync(cancellationToken) is { } line)
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                AdminAuditLogEntry entry;
                try
                {
                    entry = DeserializeEntry(line, path);
                }
                catch (InvalidOperationException ex)
                {
                    return new AuditIntegrityStatus(false, checkedEntries, previous?.Sequence.ToString(), "Audit chain contains an unreadable entry.", ex.Message);
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

            _tailState = previous is null ? null : new AuditTailState(previous.Sequence, previous.EntryHash);
            return new AuditIntegrityStatus(true, checkedEntries, previous?.Sequence.ToString(), $"Verified {checkedEntries} chained audit entr{(checkedEntries == 1 ? "y" : "ies") }.", null);
        }
        finally
        {
            _mutex.Release();
        }
    }

    private string GetPath() => Path.Combine(options.DataRoot, options.AuditLogFileName);

    private static AdminAuditLogEntry CreateNormalizedEntry(AdminAuditLogEntry entry, AuditTailState? previous)
    {
        AdminAuditLogEntry candidate = entry with
        {
            Sequence = (previous?.Sequence ?? 0) + 1,
            PreviousHash = previous?.EntryHash ?? "GENESIS",
            EntryHash = string.Empty,
            ActorRoles = entry.ActorRoles.OrderBy(x => x, StringComparer.Ordinal).ToArray()
        };

        return candidate with { EntryHash = ComputeHash(candidate) };
    }

    private static AdminAuditLogEntry DeserializeEntry(string line, string path)
    {
        try
        {
            return JsonSerializer.Deserialize(line, AdminJsonContext.Default.AdminAuditLogEntry)
                ?? throw new InvalidOperationException($"Audit log '{path}' contains an unreadable JSON line.");
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException($"Audit log '{path}' contains an unreadable JSON line.", ex);
        }
    }

    private static async Task<AuditTailState?> ReadTailStateAsync(string path, CancellationToken cancellationToken)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        IReadOnlyList<string> lines = await ReadTailLinesAsync(path, 1, cancellationToken);
        if (lines.Count == 0)
        {
            return null;
        }

        AdminAuditLogEntry lastEntry = DeserializeEntry(lines[0], path);
        return new AuditTailState(lastEntry.Sequence, lastEntry.EntryHash);
    }

    private static async Task<IReadOnlyList<string>> ReadTailLinesAsync(string path, int take, CancellationToken cancellationToken)
    {
        List<string> lines = [];
        await using FileStream stream = File.Open(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (stream.Length == 0)
        {
            return lines;
        }

        long position = stream.Length;
        byte[] buffer = new byte[4096];
        List<byte> reversedLineBytes = [];
        bool skippedTrailingNewline = false;

        while (position > 0 && lines.Count < take)
        {
            int bytesToRead = (int)Math.Min(buffer.Length, position);
            position -= bytesToRead;
            stream.Position = position;
            int read = await stream.ReadAsync(buffer.AsMemory(0, bytesToRead), cancellationToken);

            for (int index = read - 1; index >= 0; index--)
            {
                byte current = buffer[index];
                if (current == (byte)'\n')
                {
                    if (!skippedTrailingNewline && reversedLineBytes.Count == 0)
                    {
                        skippedTrailingNewline = true;
                        continue;
                    }

                    AddCompletedLine(lines, reversedLineBytes);
                    if (lines.Count >= take)
                    {
                        break;
                    }

                    skippedTrailingNewline = true;
                }
                else
                {
                    reversedLineBytes.Add(current);
                }
            }
        }

        if (lines.Count < take && reversedLineBytes.Count > 0)
        {
            AddCompletedLine(lines, reversedLineBytes);
        }

        return lines;
    }

    private static void AddCompletedLine(List<string> lines, List<byte> reversedLineBytes)
    {
        if (reversedLineBytes.Count == 0)
        {
            return;
        }

        byte[] bytes = new byte[reversedLineBytes.Count];
        for (int i = 0; i < reversedLineBytes.Count; i++)
        {
            bytes[i] = reversedLineBytes[reversedLineBytes.Count - 1 - i];
        }

        string line = StripLeadingByteOrderMark(Encoding.UTF8.GetString(bytes)).TrimEnd('\r');
        reversedLineBytes.Clear();
        if (!string.IsNullOrWhiteSpace(line))
        {
            lines.Add(line);
        }
    }

    private static string StripLeadingByteOrderMark(string line)
        => line.Length > 0 && line[0] == '\uFEFF'
            ? line[1..]
            : line;

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

    private sealed record AuditTailState(long Sequence, string EntryHash);
}
