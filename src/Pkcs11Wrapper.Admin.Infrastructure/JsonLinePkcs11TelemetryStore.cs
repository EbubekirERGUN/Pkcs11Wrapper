using System.Text;
using System.Text.Json;
using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Infrastructure;

public sealed class JsonLinePkcs11TelemetryStore(AdminStorageOptions options) : IPkcs11TelemetryStore
{
    private readonly SemaphoreSlim _mutex = new(1, 1);

    public async Task AppendAsync(AdminPkcs11TelemetryEntry entry, CancellationToken cancellationToken = default)
    {
        await _mutex.WaitAsync(cancellationToken);
        try
        {
            string path = GetPath();
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);

            string line = JsonSerializer.Serialize(entry, AdminJsonContext.Default.AdminPkcs11TelemetryEntry) + Environment.NewLine;

            await using FileStream stream = new(path, FileMode.Append, FileAccess.Write, FileShare.Read, 64 * 1024, FileOptions.Asynchronous);
            await using StreamWriter writer = new(stream, Encoding.UTF8, leaveOpen: true);
            await writer.WriteAsync(line.AsMemory(), cancellationToken);
            await writer.FlushAsync(cancellationToken);
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

    private string GetPath() => Path.Combine(options.DataRoot, options.TelemetryLogFileName);

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
        StringBuilder reversed = new();
        bool skippedTrailingNewline = false;

        while (position > 0 && lines.Count < take)
        {
            int bytesToRead = (int)Math.Min(buffer.Length, position);
            position -= bytesToRead;
            stream.Position = position;
            int read = await stream.ReadAsync(buffer.AsMemory(0, bytesToRead), cancellationToken);

            for (int index = read - 1; index >= 0; index--)
            {
                char current = (char)buffer[index];
                if (current == '\n')
                {
                    if (!skippedTrailingNewline && reversed.Length == 0)
                    {
                        skippedTrailingNewline = true;
                        continue;
                    }

                    AddCompletedLine(lines, reversed);
                    if (lines.Count >= take)
                    {
                        break;
                    }

                    skippedTrailingNewline = true;
                }
                else
                {
                    reversed.Append(current);
                }
            }
        }

        if (lines.Count < take && reversed.Length > 0)
        {
            AddCompletedLine(lines, reversed);
        }

        return lines;
    }

    private static void AddCompletedLine(List<string> lines, StringBuilder reversed)
    {
        if (reversed.Length == 0)
        {
            return;
        }

        char[] chars = new char[reversed.Length];
        for (int i = 0; i < reversed.Length; i++)
        {
            chars[i] = reversed[reversed.Length - 1 - i];
        }

        string line = new string(chars).TrimEnd('\r');
        reversed.Clear();
        if (!string.IsNullOrWhiteSpace(line))
        {
            lines.Add(line);
        }
    }
}
