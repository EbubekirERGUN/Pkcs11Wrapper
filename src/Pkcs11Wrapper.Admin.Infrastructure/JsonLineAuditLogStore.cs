using System.Text;
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
            string line = JsonSerializer.Serialize(entry, AdminJsonContext.Default.AdminAuditLogEntry) + Environment.NewLine;
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

    private string GetPath() => Path.Combine(options.DataRoot, options.AuditLogFileName);
}
