using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Pkcs11Wrapper.Admin.Infrastructure;

public static class CrashSafeFileStore
{
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    public static async Task<T?> ReadJsonAsync<T>(string path, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(path))
        {
            return default;
        }

        try
        {
            await using FileStream stream = File.OpenRead(path);
            T? value = await JsonSerializer.DeserializeAsync(stream, typeInfo, cancellationToken);
            if (value is null)
            {
                throw new InvalidOperationException(CreateCorruptionMessage(path));
            }

            return value;
        }
        catch (InvalidOperationException ex) when (!string.Equals(ex.Message, CreateCorruptionMessage(path), StringComparison.Ordinal))
        {
            throw new InvalidOperationException(CreateCorruptionMessage(path), ex);
        }
        catch (JsonException ex)
        {
            throw new InvalidOperationException(CreateCorruptionMessage(path), ex);
        }
    }

    public static async Task WriteJsonAsync<T>(string path, T value, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string tempPath = CreateTempPath(path);

        try
        {
            await using (FileStream stream = CreateWriteThroughStream(tempPath))
            {
                await JsonSerializer.SerializeAsync(stream, value, typeInfo, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }

            PromoteTempFile(path, tempPath);
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    public static async Task WriteTextAsync(string path, string content, CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        string tempPath = CreateTempPath(path);

        try
        {
            await using (FileStream stream = CreateWriteThroughStream(tempPath))
            await using (StreamWriter writer = new(stream, Utf8NoBom, leaveOpen: true))
            {
                await writer.WriteAsync(content.AsMemory(), cancellationToken);
                await writer.FlushAsync(cancellationToken);
                await stream.FlushAsync(cancellationToken);
                stream.Flush(flushToDisk: true);
            }

            PromoteTempFile(path, tempPath);
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    public static string GetBackupPath(string path)
        => $"{path}.bak";

    public static void PromoteTempFile(string destinationPath, string tempPath)
        => PromoteTempFile(destinationPath, tempPath, onBeforeMove: null);

    private static FileStream CreateWriteThroughStream(string path)
        => new(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.WriteThrough);

    internal static void PromoteTempFile(string destinationPath, string tempPath, Action? onBeforeMove)
    {
        string backupPath = GetBackupPath(destinationPath);
        if (File.Exists(destinationPath))
        {
            try
            {
                File.Replace(tempPath, destinationPath, backupPath, ignoreMetadataErrors: true);
                return;
            }
            catch (FileNotFoundException) when (!File.Exists(destinationPath))
            {
                // Another writer/process removed the destination after our existence check.
                // Fall through to the create path below and keep the temp payload intact.
            }
        }

        onBeforeMove?.Invoke();

        try
        {
            File.Move(tempPath, destinationPath);
        }
        catch (IOException) when (File.Exists(destinationPath))
        {
            File.Replace(tempPath, destinationPath, backupPath, ignoreMetadataErrors: true);
        }
    }

    private static string CreateTempPath(string destinationPath)
        => $"{destinationPath}.tmp-{Guid.NewGuid():N}";

    private static void TryDelete(string path)
    {
        if (File.Exists(path))
        {
            File.Delete(path);
        }
    }

    private static string CreateCorruptionMessage(string path)
        => $"Admin data file '{path}' is unreadable or corrupt. Recover from backup '{GetBackupPath(path)}' or replace the file with a valid export.";
}
