using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Infrastructure;

namespace Pkcs11Wrapper.Admin.Web.Security;

public sealed class LocalAdminUserStore(AdminStorageOptions options)
{
    private readonly SemaphoreSlim _mutex = new(1, 1);
    private readonly PasswordHasher<AdminWebUserRecord> _hasher = new();

    public async Task<AdminWebUserRecord?> ValidateCredentialsAsync(string username, string password)
    {
        await _mutex.WaitAsync();
        try
        {
            AdminWebUserRecord? user = (await ReadAllCoreAsync()).FirstOrDefault(x => string.Equals(x.Username, username, StringComparison.OrdinalIgnoreCase));
            if (user is null)
            {
                return null;
            }

            PasswordVerificationResult result = _hasher.VerifyHashedPassword(user, user.PasswordHash, password);
            return result == PasswordVerificationResult.Failed ? null : user;
        }
        finally
        {
            _mutex.Release();
        }
    }

    public async Task EnsureSeedDataAsync()
    {
        await _mutex.WaitAsync();
        try
        {
            List<AdminWebUserRecord> users = await ReadAllCoreAsync();
            if (users.Count != 0)
            {
                return;
            }

            string bootstrapPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(12));
            AdminWebUserRecord admin = new(
                "admin",
                string.Empty,
                [AdminRoles.Admin],
                DateTimeOffset.UtcNow);

            admin = admin with { PasswordHash = _hasher.HashPassword(admin, bootstrapPassword) };
            users.Add(admin);
            await WriteAllCoreAsync(users);

            string noticePath = Path.Combine(options.DataRoot, "bootstrap-admin.txt");
            await File.WriteAllTextAsync(noticePath, $"Initial admin credentials\nusername=admin\npassword={bootstrapPassword}\nRotate this file and create a new admin credential before broader exposure.\n");
        }
        finally
        {
            _mutex.Release();
        }
    }

    private async Task<List<AdminWebUserRecord>> ReadAllCoreAsync()
    {
        string path = GetPath();
        if (!File.Exists(path))
        {
            return [];
        }

        await using FileStream stream = File.OpenRead(path);
        return await JsonSerializer.DeserializeAsync(stream, AdminWebJsonContext.Default.ListAdminWebUserRecord) ?? [];
    }

    private async Task WriteAllCoreAsync(List<AdminWebUserRecord> users)
    {
        string path = GetPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await using FileStream stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, users, AdminWebJsonContext.Default.ListAdminWebUserRecord);
    }

    private string GetPath() => Path.Combine(options.DataRoot, "admin-users.json");
}
