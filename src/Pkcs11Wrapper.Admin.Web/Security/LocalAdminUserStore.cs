using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Infrastructure;

namespace Pkcs11Wrapper.Admin.Web.Security;

public sealed class LocalAdminUserStore(IOptions<AdminStorageOptions> options)
{
    private readonly PasswordHasher<AdminWebUserRecord> _passwordHasher = new();
    private readonly SemaphoreSlim _gate = new(1, 1);

    public async Task<(bool Success, AdminWebUserRecord? User)> ValidateCredentialsAsync(string? userName, string? password, CancellationToken cancellationToken = default)
    {
        string normalizedUserName = NormalizeUserName(userName);
        string providedPassword = password ?? string.Empty;
        if (string.IsNullOrWhiteSpace(normalizedUserName) || string.IsNullOrEmpty(providedPassword))
        {
            return (false, null);
        }

        await EnsureSeedDataAsync(cancellationToken);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            List<AdminWebUserRecord> users = await ReadUsersUnsafeAsync(cancellationToken);
            int index = users.FindIndex(record => string.Equals(record.UserName, normalizedUserName, StringComparison.OrdinalIgnoreCase));
            if (index < 0)
            {
                return (false, null);
            }

            AdminWebUserRecord user = users[index];
            PasswordVerificationResult verification = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash, providedPassword);
            if (verification == PasswordVerificationResult.Failed)
            {
                return (false, null);
            }

            if (verification == PasswordVerificationResult.SuccessRehashNeeded)
            {
                AdminWebUserRecord updated = user with { PasswordHash = _passwordHasher.HashPassword(user, providedPassword) };
                users[index] = updated;
                await SaveUsersUnsafeAsync(users, cancellationToken);
                user = updated;
            }

            return (true, Clone(user));
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<AdminWebUserRecord>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        await EnsureSeedDataAsync(cancellationToken);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            return (await ReadUsersUnsafeAsync(cancellationToken)).Select(Clone).ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<BootstrapCredentialStatus> GetBootstrapStatusAsync(CancellationToken cancellationToken = default)
    {
        await EnsureSeedDataAsync(cancellationToken);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            FileInfo file = new(BootstrapNoticePath);
            if (!file.Exists)
            {
                return new(false, BootstrapNoticePath, null, null);
            }

            string? userName = await TryReadBootstrapUserNameUnsafeAsync(cancellationToken);
            return new(true, BootstrapNoticePath, file.LastWriteTimeUtc, userName);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<AdminWebUserRecord> CreateUserAsync(string userName, string password, IReadOnlyList<string> roles, CancellationToken cancellationToken = default)
    {
        await EnsureSeedDataAsync(cancellationToken);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            List<AdminWebUserRecord> users = await ReadUsersUnsafeAsync(cancellationToken);
            string normalizedUserName = NormalizeUserName(userName);
            if (users.Any(record => string.Equals(record.UserName, normalizedUserName, StringComparison.OrdinalIgnoreCase)))
            {
                throw new InvalidOperationException($"Local admin user '{normalizedUserName}' already exists.");
            }

            string[] normalizedRoles = NormalizeRoles(roles);
            AdminWebUserRecord created = new(
                normalizedUserName,
                string.Empty,
                normalizedRoles,
                DateTimeOffset.UtcNow);
            created = created with { PasswordHash = _passwordHasher.HashPassword(created, password) };
            users.Add(created);
            await SaveUsersUnsafeAsync(users, cancellationToken);
            return Clone(created);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<AdminWebUserRecord> UpdateRolesAsync(string userName, IReadOnlyList<string> roles, CancellationToken cancellationToken = default)
    {
        await EnsureSeedDataAsync(cancellationToken);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            List<AdminWebUserRecord> users = await ReadUsersUnsafeAsync(cancellationToken);
            int index = FindUserIndex(users, userName);
            string[] normalizedRoles = NormalizeRoles(roles);
            users[index] = users[index] with { Roles = normalizedRoles };
            EnsureAtLeastOneAdmin(users);
            await SaveUsersUnsafeAsync(users, cancellationToken);
            return Clone(users[index]);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<AdminWebUserRecord> RotatePasswordAsync(string userName, string password, CancellationToken cancellationToken = default)
    {
        await EnsureSeedDataAsync(cancellationToken);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            List<AdminWebUserRecord> users = await ReadUsersUnsafeAsync(cancellationToken);
            int index = FindUserIndex(users, userName);
            AdminWebUserRecord current = users[index];
            users[index] = current with { PasswordHash = _passwordHasher.HashPassword(current, password) };
            await SaveUsersUnsafeAsync(users, cancellationToken);
            return Clone(users[index]);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task DeleteUserAsync(string userName, CancellationToken cancellationToken = default)
    {
        await EnsureSeedDataAsync(cancellationToken);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            List<AdminWebUserRecord> users = await ReadUsersUnsafeAsync(cancellationToken);
            int index = FindUserIndex(users, userName);
            users.RemoveAt(index);
            EnsureAtLeastOneAdmin(users);
            await SaveUsersUnsafeAsync(users, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task RetireBootstrapNoticeAsync(CancellationToken cancellationToken = default)
    {
        await EnsureSeedDataAsync(cancellationToken);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (File.Exists(BootstrapNoticePath))
            {
                File.Delete(BootstrapNoticePath);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task EnsureSeedDataAsync(CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(StorageRoot);
        if (File.Exists(UserFilePath))
        {
            return;
        }

        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (File.Exists(UserFilePath))
            {
                return;
            }

            string password = GenerateBootstrapPassword();
            DateTimeOffset createdUtc = DateTimeOffset.UtcNow;
            AdminWebUserRecord admin = new(
                "admin",
                string.Empty,
                [AdminRoles.Admin, AdminRoles.Operator, AdminRoles.Viewer],
                createdUtc);
            admin = admin with { PasswordHash = _passwordHasher.HashPassword(admin, password) };

            await SaveUsersUnsafeAsync([admin], cancellationToken);
            string bootstrap = $"""
Pkcs11Wrapper Admin bootstrap credential
======================================
username: admin
password: {password}
generated_utc: {createdUtc:O}

Rotate this password after first sign-in and then retire this file.
""";
            await CrashSafeFileStore.WriteTextAsync(BootstrapNoticePath, bootstrap, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<List<AdminWebUserRecord>> ReadUsersUnsafeAsync(CancellationToken cancellationToken)
        => (await CrashSafeFileStore.ReadJsonAsync(UserFilePath, AdminWebJsonContext.Default.AdminWebUserRecordArray, cancellationToken) ?? []).Select(Clone).ToList();

    private Task SaveUsersUnsafeAsync(IReadOnlyList<AdminWebUserRecord> users, CancellationToken cancellationToken)
        => CrashSafeFileStore.WriteJsonAsync(UserFilePath, users.Select(Clone).ToArray(), AdminWebJsonContext.Default.AdminWebUserRecordArray, cancellationToken);

    private async Task<string?> TryReadBootstrapUserNameUnsafeAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(BootstrapNoticePath))
        {
            return null;
        }

        string[] lines = await File.ReadAllLinesAsync(BootstrapNoticePath, cancellationToken);
        foreach (string line in lines)
        {
            if (line.StartsWith("username:", StringComparison.OrdinalIgnoreCase))
            {
                return line["username:".Length..].Trim();
            }
        }

        return "admin";
    }

    private static int FindUserIndex(List<AdminWebUserRecord> users, string userName)
    {
        string normalizedUserName = NormalizeUserName(userName);
        int index = users.FindIndex(record => string.Equals(record.UserName, normalizedUserName, StringComparison.OrdinalIgnoreCase));
        if (index < 0)
        {
            throw new InvalidOperationException($"Local admin user '{normalizedUserName}' was not found.");
        }

        return index;
    }

    private static void EnsureAtLeastOneAdmin(IEnumerable<AdminWebUserRecord> users)
    {
        if (!users.Any(record => record.Roles.Contains(AdminRoles.Admin, StringComparer.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("At least one local admin user must retain the admin role.");
        }
    }

    private static string NormalizeUserName(string? value)
        => value?.Trim() ?? string.Empty;

    private static string[] NormalizeRoles(IEnumerable<string> roles)
        => roles
            .Select(role => role.Trim().ToLowerInvariant())
            .Where(role => !string.IsNullOrWhiteSpace(role))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static role => role, StringComparer.Ordinal)
            .ToArray();

    private static AdminWebUserRecord Clone(AdminWebUserRecord record)
        => record with { Roles = [.. record.Roles] };

    private string StorageRoot => ResolveStorageRoot(options.Value);

    private string UserFilePath => Path.Combine(StorageRoot, "admin-users.json");

    private string BootstrapNoticePath => Path.Combine(StorageRoot, "bootstrap-admin.txt");

    private static string ResolveStorageRoot(AdminStorageOptions options)
    {
        foreach (string propertyName in new[] { "DataRoot", "RootPath", "Path", "StorageRootPath", "BasePath", "DataPath" })
        {
            object? value = typeof(AdminStorageOptions).GetProperty(propertyName)?.GetValue(options);
            if (value is string path && !string.IsNullOrWhiteSpace(path))
            {
                return path;
            }
        }

        return Path.Combine(AppContext.BaseDirectory, "App_Data");
    }

    private static string GenerateBootstrapPassword()
        => Convert.ToBase64String(Guid.NewGuid().ToByteArray())
            .Replace("/", "A", StringComparison.Ordinal)
            .Replace("+", "B", StringComparison.Ordinal)
            .Replace("=", "9", StringComparison.Ordinal);
}
