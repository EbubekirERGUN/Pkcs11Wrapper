using System.Text.RegularExpressions;
using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;

namespace Pkcs11Wrapper.Admin.Web.Security;

public sealed class LocalAdminSecurityService(
    LocalAdminUserStore userStore,
    AuditLogService auditLog,
    IAdminAuthorizationService authorization,
    IAdminActorContext actorContext)
{
    private static readonly Regex UserNamePattern = new("^[a-zA-Z0-9._-]{3,64}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);
    private static readonly HashSet<string> AllowedRoles = new(StringComparer.Ordinal)
    {
        AdminRoles.Viewer,
        AdminRoles.Operator,
        AdminRoles.Admin
    };

    public async Task<LocalAdminSecuritySnapshot> GetSnapshotAsync(CancellationToken cancellationToken = default)
    {
        authorization.DemandAdmin();
        AdminActorInfo actor = actorContext.GetCurrent();
        IReadOnlyList<AdminWebUserRecord> records = await userStore.GetAllAsync(cancellationToken);
        BootstrapCredentialStatus bootstrap = await userStore.GetBootstrapStatusAsync(cancellationToken);
        LocalAdminUserSummary[] users = records
            .OrderBy(x => x.UserName, StringComparer.OrdinalIgnoreCase)
            .Select(record => new LocalAdminUserSummary(
                record.UserName,
                record.Roles.OrderBy(static role => role, StringComparer.Ordinal).ToArray(),
                record.CreatedUtc,
                string.Equals(record.UserName, actor.Name, StringComparison.OrdinalIgnoreCase),
                bootstrap.NoticeExists && string.Equals(record.UserName, bootstrap.UserName, StringComparison.OrdinalIgnoreCase)))
            .ToArray();

        return new(actor.Name, users, bootstrap);
    }

    public async Task CreateUserAsync(CreateLocalAdminUserRequest request, CancellationToken cancellationToken = default)
    {
        authorization.DemandAdmin();
        ArgumentNullException.ThrowIfNull(request);

        string userName = ValidateUserName(request.UserName);
        string password = ValidatePassword(request.Password);
        IReadOnlyList<string> roles = NormalizeRoles(request.Roles);

        try
        {
            await userStore.CreateUserAsync(userName, password, roles, cancellationToken);
            await auditLog.WriteAsync("AdminUsers", "Create", userName, "Success", $"Created local admin user with roles: {string.Join(", ", roles)}.", cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            await auditLog.WriteAsync("AdminUsers", "Create", userName, "Failure", ex.Message, cancellationToken: cancellationToken);
            throw;
        }
    }

    public async Task UpdateRolesAsync(UpdateLocalAdminUserRolesRequest request, CancellationToken cancellationToken = default)
    {
        authorization.DemandAdmin();
        ArgumentNullException.ThrowIfNull(request);

        AdminActorInfo actor = actorContext.GetCurrent();
        string userName = ValidateUserName(request.UserName);
        if (string.Equals(actor.Name, userName, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Current signed-in admin cannot change their own roles from this screen.");
        }

        IReadOnlyList<string> roles = NormalizeRoles(request.Roles);

        try
        {
            await userStore.UpdateRolesAsync(userName, roles, cancellationToken);
            await auditLog.WriteAsync("AdminUsers", "UpdateRoles", userName, "Success", $"Updated roles to: {string.Join(", ", roles)}.", cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            await auditLog.WriteAsync("AdminUsers", "UpdateRoles", userName, "Failure", ex.Message, cancellationToken: cancellationToken);
            throw;
        }
    }

    public async Task RotatePasswordAsync(RotateLocalAdminPasswordRequest request, CancellationToken cancellationToken = default)
    {
        authorization.DemandAdmin();
        ArgumentNullException.ThrowIfNull(request);

        string userName = ValidateUserName(request.UserName);
        string password = ValidatePassword(request.NewPassword);

        try
        {
            await userStore.RotatePasswordAsync(userName, password, cancellationToken);
            await auditLog.WriteAsync("AdminUsers", "RotatePassword", userName, "Success", "Rotated local user password.", cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            await auditLog.WriteAsync("AdminUsers", "RotatePassword", userName, "Failure", ex.Message, cancellationToken: cancellationToken);
            throw;
        }
    }

    public async Task DeleteUserAsync(string userName, CancellationToken cancellationToken = default)
    {
        authorization.DemandAdmin();

        AdminActorInfo actor = actorContext.GetCurrent();
        string normalizedUserName = ValidateUserName(userName);
        if (string.Equals(actor.Name, normalizedUserName, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Current signed-in admin cannot delete their own account from this screen.");
        }

        try
        {
            await userStore.DeleteUserAsync(normalizedUserName, cancellationToken);
            await auditLog.WriteAsync("AdminUsers", "Delete", normalizedUserName, "Success", "Deleted local user.", cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            await auditLog.WriteAsync("AdminUsers", "Delete", normalizedUserName, "Failure", ex.Message, cancellationToken: cancellationToken);
            throw;
        }
    }

    public async Task RetireBootstrapNoticeAsync(CancellationToken cancellationToken = default)
    {
        authorization.DemandAdmin();

        try
        {
            await userStore.RetireBootstrapNoticeAsync(cancellationToken);
            await auditLog.WriteAsync("AdminUsers", "RetireBootstrapNotice", "bootstrap-admin.txt", "Success", "Retired bootstrap credential notice.", cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            await auditLog.WriteAsync("AdminUsers", "RetireBootstrapNotice", "bootstrap-admin.txt", "Failure", ex.Message, cancellationToken: cancellationToken);
            throw;
        }
    }

    private static string ValidateUserName(string? value)
    {
        string userName = value?.Trim() ?? string.Empty;
        if (!UserNamePattern.IsMatch(userName))
        {
            throw new ArgumentException("Username must be 3-64 chars and use only letters, digits, dot, dash, or underscore.", nameof(value));
        }

        return userName;
    }

    private static string ValidatePassword(string? value)
    {
        string password = value ?? string.Empty;
        if (password.Length < 12)
        {
            throw new ArgumentException("Password must be at least 12 characters long.", nameof(value));
        }

        return password;
    }

    private static IReadOnlyList<string> NormalizeRoles(IEnumerable<string>? roles)
    {
        if (roles is null)
        {
            throw new ArgumentException("At least one role is required.", nameof(roles));
        }

        string[] normalized = roles
            .Select(role => role.Trim().ToLowerInvariant())
            .Where(role => !string.IsNullOrWhiteSpace(role))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static role => role, StringComparer.Ordinal)
            .ToArray();

        if (normalized.Length == 0)
        {
            throw new ArgumentException("At least one role is required.", nameof(roles));
        }

        if (normalized.Any(role => !AllowedRoles.Contains(role)))
        {
            throw new ArgumentException("Roles must be limited to viewer, operator, and admin.", nameof(roles));
        }

        return normalized;
    }
}
