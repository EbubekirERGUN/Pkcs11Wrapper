using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Web.Security;

public sealed record LocalAdminUserSummary(
    string Username,
    IReadOnlyList<string> Roles,
    DateTimeOffset CreatedUtc,
    bool IsCurrentUser,
    bool IsBootstrapNoticeUser);

public sealed record BootstrapCredentialStatus(
    bool NoticeExists,
    string NoticePath,
    DateTimeOffset? LastModifiedUtc,
    string? UserName);

public sealed record LocalAdminSecuritySnapshot(
    string CurrentUserName,
    IReadOnlyList<LocalAdminUserSummary> Users,
    BootstrapCredentialStatus BootstrapStatus);

public sealed class CreateLocalAdminUserRequest
{
    public string UserName { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    public List<string> Roles { get; set; } = [];
}

public sealed class UpdateLocalAdminUserRolesRequest
{
    public string UserName { get; set; } = string.Empty;

    public List<string> Roles { get; set; } = [];
}

public sealed class RotateLocalAdminPasswordRequest
{
    public string UserName { get; set; } = string.Empty;

    public string NewPassword { get; set; } = string.Empty;
}
