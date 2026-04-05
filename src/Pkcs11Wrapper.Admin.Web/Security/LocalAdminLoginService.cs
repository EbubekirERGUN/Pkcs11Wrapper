using Pkcs11Wrapper.Admin.Application.Services;
using Pkcs11Wrapper.Admin.Application.Observability;

namespace Pkcs11Wrapper.Admin.Web.Security;

public sealed class LocalAdminLoginService(
    LocalAdminUserStore userStore,
    AuditLogService auditLog,
    LocalAdminLoginThrottleService throttle,
    AdminMetrics? metrics = null)
{
    public async Task<LocalAdminLoginResult> AttemptLoginAsync(string? userName, string? password, string? remoteIp, CancellationToken cancellationToken = default)
    {
        LocalAdminLoginThrottleStatus status = throttle.GetStatus(userName, remoteIp);
        string target = NormalizeTarget(userName);

        if (status.IsLocked)
        {
            string details = $"Login attempt throttled until {status.LockedUntilUtc:O}.";
            await auditLog.WriteAsync("Authentication", "Login", target, "Throttled", details, actor: target, cancellationToken: cancellationToken);
            metrics?.RecordLoginAttempt("throttled");
            return new(false, true, "locked", details, null, status.LockedUntilUtc);
        }

        (bool success, AdminWebUserRecord? user) = await userStore.ValidateCredentialsAsync(userName, password, cancellationToken);
        if (!success || user is null)
        {
            LocalAdminLoginThrottleStatus failureStatus = throttle.RecordFailure(userName, remoteIp);
            string details = failureStatus.IsLocked
                ? $"Invalid credentials. Lockout active until {failureStatus.LockedUntilUtc:O}."
                : "Invalid username or password.";
            await auditLog.WriteAsync("Authentication", "Login", target, failureStatus.IsLocked ? "Throttled" : "Failure", details, actor: target, cancellationToken: cancellationToken);
            metrics?.RecordLoginAttempt(failureStatus.IsLocked ? "throttled" : "failure");
            return new(false, failureStatus.IsLocked, failureStatus.IsLocked ? "locked" : "invalid", details, null, failureStatus.LockedUntilUtc);
        }

        throttle.RecordSuccess(user.UserName, remoteIp);
        await auditLog.WriteAsync("Authentication", "Login", user.UserName, "Success", "Local admin login succeeded.", actor: user.UserName, cancellationToken: cancellationToken);
        metrics?.RecordLoginAttempt("success");
        return new(true, false, string.Empty, "Login succeeded.", user, null);
    }

    public Task WriteLogoutAsync(string? userName, CancellationToken cancellationToken = default)
    {
        metrics?.RecordLogout("success");
        return auditLog.WriteAsync("Authentication", "Logout", NormalizeTarget(userName), "Success", "Local admin logout succeeded.", actor: NormalizeTarget(userName), cancellationToken: cancellationToken);
    }

    private static string NormalizeTarget(string? userName)
        => string.IsNullOrWhiteSpace(userName) ? "anonymous" : userName.Trim();
}
