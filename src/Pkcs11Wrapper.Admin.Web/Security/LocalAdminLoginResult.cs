using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Web.Security;

public sealed record LocalAdminLoginResult(
    bool Success,
    bool IsThrottled,
    string RedirectErrorCode,
    string Message,
    AdminWebUserRecord? User,
    DateTimeOffset? LockedUntilUtc);
