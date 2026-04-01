namespace Pkcs11Wrapper.Admin.Web.Security;

public sealed record LocalAdminLoginThrottleStatus(
    bool IsLocked,
    DateTimeOffset? LockedUntilUtc,
    int UserFailureCount,
    int RemoteIpFailureCount);
