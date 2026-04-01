namespace Pkcs11Wrapper.Admin.Web.Security;

public sealed class LocalAdminLoginThrottleOptions
{
    public int MaxFailuresPerKey { get; set; } = 5;

    public TimeSpan FailureWindow { get; set; } = TimeSpan.FromMinutes(10);

    public TimeSpan LockoutDuration { get; set; } = TimeSpan.FromMinutes(15);
}
