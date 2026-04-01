namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed class AdminSessionRegistryOptions
{
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromMinutes(20);
}
