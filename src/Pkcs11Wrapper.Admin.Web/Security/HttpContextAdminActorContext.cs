using System.Security.Claims;
using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Web.Security;

public sealed class HttpContextAdminActorContext(IHttpContextAccessor accessor) : IAdminActorContext
{
    public AdminActorInfo GetCurrent()
    {
        ClaimsPrincipal principal = accessor.HttpContext?.User ?? new ClaimsPrincipal(new ClaimsIdentity());
        return new AdminActorInfo(
            principal.Identity?.Name ?? "anonymous",
            principal.Identity?.AuthenticationType ?? "none",
            principal.Identity?.IsAuthenticated ?? false,
            principal.FindAll(ClaimTypes.Role).Select(x => x.Value).Distinct(StringComparer.Ordinal).OrderBy(x => x, StringComparer.Ordinal).ToArray(),
            accessor.HttpContext?.Connection.RemoteIpAddress?.ToString(),
            accessor.HttpContext?.TraceIdentifier,
            accessor.HttpContext?.Request.Headers.UserAgent.ToString());
    }
}
