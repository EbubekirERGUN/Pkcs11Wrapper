using System.Security.Claims;
using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Web.Security;

public sealed class HttpContextAdminAuthorizationService(IHttpContextAccessor accessor) : IAdminAuthorizationService
{
    public void DemandViewer() => DemandAny(AdminRoles.Viewer, AdminRoles.Operator, AdminRoles.Admin);

    public void DemandOperator() => DemandAny(AdminRoles.Operator, AdminRoles.Admin);

    public void DemandAdmin() => DemandAny(AdminRoles.Admin);

    private void DemandAny(params string[] roles)
    {
        ClaimsPrincipal principal = accessor.HttpContext?.User ?? new ClaimsPrincipal(new ClaimsIdentity());
        if (!(principal.Identity?.IsAuthenticated ?? false) || !roles.Any(principal.IsInRole))
        {
            throw new UnauthorizedAccessException($"This action requires one of the following roles: {string.Join(", ", roles)}.");
        }
    }
}
