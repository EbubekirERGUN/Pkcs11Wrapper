using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Web.Security;

public static class AccountEndpoints
{
    public static async Task<IResult> LoginAsync(HttpContext context, LocalAdminUserStore users)
    {
        IFormCollection form = await context.Request.ReadFormAsync();
        string username = form["username"].ToString();
        string password = form["password"].ToString();
        string? returnUrl = form["returnUrl"].ToString();

        AdminWebUserRecord? user = await users.ValidateCredentialsAsync(username, password);
        if (user is null)
        {
            return Results.LocalRedirect($"/login?error=1&returnUrl={Uri.EscapeDataString(string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl)}");
        }

        List<Claim> claims =
        [
            new(ClaimTypes.Name, user.Username),
            .. user.Roles.Select(role => new Claim(ClaimTypes.Role, role))
        ];

        ClaimsIdentity identity = new(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
        return Results.LocalRedirect(string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl);
    }

    public static async Task<IResult> LogoutAsync(HttpContext context)
    {
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Results.LocalRedirect("/login");
    }
}
