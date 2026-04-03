using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Web.Security;

public static class AccountEndpoints
{
    public static async Task<IResult> LoginAsync(HttpContext context, LocalAdminLoginService loginService)
    {
        IResult? antiforgeryFailure = await ValidateAntiforgeryAsync(context);
        if (antiforgeryFailure is not null)
        {
            return antiforgeryFailure;
        }

        IFormCollection form = await context.Request.ReadFormAsync();
        string username = form["username"].ToString();
        string password = form["password"].ToString();
        string? returnUrl = form["returnUrl"].ToString();

        LocalAdminLoginResult result = await loginService.AttemptLoginAsync(username, password, context.Connection.RemoteIpAddress?.ToString(), context.RequestAborted);
        if (!result.Success || result.User is null)
        {
            return Results.LocalRedirect($"/login?error={result.RedirectErrorCode}&returnUrl={Uri.EscapeDataString(string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl)}");
        }

        List<Claim> claims =
        [
            new(ClaimTypes.Name, result.User.UserName),
            .. result.User.Roles.Select(role => new Claim(ClaimTypes.Role, role))
        ];

        ClaimsIdentity identity = new(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
        return Results.LocalRedirect(string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl);
    }

    public static async Task<IResult> LogoutAsync(HttpContext context, LocalAdminLoginService loginService)
    {
        IResult? antiforgeryFailure = await ValidateAntiforgeryAsync(context);
        if (antiforgeryFailure is not null)
        {
            return antiforgeryFailure;
        }

        string? userName = context.User.Identity?.Name;
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        await loginService.WriteLogoutAsync(userName, context.RequestAborted);
        return Results.LocalRedirect("/login");
    }

    private static async Task<IResult?> ValidateAntiforgeryAsync(HttpContext context)
    {
        IAntiforgery antiforgery = context.RequestServices.GetRequiredService<IAntiforgery>();

        try
        {
            await antiforgery.ValidateRequestAsync(context);
            return null;
        }
        catch (AntiforgeryValidationException)
        {
            return Results.Problem(
                title: "Request verification failed.",
                detail: "The admin request is missing a valid antiforgery token.",
                statusCode: StatusCodes.Status400BadRequest);
        }
    }
}
