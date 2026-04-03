namespace Pkcs11Wrapper.Admin.Web.Security;

public static class AdminSecurityResponseHeadersExtensions
{
    public static IApplicationBuilder UseAdminSecurityResponseHeaders(this IApplicationBuilder app)
        => app.Use(async (context, next) =>
        {
            bool disableCaching = IsSensitivePath(context.Request.Path);

            context.Response.OnStarting(static state =>
            {
                (HttpContext httpContext, bool noStore) = ((HttpContext, bool))state;
                IHeaderDictionary headers = httpContext.Response.Headers;

                headers["X-Frame-Options"] = "DENY";
                headers["X-Content-Type-Options"] = "nosniff";
                headers["Referrer-Policy"] = "no-referrer";
                headers["Permissions-Policy"] = "camera=(), geolocation=(), microphone=()";

                if (noStore)
                {
                    headers["Cache-Control"] = "no-store, max-age=0";
                    headers["Pragma"] = "no-cache";
                    headers["Expires"] = "0";
                }

                return Task.CompletedTask;
            }, (context, disableCaching));

            await next();
        });

    private static bool IsSensitivePath(PathString path)
        => path.StartsWithSegments("/login", StringComparison.OrdinalIgnoreCase)
            || path.StartsWithSegments("/account", StringComparison.OrdinalIgnoreCase)
            || path.StartsWithSegments("/configuration/export", StringComparison.OrdinalIgnoreCase)
            || path.StartsWithSegments("/telemetry/export", StringComparison.OrdinalIgnoreCase)
            || path.StartsWithSegments("/openapi", StringComparison.OrdinalIgnoreCase)
            || path.StartsWithSegments("/swagger", StringComparison.OrdinalIgnoreCase);
}
