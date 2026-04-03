using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;

namespace Pkcs11Wrapper.Admin.Web.OpenApi;

public static class AdminOpenApiExtensions
{
    public const string DefaultDocumentName = "v1";
    public const string DefaultDocumentPath = "/openapi/v1.json";
    public const string DefaultSwaggerPath = "/swagger";

    public static IServiceCollection AddAdminOpenApi(this IServiceCollection services)
    {
        services.AddOpenApi(DefaultDocumentName, options =>
        {
            options.AddDocumentTransformer((document, _, _) =>
            {
                document.Info = new OpenApiInfo
                {
                    Title = "Pkcs11Wrapper Admin HTTP API",
                    Version = DefaultDocumentName,
                    Description = "Documents only the admin host's real HTTP endpoints (auth form posts, export routes, and health probes). Interactive Blazor component traffic is intentionally excluded. OpenAPI JSON and Swagger UI are exposed only in the Development environment."
                };

                return Task.CompletedTask;
            });
        });

        return services;
    }

    public static WebApplication UseAdminOpenApi(this WebApplication app)
    {
        app.MapOpenApi(DefaultDocumentPath);
        app.UseSwaggerUI(options =>
        {
            options.RoutePrefix = DefaultSwaggerPath.Trim('/');
            options.DocumentTitle = "Pkcs11Wrapper Admin HTTP API";
            options.SwaggerEndpoint(DefaultDocumentPath, DefaultDocumentName);
            options.DisplayRequestDuration();
        });

        return app;
    }
}
