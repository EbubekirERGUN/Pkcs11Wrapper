using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;
using OpenTelemetry.Metrics;
using Pkcs11Wrapper.CryptoApi.Gateway.Configuration;
using Pkcs11Wrapper.CryptoApi.Gateway.Health;
using Pkcs11Wrapper.CryptoApi.Gateway.Observability;
using Pkcs11Wrapper.CryptoApi.Gateway.Runtime;
using Pkcs11Wrapper.Observability;
using Yarp.ReverseProxy.Transforms;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddProblemDetails();
builder.Services.AddOptions<CryptoApiGatewayOptions>()
    .Bind(builder.Configuration.GetSection(CryptoApiGatewayOptions.SectionName))
    .PostConfigure(CryptoApiGatewayOptionsLoader.Normalize)
    .Services.AddSingleton<IValidateOptions<CryptoApiGatewayOptions>, CryptoApiGatewayOptionsValidator>();
builder.Services.AddOptions<CryptoApiGatewayOptions>()
    .ValidateOnStart();

builder.Services.AddOptions<ObservabilityOptions>()
    .Bind(builder.Configuration.GetSection(ObservabilityOptions.SectionName))
    .PostConfigure(ObservabilityOptions.Normalize)
    .Validate(static options => options.MetricsPath.StartsWith("/", StringComparison.Ordinal), "Observability metrics path must start with '/'.")
    .ValidateOnStart();

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<GatewayMetrics>();
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics =>
    {
        metrics
            .AddPrometheusExporter()
            .AddMeter(
                "Microsoft.AspNetCore.Hosting",
                "Microsoft.AspNetCore.Server.Kestrel",
                "System.Net.Http",
                "Yarp.ReverseProxy",
                GatewayMetrics.MeterName);
    });
builder.Services.AddHttpClient(GatewayBackendReadinessProbe.HttpClientName);
builder.Services.AddSingleton<CryptoApiGatewayRuntimeDescriptorProvider>();
builder.Services.AddSingleton<GatewayBackendReadinessProbe>();
builder.Services.AddSingleton<Yarp.ReverseProxy.Configuration.IProxyConfigProvider, CryptoApiGatewayProxyConfigProvider>();

(builder.Services
    .AddReverseProxy())
    .AddTransforms(static transformBuilderContext =>
    {
        transformBuilderContext.AddResponseTransform(static responseTransformContext =>
        {
            responseTransformContext.ProxyResponse?.Headers.Remove("server");
            return ValueTask.CompletedTask;
        });
    });

WebApplication app = builder.Build();
CryptoApiGatewayOptions gatewayOptions = app.Services.GetRequiredService<IOptions<CryptoApiGatewayOptions>>().Value;
ObservabilityOptions observabilityOptions = app.Services.GetRequiredService<IOptions<ObservabilityOptions>>().Value;
CryptoApiGatewayRuntimeDescriptorProvider descriptorProvider = app.Services.GetRequiredService<CryptoApiGatewayRuntimeDescriptorProvider>();
GatewayBackendReadinessProbe readinessProbe = app.Services.GetRequiredService<GatewayBackendReadinessProbe>();
GatewayMetrics gatewayMetrics = app.Services.GetRequiredService<GatewayMetrics>();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler();
    app.UseHsts();
}

app.Use(async (context, next) =>
{
    string headerName = gatewayOptions.CorrelationIdHeaderName;
    string correlationId = context.Request.Headers.TryGetValue(headerName, out var headerValues)
        ? headerValues.FirstOrDefault(static value => !string.IsNullOrWhiteSpace(value))?.Trim() ?? string.Empty
        : string.Empty;

    if (string.IsNullOrWhiteSpace(correlationId))
    {
        correlationId = Guid.NewGuid().ToString("N");
    }

    context.Request.Headers[headerName] = correlationId;
    context.TraceIdentifier = correlationId;
    context.Response.OnStarting(static state =>
    {
        (HttpContext httpContext, string responseHeaderName, string responseCorrelationId) = ((HttpContext, string, string))state;
        httpContext.Response.Headers[responseHeaderName] = responseCorrelationId;
        return Task.CompletedTask;
    }, (context, headerName, correlationId));

    await next(context);
});

app.Use(async (context, next) =>
{
    long? maxRequestBodySizeBytes = gatewayOptions.MaxRequestBodySizeBytes;
    if (maxRequestBodySizeBytes is long maxRequestBodySize)
    {
        IHttpMaxRequestBodySizeFeature? requestBodySizeFeature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (requestBodySizeFeature is not null && !requestBodySizeFeature.IsReadOnly)
        {
            requestBodySizeFeature.MaxRequestBodySize = maxRequestBodySize;
        }

        if (context.Request.ContentLength is long contentLength && contentLength > maxRequestBodySize)
        {
            gatewayMetrics.RecordRequestBodyRejected(maxRequestBodySize);
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            await context.Response.WriteAsJsonAsync(new
            {
                title = "Request body exceeds the configured gateway limit.",
                status = StatusCodes.Status413PayloadTooLarge,
                detail = $"The request declared {contentLength} bytes, which exceeds the configured gateway ingress limit of {maxRequestBodySize} bytes.",
                maxRequestBodySizeBytes = maxRequestBodySize
            });
            return;
        }
    }

    await next(context);
});

app.MapGet("/", () =>
{
    CryptoApiGatewayRuntimeDescriptor descriptor = descriptorProvider.Describe();
    return Results.Ok(new
    {
        descriptor.ServiceName,
        descriptor.InstanceId,
        descriptor.ClusterId,
        descriptor.ApiBasePath,
        descriptor.DeploymentModel,
        descriptor.LoadBalancingPolicy,
        descriptor.CorrelationIdHeaderName,
        descriptor.MaxRequestBodySizeBytes,
        descriptor.ActiveHealthChecksEnabled,
        descriptor.ConfiguredDestinationCount,
        descriptor.StartedAtUtc,
        descriptor.CurrentSurface,
        descriptor.Notes,
        Metrics = observabilityOptions.EnablePrometheusScrapingEndpoint ? observabilityOptions.MetricsPath : null
    });
});
app.MapGet(CryptoApiGatewayDefaults.RuntimePath, () => Results.Ok(descriptorProvider.Describe()));
app.MapGet(CryptoApiGatewayDefaults.HealthLivePath, () => Results.Ok(new
{
    status = "Healthy",
    service = gatewayOptions.ServiceName,
    clusterId = gatewayOptions.ClusterId,
    timestampUtc = DateTimeOffset.UtcNow
}));
app.MapGet(CryptoApiGatewayDefaults.HealthReadyPath, async (CancellationToken cancellationToken) =>
{
    GatewayBackendReadinessResult readiness = await readinessProbe.ProbeAsync(cancellationToken);
    return readiness.Ready
        ? Results.Ok(readiness)
        : Results.Problem(
            title: "No healthy Crypto API destinations are currently ready.",
            detail: "The gateway could not confirm a healthy upstream Crypto API destination via the configured readiness probes.",
            statusCode: StatusCodes.Status503ServiceUnavailable,
            extensions: new Dictionary<string, object?>
            {
                ["readiness"] = readiness
            });
});

app.MapReverseProxy();

if (observabilityOptions.EnablePrometheusScrapingEndpoint)
{
    app.MapPrometheusScrapingEndpoint(observabilityOptions.MetricsPath);
}

app.Run();

public partial class Program;
