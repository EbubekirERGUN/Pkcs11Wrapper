using System.Text.Json.Serialization;

namespace Pkcs11Wrapper.Admin.Web.OpenApi;

public sealed class AdminLoginRequest
{
    [JsonPropertyName("username")]
    public string? UserName { get; init; }

    [JsonPropertyName("password")]
    public string? Password { get; init; }

    [JsonPropertyName("returnUrl")]
    public string? ReturnUrl { get; init; }

    [JsonPropertyName("__RequestVerificationToken")]
    public string? RequestVerificationToken { get; init; }
}

public sealed class AdminLogoutRequest
{
    [JsonPropertyName("__RequestVerificationToken")]
    public string? RequestVerificationToken { get; init; }
}
