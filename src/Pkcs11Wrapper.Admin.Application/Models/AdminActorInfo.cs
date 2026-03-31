namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record AdminActorInfo(
    string Name,
    string AuthenticationType,
    bool IsAuthenticated,
    string[] Roles,
    string? RemoteIp,
    string? SessionId,
    string? UserAgent);
