namespace Pkcs11Wrapper.Admin.Web.Security;

public sealed record AdminWebUserRecord(
    string UserName,
    string PasswordHash,
    string[] Roles,
    DateTimeOffset CreatedUtc);
