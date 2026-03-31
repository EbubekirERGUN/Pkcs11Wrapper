namespace Pkcs11Wrapper.Admin.Web.Security;

public sealed record AdminWebUserRecord(string Username, string PasswordHash, string[] Roles, DateTimeOffset CreatedUtc);
