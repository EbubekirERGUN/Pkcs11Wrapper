namespace Pkcs11Wrapper.Admin.Application.Models;

public static class AdminRoles
{
    public const string Viewer = "viewer";
    public const string Operator = "operator";
    public const string Admin = "admin";

    public static readonly string[] All = [Viewer, Operator, Admin];
}
