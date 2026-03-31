using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Web.Lab;

public sealed record Pkcs11LabSavedTemplate(
    Guid Id,
    string Name,
    string? Notes,
    DateTimeOffset CreatedUtc,
    DateTimeOffset UpdatedUtc,
    Pkcs11LabRequest Request);
