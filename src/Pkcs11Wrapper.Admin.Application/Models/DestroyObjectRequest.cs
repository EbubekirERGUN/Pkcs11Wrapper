namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed class DestroyObjectRequest
{
    public nuint Handle { get; set; }

    public string? Label { get; set; }

    public string UserPin { get; set; } = string.Empty;

    public string ConfirmationText { get; set; } = string.Empty;

    public bool AcknowledgePermanentDeletion { get; set; }
}
