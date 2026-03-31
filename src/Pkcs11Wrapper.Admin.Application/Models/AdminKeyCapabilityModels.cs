namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record SlotMechanismSupport(
    string Name,
    string TypeHex,
    bool Available,
    bool SupportsGenerate,
    bool SupportsGenerateKeyPair,
    bool SupportsEncrypt,
    bool SupportsDecrypt,
    bool SupportsSign,
    bool SupportsVerify,
    bool SupportsWrap,
    bool SupportsUnwrap,
    string Summary);

public sealed record KeyManagementSlotCapabilities(
    Guid DeviceId,
    nuint SlotId,
    bool TokenPresent,
    bool SupportsAesKeyGeneration,
    bool SupportsRsaKeyPairGeneration,
    bool SupportsAesObjectImport,
    IReadOnlyList<string> Warnings,
    IReadOnlyList<SlotMechanismSupport> Mechanisms);

public sealed record ObjectEditCapabilities(
    bool CanEditAnyAttributes,
    bool CanEditToken,
    bool CanEditPrivate,
    bool CanEditExtractable,
    bool CanEditEncrypt,
    bool CanEditDecrypt,
    bool CanEditSign,
    bool CanEditVerify,
    bool CanEditWrap,
    bool CanEditUnwrap,
    bool CanEditDerive,
    IReadOnlyList<string> Warnings);

public sealed class CopyObjectRequest
{
    public nuint SourceHandle { get; set; }

    public string? SourceLabel { get; set; }

    public string? SourceObjectClass { get; set; }

    [System.ComponentModel.DataAnnotations.Required]
    [System.ComponentModel.DataAnnotations.StringLength(128)]
    public string Label { get; set; } = string.Empty;

    public string? IdHex { get; set; }

    public bool? Token { get; set; }

    public bool? Private { get; set; }

    public bool? Extractable { get; set; }

    public bool? AllowEncrypt { get; set; }

    public bool? AllowDecrypt { get; set; }

    public bool? AllowSign { get; set; }

    public bool? AllowVerify { get; set; }

    public bool? AllowWrap { get; set; }

    public bool? AllowUnwrap { get; set; }

    public bool? AllowDerive { get; set; }
}
