using System.ComponentModel.DataAnnotations;

namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed class GenerateAesKeyRequest
{
    [Required]
    [StringLength(128)]
    public string Label { get; set; } = string.Empty;

    public string? IdHex { get; set; }

    [Range(16, 64)]
    public int SizeBytes { get; set; } = 32;

    public bool Token { get; set; } = true;

    public bool Private { get; set; } = true;

    public bool Sensitive { get; set; } = true;

    public bool Extractable { get; set; }

    public bool AllowEncrypt { get; set; } = true;

    public bool AllowDecrypt { get; set; } = true;

    public bool AllowWrap { get; set; }

    public bool AllowUnwrap { get; set; }
}

public sealed class GenerateRsaKeyPairRequest
{
    [Required]
    [StringLength(128)]
    public string Label { get; set; } = string.Empty;

    public string? IdHex { get; set; }

    [Range(1024, 8192)]
    public int ModulusBits { get; set; } = 2048;

    public string PublicExponentHex { get; set; } = "010001";

    public bool Token { get; set; } = true;

    public bool Sensitive { get; set; } = true;

    public bool Extractable { get; set; }

    public bool AllowSign { get; set; } = true;

    public bool AllowVerify { get; set; } = true;

    public bool AllowEncrypt { get; set; }

    public bool AllowDecrypt { get; set; }
}

public sealed class ImportAesKeyRequest
{
    [Required]
    [StringLength(128)]
    public string Label { get; set; } = string.Empty;

    public string? IdHex { get; set; }

    [Required]
    public string ValueHex { get; set; } = string.Empty;

    public bool Token { get; set; } = true;

    public bool Private { get; set; } = true;

    public bool Sensitive { get; set; } = true;

    public bool Extractable { get; set; }

    public bool AllowEncrypt { get; set; } = true;

    public bool AllowDecrypt { get; set; } = true;

    public bool AllowWrap { get; set; }

    public bool AllowUnwrap { get; set; }
}

public sealed class UpdateObjectAttributesRequest
{
    public nuint Handle { get; set; }

    public string? CurrentLabel { get; set; }

    [Required]
    [StringLength(128)]
    public string Label { get; set; } = string.Empty;

    public string? IdHex { get; set; }

    public bool? Private { get; set; }

    public bool? Token { get; set; }

    public bool? Extractable { get; set; }

    public bool? AllowEncrypt { get; set; }

    public bool? AllowDecrypt { get; set; }

    public bool? AllowSign { get; set; }

    public bool? AllowVerify { get; set; }

    public bool? AllowWrap { get; set; }

    public bool? AllowUnwrap { get; set; }

    public bool? AllowDerive { get; set; }
}

public sealed record KeyManagementResult(
    string Operation,
    string Summary,
    IReadOnlyList<nuint> Handles,
    string? Label,
    string? IdHex);
