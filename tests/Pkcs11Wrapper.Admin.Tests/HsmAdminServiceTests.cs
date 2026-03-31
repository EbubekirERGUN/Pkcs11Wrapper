using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class HsmAdminServiceTests
{
    [Fact]
    public void ValidateGenerateAesKeyRequestRejectsMissingCapabilities()
    {
        GenerateAesKeyRequest request = new()
        {
            Label = "aes-test",
            SizeBytes = 32,
            AllowEncrypt = false,
            AllowDecrypt = false,
            AllowWrap = false,
            AllowUnwrap = false
        };

        ArgumentException ex = Assert.Throws<ArgumentException>(() => HsmAdminService.ValidateGenerateAesKeyRequest(request));
        Assert.Contains("at least one AES capability", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateGenerateRsaKeyPairRequestRejectsWeakCombination()
    {
        GenerateRsaKeyPairRequest request = new()
        {
            Label = "rsa-test",
            AllowSign = false,
            AllowDecrypt = false,
            AllowVerify = true,
            AllowEncrypt = false,
            PublicExponentHex = "010001",
            ModulusBits = 2048
        };

        ArgumentException ex = Assert.Throws<ArgumentException>(() => HsmAdminService.ValidateGenerateRsaKeyPairRequest(request));
        Assert.Contains("Private key", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateDestroyRequestRequiresTypedConfirmationAndAck()
    {
        DestroyObjectRequest request = new()
        {
            Handle = 42,
            Label = "demo-key",
            UserPin = "1234",
            ConfirmationText = "DESTROY 42 demo-key",
            AcknowledgePermanentDeletion = false
        };

        InvalidOperationException ackEx = Assert.Throws<InvalidOperationException>(() => HsmAdminService.ValidateDestroyRequest(request));
        Assert.Contains("acknowledged", ackEx.Message, StringComparison.OrdinalIgnoreCase);

        request.AcknowledgePermanentDeletion = true;
        request.ConfirmationText = "DESTROY 42";

        InvalidOperationException confirmEx = Assert.Throws<InvalidOperationException>(() => HsmAdminService.ValidateDestroyRequest(request));
        Assert.Contains("DESTROY 42 demo-key", confirmEx.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void BuildDestroyConfirmationTextIncludesLabelWhenAvailable()
    {
        Assert.Equal("DESTROY 99 important-key", HsmAdminService.BuildDestroyConfirmationText(99, "important-key"));
        Assert.Equal("DESTROY 99", HsmAdminService.BuildDestroyConfirmationText(99, null));
    }

    [Fact]
    public void ValidateImportAesKeyRequestRejectsInvalidLength()
    {
        ImportAesKeyRequest request = new()
        {
            Label = "aes-import",
            ValueHex = "00112233445566778899AABBCCDDEEFF00"
        };

        ArgumentOutOfRangeException ex = Assert.Throws<ArgumentOutOfRangeException>(() => HsmAdminService.ValidateImportAesKeyRequest(request));
        Assert.Contains("Imported AES key value", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateUpdateObjectAttributesRequestRejectsMissingHandle()
    {
        UpdateObjectAttributesRequest request = new()
        {
            Handle = 0,
            Label = "updated"
        };

        Assert.Throws<ArgumentOutOfRangeException>(() => HsmAdminService.ValidateUpdateObjectAttributesRequest(request));
    }

    [Fact]
    public void ValidateCopyObjectRequestRejectsMissingSourceHandle()
    {
        CopyObjectRequest request = new()
        {
            SourceHandle = 0,
            Label = "copy-of-key"
        };

        Assert.Throws<ArgumentOutOfRangeException>(() => HsmAdminService.ValidateCopyObjectRequest(request));
    }

    [Fact]
    public void ValidateCopyObjectRequestRejectsMissingLabel()
    {
        CopyObjectRequest request = new()
        {
            SourceHandle = 77,
            Label = "   "
        };

        ArgumentException ex = Assert.Throws<ArgumentException>(() => HsmAdminService.ValidateCopyObjectRequest(request));
        Assert.Contains("Label is required", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
