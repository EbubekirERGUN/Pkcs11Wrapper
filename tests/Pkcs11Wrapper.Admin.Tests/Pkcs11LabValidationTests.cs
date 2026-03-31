using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class Pkcs11LabValidationTests
{
    [Fact]
    public void ValidateLabRequestAllowsModuleInfoWithoutSlot()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            Operation = Pkcs11LabOperation.ModuleInfo
        };

        HsmAdminService.ValidateLabRequest(request);
    }

    [Fact]
    public void ValidateLabRequestRequiresSlotForMechanismList()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            Operation = Pkcs11LabOperation.MechanismList
        };

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() => HsmAdminService.ValidateLabRequest(request));
        Assert.Contains("requires a slot", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateLabRequestRequiresMechanismTypeForMechanismInfo()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.MechanismInfo
        };

        ArgumentException exception = Assert.Throws<ArgumentException>(() => HsmAdminService.ValidateLabRequest(request));
        Assert.Contains("Mechanism type", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateLabRequestRequiresKeyHandleForSign()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.SignData,
            MechanismTypeText = "0x1",
            PayloadEncoding = Pkcs11LabPayloadEncoding.Utf8Text,
            TextInput = "hello"
        };

        ArgumentException exception = Assert.Throws<ArgumentException>(() => HsmAdminService.ValidateLabRequest(request));
        Assert.Contains("Key handle", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateLabRequestRequiresPayloadForEncrypt()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.EncryptData,
            MechanismTypeText = "0x1082",
            KeyHandleText = "42",
            PayloadEncoding = Pkcs11LabPayloadEncoding.Hex,
            DataHex = "   "
        };

        ArgumentException exception = Assert.Throws<ArgumentException>(() => HsmAdminService.ValidateLabRequest(request));
        Assert.Contains("Hex payload", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateLabRequestRequiresSignatureForVerify()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.VerifySignature,
            MechanismTypeText = "0x40",
            KeyHandleText = "77",
            PayloadEncoding = Pkcs11LabPayloadEncoding.Utf8Text,
            TextInput = "hello"
        };

        ArgumentException exception = Assert.Throws<ArgumentException>(() => HsmAdminService.ValidateLabRequest(request));
        Assert.Contains("Signature hex", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateLabRequestRequiresCiphertextForDecrypt()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.DecryptData,
            MechanismTypeText = "0x1",
            KeyHandleText = "42"
        };

        ArgumentException exception = Assert.Throws<ArgumentException>(() => HsmAdminService.ValidateLabRequest(request));
        Assert.Contains("Ciphertext hex", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateLabRequestAcceptsVerifySignatureWithHexPayload()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.VerifySignature,
            MechanismTypeText = "0x1",
            KeyHandleText = "42",
            PayloadEncoding = Pkcs11LabPayloadEncoding.Hex,
            DataHex = "DEADBEEF",
            SignatureHex = "AABBCC"
        };

        HsmAdminService.ValidateLabRequest(request);
    }

    [Fact]
    public void ValidateLabRequestRequiresHandleForInspectObject()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.InspectObject
        };

        ArgumentException exception = Assert.Throws<ArgumentException>(() => HsmAdminService.ValidateLabRequest(request));
        Assert.Contains("Key handle", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateLabRequestRequiresWrappingHandleForWrapKey()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.WrapKey,
            MechanismTypeText = "0x2109",
            KeyHandleText = "42"
        };

        ArgumentException exception = Assert.Throws<ArgumentException>(() => HsmAdminService.ValidateLabRequest(request));
        Assert.Contains("Wrapping key handle", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateLabRequestRequiresWrappedBlobForUnwrapKey()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.UnwrapAesKey,
            MechanismTypeText = "0x2109",
            KeyHandleText = "7"
        };

        ArgumentException exception = Assert.Throws<ArgumentException>(() => HsmAdminService.ValidateLabRequest(request));
        Assert.Contains("Wrapped key hex", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateLabRequestAcceptsUnwrapKeyWithoutExplicitTargetLabel()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.UnwrapAesKey,
            MechanismTypeText = "0x2109",
            KeyHandleText = "7",
            DataHex = "AABBCCDD"
        };

        HsmAdminService.ValidateLabRequest(request);
    }

    [Fact]
    public void ValidateLabRequestRequiresAttributeTypeForReadAttribute()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.ReadAttribute,
            KeyHandleText = "42"
        };

        ArgumentException exception = Assert.Throws<ArgumentException>(() => HsmAdminService.ValidateLabRequest(request));
        Assert.Contains("Attribute type", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateLabRequestAcceptsReadAttributeWithHexCode()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.ReadAttribute,
            KeyHandleText = "42",
            AttributeTypeText = "0x3"
        };

        HsmAdminService.ValidateLabRequest(request);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4097)]
    public void ValidateLabRequestRejectsOutOfRangeRandomLength(int randomLength)
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.GenerateRandom,
            RandomLength = randomLength
        };

        Assert.Throws<ArgumentOutOfRangeException>(() => HsmAdminService.ValidateLabRequest(request));
    }

    [Fact]
    public void ValidateLabRequestRequiresDigestInput()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.DigestText,
            TextInput = "   "
        };

        ArgumentException exception = Assert.Throws<ArgumentException>(() => HsmAdminService.ValidateLabRequest(request));
        Assert.Contains("Digest input", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(257)]
    public void ValidateLabRequestRejectsOutOfRangeFindObjectLimit(int maxObjects)
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.FindObjects,
            MaxObjects = maxObjects
        };

        Assert.Throws<ArgumentOutOfRangeException>(() => HsmAdminService.ValidateLabRequest(request));
    }
}
