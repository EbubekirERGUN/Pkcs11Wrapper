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

    [Fact]
    public void ValidateLabRequestAcceptsBatchAttributeCodes()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.ReadAttribute,
            KeyHandleText = "42",
            AttributeTypeText = "0x3, 0x102\n0x100"
        };

        HsmAdminService.ValidateLabRequest(request);
    }

    [Fact]
    public void ValidateLabRequestRejectsAesCbcProfileWithoutIv()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.EncryptData,
            MechanismTypeText = "0x1085",
            MechanismParameterProfile = Pkcs11LabMechanismParameterProfile.AesCbcIv,
            KeyHandleText = "42",
            PayloadEncoding = Pkcs11LabPayloadEncoding.Utf8Text,
            TextInput = "hello"
        };

        ArgumentException exception = Assert.Throws<ArgumentException>(() => HsmAdminService.ValidateLabRequest(request));
        Assert.Contains("AES-CBC IV", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateLabRequestAcceptsAesGcmParameterProfile()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.EncryptData,
            MechanismTypeText = "0x1087",
            MechanismParameterProfile = Pkcs11LabMechanismParameterProfile.AesGcm,
            MechanismIvHex = "00112233445566778899AABB",
            MechanismAdditionalDataHex = "AABBCCDD",
            MechanismTagBits = 128,
            KeyHandleText = "42",
            PayloadEncoding = Pkcs11LabPayloadEncoding.Utf8Text,
            TextInput = "hello"
        };

        HsmAdminService.ValidateLabRequest(request);
    }

    [Fact]
    public void ValidateLabRequestRejectsIncompatibleMechanismParameterProfile()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.SignData,
            MechanismTypeText = "0x1",
            MechanismParameterProfile = Pkcs11LabMechanismParameterProfile.AesCtr,
            MechanismIvHex = "00112233445566778899AABBCCDDEEFF",
            MechanismCounterBits = 128,
            KeyHandleText = "42",
            PayloadEncoding = Pkcs11LabPayloadEncoding.Utf8Text,
            TextInput = "hello"
        };

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() => HsmAdminService.ValidateLabRequest(request));
        Assert.Contains("not compatible", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ValidateLabRequestAcceptsRsaOaepProfile()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.EncryptData,
            MechanismTypeText = "0x9",
            MechanismParameterProfile = Pkcs11LabMechanismParameterProfile.RsaOaep,
            RsaHashProfile = Pkcs11LabRsaHashProfile.Sha256,
            RsaOaepSourceEncoding = Pkcs11LabPayloadEncoding.Utf8Text,
            RsaOaepSourceText = "label",
            KeyHandleText = "42",
            PayloadEncoding = Pkcs11LabPayloadEncoding.Utf8Text,
            TextInput = "hello"
        };

        HsmAdminService.ValidateLabRequest(request);
    }

    [Fact]
    public void ValidateLabRequestAcceptsRsaPssProfile()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.SignData,
            MechanismTypeText = "0x43",
            MechanismParameterProfile = Pkcs11LabMechanismParameterProfile.RsaPss,
            RsaHashProfile = Pkcs11LabRsaHashProfile.Sha256,
            PssSaltLength = 32,
            KeyHandleText = "42",
            PayloadEncoding = Pkcs11LabPayloadEncoding.Utf8Text,
            TextInput = "hello"
        };

        HsmAdminService.ValidateLabRequest(request);
    }

    [Fact]
    public void ValidateLabRequestRejectsRsaOaepProfileOnWrongMechanism()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.EncryptData,
            MechanismTypeText = "0x1",
            MechanismParameterProfile = Pkcs11LabMechanismParameterProfile.RsaOaep,
            KeyHandleText = "42",
            PayloadEncoding = Pkcs11LabPayloadEncoding.Utf8Text,
            TextInput = "hello"
        };

        InvalidOperationException exception = Assert.Throws<InvalidOperationException>(() => HsmAdminService.ValidateLabRequest(request));
        Assert.Contains("not compatible", exception.Message, StringComparison.OrdinalIgnoreCase);
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
