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
