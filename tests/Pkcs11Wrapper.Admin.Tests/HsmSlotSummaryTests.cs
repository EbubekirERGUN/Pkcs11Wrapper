using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class HsmSlotSummaryTests
{
    [Fact]
    public void InitializedTokenEnablesSessionActions()
    {
        HsmSlotSummary slot = new(
            Guid.NewGuid(),
            7,
            "SoftHSM slot",
            "SoftHSM project",
            "TokenPresent",
            TokenPresent: true,
            TokenInitialized: true,
            TokenLabel: "Pkcs11Wrapper CI Token",
            TokenModel: "SoftHSM v2",
            TokenSerialNumber: "123456",
            TokenFlags: "TokenInitialized, UserPinInitialized",
            MechanismCount: 12);

        Assert.True(slot.CanOpenSessions);
        Assert.False(slot.RequiresInitialization);
        Assert.Equal(string.Empty, slot.SessionOpenUnavailableReason);
    }

    [Fact]
    public void UninitializedTokenRequiresSetupBeforeSessionActions()
    {
        HsmSlotSummary slot = new(
            Guid.NewGuid(),
            3,
            "SoftHSM slot ID 0x3",
            "SoftHSM project",
            "TokenPresent",
            TokenPresent: true,
            TokenInitialized: false,
            TokenLabel: string.Empty,
            TokenModel: "SoftHSM v2",
            TokenSerialNumber: string.Empty,
            TokenFlags: "None",
            MechanismCount: 0);

        Assert.False(slot.CanOpenSessions);
        Assert.True(slot.RequiresInitialization);
        Assert.Contains("not initialized", slot.SessionOpenUnavailableReason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void MissingTokenReportsSessionActionsUnavailable()
    {
        HsmSlotSummary slot = new(
            Guid.NewGuid(),
            9,
            "Empty slot",
            "SoftHSM project",
            "None",
            TokenPresent: false,
            TokenInitialized: false,
            TokenLabel: null,
            TokenModel: null,
            TokenSerialNumber: null,
            TokenFlags: null,
            MechanismCount: 0);

        Assert.False(slot.CanOpenSessions);
        Assert.False(slot.RequiresInitialization);
        Assert.Contains("no token", slot.SessionOpenUnavailableReason, StringComparison.OrdinalIgnoreCase);
    }
}
