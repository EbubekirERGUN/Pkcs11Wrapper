using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Web.Lab;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class Pkcs11LabRequestReuseTests
{
    [Fact]
    public void PrepareVerifyKeepsRawHandleWhenCounterpartResolutionIsNotNeeded()
    {
        Pkcs11LabRequest source = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.SignData,
            KeyHandleText = "42",
            KeyObjectClass = "SecretKey",
            KeyType = "GenericSecret"
        };
        Pkcs11LabExecutionResult result = CreateResult(Pkcs11LabArtifactKind.Signature, artifactHex: "AABB");

        Pkcs11LabPreparedRequest prepared = Pkcs11LabRequestReuse.PrepareVerify(source, result);

        Assert.Null(prepared.WarningMessage);
        Assert.Equal(Pkcs11LabOperation.VerifySignature, prepared.Request.Operation);
        Assert.Equal("42", prepared.Request.KeyHandleText);
        Assert.Equal("SecretKey", prepared.Request.KeyObjectClass);
        Assert.Equal("AABB", prepared.Request.SignatureHex);
    }

    [Fact]
    public void PrepareVerifyUsesLocatorAndClearsHandleWhenRsaCounterpartMustBeResolved()
    {
        Pkcs11LabRequest source = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.SignData,
            KeyHandleText = "42",
            KeyLabel = "ci-rsa",
            KeyIdHex = "B2",
            KeyObjectClass = "PrivateKey",
            KeyType = "RSA"
        };
        Pkcs11LabExecutionResult result = CreateResult(Pkcs11LabArtifactKind.Signature, artifactHex: "AABB");

        Pkcs11LabPreparedRequest prepared = Pkcs11LabRequestReuse.PrepareVerify(source, result);

        Assert.Null(prepared.WarningMessage);
        Assert.Equal(Pkcs11LabOperation.VerifySignature, prepared.Request.Operation);
        Assert.Null(prepared.Request.KeyHandleText);
        Assert.Equal("ci-rsa", prepared.Request.KeyLabel);
        Assert.Equal("B2", prepared.Request.KeyIdHex);
        Assert.Equal("PublicKey", prepared.Request.KeyObjectClass);
        Assert.Equal("RSA", prepared.Request.KeyType);
    }

    [Fact]
    public void PrepareVerifyFallsBackToClassAndTypeMetadataWhenOnlyCounterpartLocatorHintsExist()
    {
        Pkcs11LabRequest source = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 1,
            Operation = Pkcs11LabOperation.SignData,
            KeyHandleText = "42",
            KeyObjectClass = "PrivateKey",
            KeyType = "RSA"
        };
        Pkcs11LabExecutionResult result = CreateResult(Pkcs11LabArtifactKind.Signature, artifactHex: "AABB");

        Pkcs11LabPreparedRequest prepared = Pkcs11LabRequestReuse.PrepareVerify(source, result);

        Assert.Null(prepared.WarningMessage);
        Assert.Null(prepared.Request.KeyHandleText);
        Assert.Equal("PublicKey", prepared.Request.KeyObjectClass);
        Assert.Equal("RSA", prepared.Request.KeyType);
    }

    [Fact]
    public void PrepareUnwrapMovesSecondaryLocatorIntoPrimaryReference()
    {
        Pkcs11LabRequest source = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 7,
            Operation = Pkcs11LabOperation.WrapKey,
            MechanismTypeText = "0x2109",
            SecondaryKeyHandleText = "77",
            SecondaryKeyLabel = "wrap-key",
            SecondaryKeyIdHex = "A1",
            SecondaryKeyObjectClass = "SecretKey",
            SecondaryKeyType = "AES"
        };
        Pkcs11LabExecutionResult result = CreateResult(Pkcs11LabArtifactKind.WrappedKey, artifactHex: "DEADBEEF");

        Pkcs11LabPreparedRequest prepared = Pkcs11LabRequestReuse.PrepareUnwrap(source, result);

        Assert.Null(prepared.WarningMessage);
        Assert.Equal(Pkcs11LabOperation.UnwrapAesKey, prepared.Request.Operation);
        Assert.Equal("77", prepared.Request.KeyHandleText);
        Assert.Equal("wrap-key", prepared.Request.KeyLabel);
        Assert.Equal("A1", prepared.Request.KeyIdHex);
        Assert.Equal("SecretKey", prepared.Request.KeyObjectClass);
        Assert.Equal("AES", prepared.Request.KeyType);
        Assert.Null(prepared.Request.SecondaryKeyHandleText);
        Assert.Equal("DEADBEEF", prepared.Request.DataHex);
    }

    [Fact]
    public void PrepareInspectCreatedUsesStableLocatorMetadataInsteadOfCreatedHandle()
    {
        Pkcs11LabRequest source = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 3,
            Operation = Pkcs11LabOperation.UnwrapAesKey,
            KeyHandleText = "11"
        };
        Pkcs11LabExecutionResult result = CreateResult(
            Pkcs11LabArtifactKind.None,
            createdHandleText: "701",
            createdLabel: "lab-unwrapped",
            createdIdHex: "0102",
            createdObjectClass: "SecretKey",
            createdKeyType: "AES",
            createdObjectPersistsAcrossSessions: true);

        Pkcs11LabPreparedRequest prepared = Pkcs11LabRequestReuse.PrepareInspectCreated(source, result);

        Assert.Null(prepared.WarningMessage);
        Assert.Equal(Pkcs11LabOperation.InspectObject, prepared.Request.Operation);
        Assert.Null(prepared.Request.KeyHandleText);
        Assert.Equal("lab-unwrapped", prepared.Request.KeyLabel);
        Assert.Equal("0102", prepared.Request.KeyIdHex);
        Assert.Equal("SecretKey", prepared.Request.KeyObjectClass);
        Assert.Equal("AES", prepared.Request.KeyType);
    }

    [Fact]
    public void PrepareInspectCreatedWarnsWhenCreatedObjectWasSessionScoped()
    {
        Pkcs11LabRequest source = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 3,
            Operation = Pkcs11LabOperation.UnwrapAesKey
        };
        Pkcs11LabExecutionResult result = CreateResult(
            Pkcs11LabArtifactKind.None,
            createdHandleText: "701",
            createdLabel: "lab-unwrapped",
            createdIdHex: "0102",
            createdObjectClass: "SecretKey",
            createdKeyType: "AES",
            createdObjectPersistsAcrossSessions: false);

        Pkcs11LabPreparedRequest prepared = Pkcs11LabRequestReuse.PrepareInspectCreated(source, result);

        Assert.NotNull(prepared.WarningMessage);
        Assert.Contains("session object", prepared.WarningMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Null(prepared.Request.KeyHandleText);
        Assert.Null(prepared.Request.KeyLabel);
    }

    private static Pkcs11LabExecutionResult CreateResult(
        Pkcs11LabArtifactKind artifactKind,
        string? artifactHex = null,
        string? createdHandleText = null,
        string? createdLabel = null,
        string? createdIdHex = null,
        string? createdObjectClass = null,
        string? createdKeyType = null,
        bool createdObjectPersistsAcrossSessions = false)
        => new(
            "Test",
            true,
            "ok",
            "ok",
            [],
            1,
            artifactKind,
            artifactHex,
            createdHandleText,
            createdLabel,
            createdIdHex,
            createdObjectClass,
            createdKeyType,
            createdObjectPersistsAcrossSessions);
}
