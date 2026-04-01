using System.Reflection;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;
using Pkcs11Wrapper.Native;
using Pkcs11Wrapper.Native.Interop;

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
    public void CreateImportedAesTemplateDoesNotEmitValueLengthWhenValueIsPresent()
    {
        MethodInfo method = typeof(HsmAdminService).GetMethod("CreateImportedAesTemplate", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException("CreateImportedAesTemplate was not found.");

        ImportAesKeyRequest request = new()
        {
            Label = "aes-import",
            ValueHex = "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF"
        };

        Pkcs11ObjectAttribute[] attributes = (Pkcs11ObjectAttribute[])method.Invoke(null,
        [
            request,
            System.Text.Encoding.UTF8.GetBytes(request.Label),
            Array.Empty<byte>(),
            Convert.FromHexString(request.ValueHex)
        ])!;

        Assert.Contains(attributes, attribute => attribute.Type == Pkcs11AttributeTypes.Value);
        Assert.DoesNotContain(attributes, attribute => attribute.Type == Pkcs11AttributeTypes.ValueLen);
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

    [Fact]
    public void ValidateLabRequestAcceptsLocatorMetadataWithoutRawHandle()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 5,
            Operation = Pkcs11LabOperation.SignData,
            MechanismTypeText = "0x1",
            KeyLabel = "ci-rsa",
            KeyIdHex = "B2",
            KeyObjectClass = "PrivateKey",
            KeyType = "RSA",
            PayloadEncoding = Pkcs11LabPayloadEncoding.Utf8Text,
            TextInput = "runtime-sign-data"
        };

        HsmAdminService.ValidateLabRequest(request);
    }

    [Fact]
    public void ValidateLabRequestRejectsUnsupportedLocatorObjectClass()
    {
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 5,
            Operation = Pkcs11LabOperation.SignData,
            MechanismTypeText = "0x1",
            KeyLabel = "ci-rsa",
            KeyObjectClass = "UnknownClass",
            PayloadEncoding = Pkcs11LabPayloadEncoding.Utf8Text,
            TextInput = "runtime-sign-data"
        };

        ArgumentException ex = Assert.Throws<ArgumentException>(() => HsmAdminService.ValidateLabRequest(request));
        Assert.Contains("Object class", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LoginUserToleratingAlreadyLoggedInSwallowsAlreadyLoggedInReturnValue()
    {
        MethodInfo method = GetLoginUserToleratingAlreadyLoggedInActionOverload();
        bool attempted = false;

        method.Invoke(null,
        [
            (Action)(() =>
            {
                attempted = true;
                throw new Pkcs11Exception("C_Login", new CK_RV(0x100));
            })
        ]);

        Assert.True(attempted);
    }

    [Fact]
    public void LoginUserToleratingAlreadyLoggedInPropagatesUnexpectedPkcs11Errors()
    {
        MethodInfo method = GetLoginUserToleratingAlreadyLoggedInActionOverload();

        TargetInvocationException ex = Assert.Throws<TargetInvocationException>(() => method.Invoke(null,
        [
            (Action)(() => throw new Pkcs11Exception("C_Login", new CK_RV(0xA0)))
        ]));

        Pkcs11Exception inner = Assert.IsType<Pkcs11Exception>(ex.InnerException);
        Assert.Equal((nuint)0xA0, (nuint)inner.RawResult);
    }

    private static MethodInfo GetLoginUserToleratingAlreadyLoggedInActionOverload()
    {
        return typeof(HsmAdminService)
            .GetMethods(BindingFlags.NonPublic | BindingFlags.Static)
            .Single(method => method.Name == "LoginUserToleratingAlreadyLoggedIn"
                && method.GetParameters() is [{ ParameterType: var parameterType }]
                && parameterType == typeof(Action));
    }
}
