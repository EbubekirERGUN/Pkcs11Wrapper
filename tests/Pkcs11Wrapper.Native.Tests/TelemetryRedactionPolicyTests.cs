using System.Text;
using Pkcs11Wrapper;
using Pkcs11Wrapper.Native;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper.Native.Tests;

public sealed class TelemetryRedactionPolicyTests
{
    [Fact]
    public unsafe void TemplateSummaryClassifiesSafeHashedAndNeverLogAttributes()
    {
        byte[] classValue = PackNuint(Pkcs11ObjectClasses.SecretKey.Value);
        byte[] keyTypeValue = PackNuint(Pkcs11KeyTypes.Aes.Value);
        byte[] valueLen = PackNuint(32);
        byte[] token = [1];
        byte[] label = Encoding.UTF8.GetBytes("prod-aes-key");
        byte[] id = [0xA1, 0xB2];
        byte[] secretValue = [0x11, 0x22, 0x33, 0x44];

        fixed (byte* classPtr = classValue)
        fixed (byte* keyTypePtr = keyTypeValue)
        fixed (byte* valueLenPtr = valueLen)
        fixed (byte* tokenPtr = token)
        fixed (byte* labelPtr = label)
        fixed (byte* idPtr = id)
        fixed (byte* secretValuePtr = secretValue)
        {
            CK_ATTRIBUTE[] template =
            [
                new() { Type = new CK_ATTRIBUTE_TYPE(Pkcs11AttributeTypes.Class.Value), Value = classPtr, ValueLength = (CK_ULONG)(nuint)classValue.Length },
                new() { Type = new CK_ATTRIBUTE_TYPE(Pkcs11AttributeTypes.KeyType.Value), Value = keyTypePtr, ValueLength = (CK_ULONG)(nuint)keyTypeValue.Length },
                new() { Type = new CK_ATTRIBUTE_TYPE(Pkcs11AttributeTypes.ValueLen.Value), Value = valueLenPtr, ValueLength = (CK_ULONG)(nuint)valueLen.Length },
                new() { Type = new CK_ATTRIBUTE_TYPE(Pkcs11AttributeTypes.Token.Value), Value = tokenPtr, ValueLength = (CK_ULONG)(nuint)token.Length },
                new() { Type = new CK_ATTRIBUTE_TYPE(Pkcs11AttributeTypes.Label.Value), Value = labelPtr, ValueLength = (CK_ULONG)(nuint)label.Length },
                new() { Type = new CK_ATTRIBUTE_TYPE(Pkcs11AttributeTypes.Id.Value), Value = idPtr, ValueLength = (CK_ULONG)(nuint)id.Length },
                new() { Type = new CK_ATTRIBUTE_TYPE(Pkcs11AttributeTypes.Value.Value), Value = secretValuePtr, ValueLength = (CK_ULONG)(nuint)secretValue.Length },
            ];

            Pkcs11OperationTelemetryField[] fields = Pkcs11TelemetryRedaction.Template("template", template);

            Assert.Contains(fields, f => f.Name == "template.count" && f.Classification == Pkcs11TelemetryFieldClassification.SafeMetadata && f.Value == "7");
            Assert.Contains(fields, f => f.Name == "template.CKA_CLASS" && f.Value == "CKO_SECRET_KEY");
            Assert.Contains(fields, f => f.Name == "template.CKA_KEY_TYPE" && f.Value == "CKK_AES");
            Assert.Contains(fields, f => f.Name == "template.CKA_VALUE_LEN" && f.Value == "32");
            Assert.Contains(fields, f => f.Name == "template.CKA_TOKEN" && f.Value == "true");

            Pkcs11OperationTelemetryField labelField = Assert.Single(fields, f => f.Name == "template.CKA_LABEL");
            Assert.Equal(Pkcs11TelemetryFieldClassification.Hashed, labelField.Classification);
            Assert.Contains("sha256:", labelField.Value, StringComparison.Ordinal);
            Assert.DoesNotContain("prod-aes-key", labelField.Value, StringComparison.Ordinal);

            Pkcs11OperationTelemetryField idField = Assert.Single(fields, f => f.Name == "template.CKA_ID");
            Assert.Equal(Pkcs11TelemetryFieldClassification.Hashed, idField.Classification);
            Assert.DoesNotContain("A1", idField.Value, StringComparison.OrdinalIgnoreCase);

            Pkcs11OperationTelemetryField secretField = Assert.Single(fields, f => f.Name == "template.CKA_VALUE");
            Assert.Equal(Pkcs11TelemetryFieldClassification.NeverLog, secretField.Classification);
            Assert.Equal("suppressed(len=4)", secretField.Value);
        }
    }

    [Fact]
    public void MechanismSummaryKeepsScalarsAndRedactsBytePayloads()
    {
        byte[] gcm = Pkcs11MechanismParameters.AesGcm([0x01, 0x02, 0x03, 0x04], [0xAA, 0xBB], tagBits: 96);
        byte[] oaep = Pkcs11MechanismParameters.RsaOaep(Pkcs11MechanismTypes.Sha256, Pkcs11RsaMgfTypes.Mgf1Sha256, [0x10, 0x20]);
        byte[] ecdh = Pkcs11MechanismParameters.Ecdh1Derive(Pkcs11EcKdfTypes.Null, [0x04, 0xAA, 0xBB], [0x99, 0x88]);

        Pkcs11OperationTelemetryField[] gcmFields = Pkcs11TelemetryRedaction.MechanismParameters(new CK_MECHANISM_TYPE(Pkcs11MechanismTypes.AesGcm.Value), gcm);
        Assert.Contains(gcmFields, f => f.Name == "mechanism.ivBits" && f.Value == "32");
        Assert.Contains(gcmFields, f => f.Name == "mechanism.tagBits" && f.Value == "96");
        Assert.Contains(gcmFields, f => f.Name == "mechanism.iv" && f.Classification == Pkcs11TelemetryFieldClassification.LengthOnly && f.Value == "len=4");
        Assert.Contains(gcmFields, f => f.Name == "mechanism.aad" && f.Classification == Pkcs11TelemetryFieldClassification.LengthOnly && f.Value == "len=2");

        Pkcs11OperationTelemetryField[] oaepFields = Pkcs11TelemetryRedaction.MechanismParameters(new CK_MECHANISM_TYPE(Pkcs11MechanismTypes.RsaPkcsOaep.Value), oaep);
        Assert.Contains(oaepFields, f => f.Name == "mechanism.hashAlg" && f.Value == $"0x{Pkcs11MechanismTypes.Sha256.Value:x}");
        Assert.Contains(oaepFields, f => f.Name == "mechanism.mgf" && f.Value == $"0x{Pkcs11RsaMgfTypes.Mgf1Sha256.Value:x}");
        Pkcs11OperationTelemetryField sourceDataField = Assert.Single(oaepFields, f => f.Name == "mechanism.sourceData");
        Assert.Equal(Pkcs11TelemetryFieldClassification.Hashed, sourceDataField.Classification);
        Assert.DoesNotContain("1020", sourceDataField.Value, StringComparison.OrdinalIgnoreCase);

        Pkcs11OperationTelemetryField[] ecdhFields = Pkcs11TelemetryRedaction.MechanismParameters(new CK_MECHANISM_TYPE(Pkcs11MechanismTypes.Ecdh1Derive.Value), ecdh);
        Assert.Contains(ecdhFields, f => f.Name == "mechanism.kdf" && f.Value == $"0x{Pkcs11EcKdfTypes.Null.Value:x}");
        Assert.Contains(ecdhFields, f => f.Name == "mechanism.sharedData" && f.Classification == Pkcs11TelemetryFieldClassification.LengthOnly && f.Value == "len=2");
        Pkcs11OperationTelemetryField publicDataField = Assert.Single(ecdhFields, f => f.Name == "mechanism.publicData");
        Assert.Equal(Pkcs11TelemetryFieldClassification.Hashed, publicDataField.Classification);
        Assert.DoesNotContain("04AABB", publicDataField.Value, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CredentialHelpersUseMaskedAndHashedBuckets()
    {
        Pkcs11OperationTelemetryField[] loginFields = Pkcs11TelemetryRedaction.Credentials(new CK_USER_TYPE((nuint)Pkcs11UserType.User), "123456"u8);
        Assert.Contains(loginFields, f => f.Name == "credential.userType" && f.Value == "CKU_USER");
        Assert.Contains(loginFields, f => f.Name == "credential.pin" && f.Classification == Pkcs11TelemetryFieldClassification.Masked && f.Value == "set(len=6)");

        Pkcs11OperationTelemetryField[] loginUserFields = Pkcs11TelemetryRedaction.Credentials(new CK_USER_TYPE((nuint)Pkcs11UserType.User), "123456"u8, "alice"u8);
        Pkcs11OperationTelemetryField usernameField = Assert.Single(loginUserFields, f => f.Name == "credential.username");
        Assert.Equal(Pkcs11TelemetryFieldClassification.Hashed, usernameField.Classification);
        Assert.DoesNotContain("alice", usernameField.Value, StringComparison.Ordinal);
    }

    private static byte[] PackNuint(nuint value)
    {
        byte[] bytes = new byte[IntPtr.Size];
        if (IntPtr.Size == 8)
        {
            BitConverter.GetBytes((ulong)value).CopyTo(bytes, 0);
        }
        else
        {
            BitConverter.GetBytes((uint)value).CopyTo(bytes, 0);
        }

        return bytes;
    }
}
