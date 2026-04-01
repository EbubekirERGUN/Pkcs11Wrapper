using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Web.Lab;

public sealed record Pkcs11LabPreparedRequest(Pkcs11LabRequest Request, string? WarningMessage = null);

public static class Pkcs11LabRequestReuse
{
    public static Pkcs11LabRequest Copy(Pkcs11LabRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        return new()
        {
            DeviceId = request.DeviceId,
            SlotId = request.SlotId,
            Operation = request.Operation,
            OpenReadWriteSession = request.OpenReadWriteSession,
            LoginUserIfPinProvided = request.LoginUserIfPinProvided,
            UserPin = request.UserPin,
            MechanismTypeText = request.MechanismTypeText,
            AttributeTypeText = request.AttributeTypeText,
            MechanismParameterProfile = request.MechanismParameterProfile,
            MechanismIvHex = request.MechanismIvHex,
            MechanismAdditionalDataHex = request.MechanismAdditionalDataHex,
            MechanismCounterBits = request.MechanismCounterBits,
            MechanismTagBits = request.MechanismTagBits,
            RsaHashProfile = request.RsaHashProfile,
            RsaOaepSourceEncoding = request.RsaOaepSourceEncoding,
            RsaOaepSourceText = request.RsaOaepSourceText,
            RsaOaepSourceHex = request.RsaOaepSourceHex,
            PssSaltLength = request.PssSaltLength,
            KeyHandleText = request.KeyHandleText,
            KeyLabel = request.KeyLabel,
            KeyIdHex = request.KeyIdHex,
            KeyObjectClass = request.KeyObjectClass,
            KeyType = request.KeyType,
            SecondaryKeyHandleText = request.SecondaryKeyHandleText,
            SecondaryKeyLabel = request.SecondaryKeyLabel,
            SecondaryKeyIdHex = request.SecondaryKeyIdHex,
            SecondaryKeyObjectClass = request.SecondaryKeyObjectClass,
            SecondaryKeyType = request.SecondaryKeyType,
            DigestAlgorithm = request.DigestAlgorithm,
            PayloadEncoding = request.PayloadEncoding,
            TextInput = request.TextInput,
            DataHex = request.DataHex,
            SignatureHex = request.SignatureHex,
            UnwrapTargetLabel = request.UnwrapTargetLabel,
            UnwrapTargetIdHex = request.UnwrapTargetIdHex,
            UnwrapTokenObject = request.UnwrapTokenObject,
            UnwrapPrivateObject = request.UnwrapPrivateObject,
            UnwrapSensitive = request.UnwrapSensitive,
            UnwrapExtractable = request.UnwrapExtractable,
            UnwrapAllowEncrypt = request.UnwrapAllowEncrypt,
            UnwrapAllowDecrypt = request.UnwrapAllowDecrypt,
            LabelFilter = request.LabelFilter,
            IdHex = request.IdHex,
            ObjectClassFilter = request.ObjectClassFilter,
            RandomLength = request.RandomLength,
            MaxObjects = request.MaxObjects
        };
    }

    public static Pkcs11LabPreparedRequest PrepareVerify(Pkcs11LabRequest source, Pkcs11LabExecutionResult result)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(result);

        Pkcs11LabRequest request = Copy(source);
        request.Operation = Pkcs11LabOperation.VerifySignature;
        request.SignatureHex = result.ArtifactHex;

        string? targetObjectClass = string.Equals(source.KeyObjectClass, "PrivateKey", StringComparison.OrdinalIgnoreCase)
            && string.Equals(source.KeyType, "RSA", StringComparison.OrdinalIgnoreCase)
            ? "PublicKey"
            : source.KeyObjectClass;

        string? warning = ApplyPrimaryReference(
            request,
            source.KeyHandleText,
            source.KeyLabel,
            source.KeyIdHex,
            targetObjectClass,
            source.KeyType,
            requiresCounterpartResolution: !string.Equals(targetObjectClass, source.KeyObjectClass, StringComparison.OrdinalIgnoreCase),
            warningContext: "verify key");

        return new(request, warning);
    }

    public static Pkcs11LabPreparedRequest PrepareDecrypt(Pkcs11LabRequest source, Pkcs11LabExecutionResult result)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(result);

        Pkcs11LabRequest request = Copy(source);
        request.Operation = Pkcs11LabOperation.DecryptData;
        request.DataHex = result.ArtifactHex;

        string? targetObjectClass = string.Equals(source.KeyObjectClass, "PublicKey", StringComparison.OrdinalIgnoreCase)
            && string.Equals(source.KeyType, "RSA", StringComparison.OrdinalIgnoreCase)
            ? "PrivateKey"
            : source.KeyObjectClass;

        string? warning = ApplyPrimaryReference(
            request,
            source.KeyHandleText,
            source.KeyLabel,
            source.KeyIdHex,
            targetObjectClass,
            source.KeyType,
            requiresCounterpartResolution: !string.Equals(targetObjectClass, source.KeyObjectClass, StringComparison.OrdinalIgnoreCase),
            warningContext: "decrypt key");

        return new(request, warning);
    }

    public static Pkcs11LabPreparedRequest PrepareUnwrap(Pkcs11LabRequest source, Pkcs11LabExecutionResult result)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(result);

        Pkcs11LabRequest request = Copy(source);
        request.Operation = Pkcs11LabOperation.UnwrapAesKey;
        request.KeyHandleText = source.SecondaryKeyHandleText;
        request.KeyLabel = source.SecondaryKeyLabel;
        request.KeyIdHex = source.SecondaryKeyIdHex;
        request.KeyObjectClass = source.SecondaryKeyObjectClass;
        request.KeyType = source.SecondaryKeyType;
        request.SecondaryKeyHandleText = null;
        request.SecondaryKeyLabel = null;
        request.SecondaryKeyIdHex = null;
        request.SecondaryKeyObjectClass = null;
        request.SecondaryKeyType = null;
        request.DataHex = result.ArtifactHex;
        request.SignatureHex = null;
        return new(request);
    }

    public static Pkcs11LabPreparedRequest PrepareInspectCreated(Pkcs11LabRequest source, Pkcs11LabExecutionResult result)
    {
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(result);

        Pkcs11LabRequest request = Copy(source);
        request.Operation = Pkcs11LabOperation.InspectObject;
        request.KeyHandleText = null;
        request.KeyLabel = null;
        request.KeyIdHex = null;
        request.KeyObjectClass = null;
        request.KeyType = null;
        request.SecondaryKeyHandleText = null;
        request.SecondaryKeyLabel = null;
        request.SecondaryKeyIdHex = null;
        request.SecondaryKeyObjectClass = null;
        request.SecondaryKeyType = null;
        request.SignatureHex = null;

        if (CanInspectCreated(result))
        {
            request.KeyLabel = result.CreatedLabel;
            request.KeyIdHex = result.CreatedIdHex;
            request.KeyObjectClass = result.CreatedObjectClass;
            request.KeyType = result.CreatedKeyType;
            return new(request);
        }

        string warning = result.CreatedObjectPersistsAcrossSessions
            ? "Created object follow-up needs locator metadata. Select the object again from Keys or Find Objects before running Inspect."
            : "Created object follow-up is unavailable because the object was created as a transient session object and vanished when the lab session closed.";
        return new(request, warning);
    }

    public static bool CanInspectCreated(Pkcs11LabExecutionResult result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return result.CreatedObjectPersistsAcrossSessions && HasLocator(result.CreatedLabel, result.CreatedIdHex, result.CreatedObjectClass, result.CreatedKeyType);
    }

    public static bool HasLocator(string? label, string? idHex, string? objectClass, string? keyType)
        => !string.IsNullOrWhiteSpace(label)
            || !string.IsNullOrWhiteSpace(idHex)
            || !string.IsNullOrWhiteSpace(objectClass)
            || !string.IsNullOrWhiteSpace(keyType);

    public static string? DescribeLocator(string? label, string? idHex, string? objectClass, string? keyType)
    {
        List<string> parts = [];
        if (!string.IsNullOrWhiteSpace(label))
        {
            parts.Add($"label={label.Trim()}");
        }

        if (!string.IsNullOrWhiteSpace(idHex))
        {
            parts.Add($"id={idHex.Trim()}");
        }

        if (!string.IsNullOrWhiteSpace(objectClass))
        {
            parts.Add($"class={objectClass.Trim()}");
        }

        if (!string.IsNullOrWhiteSpace(keyType))
        {
            parts.Add($"keyType={keyType.Trim()}");
        }

        return parts.Count == 0 ? null : string.Join(" · ", parts);
    }

    private static string? ApplyPrimaryReference(
        Pkcs11LabRequest target,
        string? handleText,
        string? label,
        string? idHex,
        string? objectClass,
        string? keyType,
        bool requiresCounterpartResolution,
        string warningContext)
    {
        target.KeyHandleText = handleText;
        target.KeyLabel = label;
        target.KeyIdHex = idHex;
        target.KeyObjectClass = objectClass;
        target.KeyType = keyType;

        if (!requiresCounterpartResolution)
        {
            return null;
        }

        if (HasLocator(label, idHex, objectClass, keyType))
        {
            target.KeyHandleText = null;
            return null;
        }

        target.KeyHandleText = null;
        return $"The previous run only captured a raw handle, so the {warningContext} could not be re-resolved safely across sessions. Select the counterpart key before running this flow.";
    }
}
