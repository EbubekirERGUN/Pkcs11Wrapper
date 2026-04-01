using System.Globalization;
using System.Text;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Services;

internal static class HsmAdminObjectCatalog
{
    private static readonly Pkcs11AttributeType[] SummaryAttributes =
    [
        Pkcs11AttributeTypes.Label,
        Pkcs11AttributeTypes.Id,
        Pkcs11AttributeTypes.Class,
        Pkcs11AttributeTypes.KeyType,
        Pkcs11AttributeTypes.Encrypt,
        Pkcs11AttributeTypes.Decrypt,
        Pkcs11AttributeTypes.Sign,
        Pkcs11AttributeTypes.Verify,
        Pkcs11AttributeTypes.Wrap,
        Pkcs11AttributeTypes.Unwrap
    ];

    private static readonly AttributeDescriptor[] DetailAttributes =
    [
        new("Label", Pkcs11AttributeTypes.Label, AttributeValueKind.Utf8),
        new("Id", Pkcs11AttributeTypes.Id, AttributeValueKind.Hex),
        new("Class", Pkcs11AttributeTypes.Class, AttributeValueKind.ObjectClass),
        new("Key Type", Pkcs11AttributeTypes.KeyType, AttributeValueKind.KeyType),
        new("Token", Pkcs11AttributeTypes.Token, AttributeValueKind.Boolean),
        new("Private", Pkcs11AttributeTypes.Private, AttributeValueKind.Boolean),
        new("Modifiable", Pkcs11AttributeTypes.Modifiable, AttributeValueKind.Boolean),
        new("Sensitive", Pkcs11AttributeTypes.Sensitive, AttributeValueKind.Boolean, TreatUnreadableAsSensitive: true),
        new("Extractable", Pkcs11AttributeTypes.Extractable, AttributeValueKind.Boolean),
        new("Encrypt", Pkcs11AttributeTypes.Encrypt, AttributeValueKind.Boolean),
        new("Decrypt", Pkcs11AttributeTypes.Decrypt, AttributeValueKind.Boolean),
        new("Sign", Pkcs11AttributeTypes.Sign, AttributeValueKind.Boolean),
        new("Verify", Pkcs11AttributeTypes.Verify, AttributeValueKind.Boolean),
        new("Wrap", Pkcs11AttributeTypes.Wrap, AttributeValueKind.Boolean),
        new("Unwrap", Pkcs11AttributeTypes.Unwrap, AttributeValueKind.Boolean),
        new("Derive", Pkcs11AttributeTypes.Derive, AttributeValueKind.Boolean),
        new("Value Length", Pkcs11AttributeTypes.ValueLen, AttributeValueKind.Nuint),
        new("Modulus Bits", Pkcs11AttributeTypes.ModulusBits, AttributeValueKind.Nuint),
        new("Public Exponent", Pkcs11AttributeTypes.PublicExponent, AttributeValueKind.Hex),
        new("EC Parameters", Pkcs11AttributeTypes.EcParams, AttributeValueKind.Hex),
        new("EC Point", Pkcs11AttributeTypes.EcPoint, AttributeValueKind.Hex)
    ];

    public static HsmKeyObjectSummary ReadObjectSummary(Guid deviceId, nuint slotIdValue, Pkcs11Session session, Pkcs11ObjectHandle handle)
    {
        IReadOnlyList<Pkcs11AttributeValue> values = session.GetAttributeValues(handle, SummaryAttributes);
        return new HsmKeyObjectSummary(
            deviceId,
            slotIdValue,
            handle.Value,
            ReadUtf8Attribute(values, Pkcs11AttributeTypes.Label),
            ReadHexAttribute(values, Pkcs11AttributeTypes.Id),
            DescribeObjectClass(ReadNuintAttribute(values, Pkcs11AttributeTypes.Class)),
            DescribeKeyType(ReadNuintAttribute(values, Pkcs11AttributeTypes.KeyType)),
            ReadBooleanAttribute(values, Pkcs11AttributeTypes.Encrypt),
            ReadBooleanAttribute(values, Pkcs11AttributeTypes.Decrypt),
            ReadBooleanAttribute(values, Pkcs11AttributeTypes.Sign),
            ReadBooleanAttribute(values, Pkcs11AttributeTypes.Verify),
            ReadBooleanAttribute(values, Pkcs11AttributeTypes.Wrap),
            ReadBooleanAttribute(values, Pkcs11AttributeTypes.Unwrap));
    }

    public static HsmObjectDetail ReadObjectDetail(Guid deviceId, nuint slotIdValue, Pkcs11Session session, Pkcs11ObjectHandle handle)
    {
        List<HsmObjectAttributeView> attributes = [];
        foreach (AttributeDescriptor descriptor in DetailAttributes)
        {
            HsmObjectAttributeView? view = ReadAttributeView(session, handle, descriptor);
            if (view is not null)
            {
                attributes.Add(view);
            }
        }

        ObjectEditCapabilities editCapabilities = BuildEditCapabilities(session, handle);

        return new HsmObjectDetail(
            deviceId,
            slotIdValue,
            handle.Value,
            ReadUtf8Attribute(session, handle, Pkcs11AttributeTypes.Label),
            ReadHexAttribute(session, handle, Pkcs11AttributeTypes.Id),
            DescribeObjectClass(ReadNuintAttribute(session, handle, Pkcs11AttributeTypes.Class)),
            DescribeKeyType(ReadNuintAttribute(session, handle, Pkcs11AttributeTypes.KeyType)),
            ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Token),
            ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Private),
            ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Modifiable),
            ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Sensitive),
            ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Extractable),
            ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Encrypt),
            ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Decrypt),
            ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Sign),
            ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Verify),
            ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Wrap),
            ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Unwrap),
            ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Derive),
            ReadObjectSize(session, handle),
            ReadNuintAttribute(session, handle, Pkcs11AttributeTypes.ValueLen),
            ReadNuintAttribute(session, handle, Pkcs11AttributeTypes.ModulusBits),
            ReadHexAttribute(session, handle, Pkcs11AttributeTypes.PublicExponent),
            ReadHexAttribute(session, handle, Pkcs11AttributeTypes.EcParams),
            editCapabilities,
            attributes);
    }

    public static List<Pkcs11ObjectHandle> EnumerateObjectHandles(Pkcs11Session session, Pkcs11ObjectSearchParameters search)
    {
        List<Pkcs11ObjectHandle> results = [];
        Pkcs11ObjectHandle[] buffer = new Pkcs11ObjectHandle[64];
        bool hasMore;
        do
        {
            session.TryFindObjects(search, buffer, out int written, out hasMore);
            for (int i = 0; i < written; i++)
            {
                results.Add(buffer[i]);
            }
        }
        while (hasMore);

        return results;
    }

    public static List<Pkcs11ObjectHandle> EnumerateObjectHandles(Pkcs11Session session, Pkcs11ObjectSearchParameters search, int maxCount, out bool truncated)
    {
        List<Pkcs11ObjectHandle> results = [];
        Pkcs11ObjectHandle[] buffer = new Pkcs11ObjectHandle[Math.Min(Math.Max(maxCount, 1), 64)];
        bool hasMore;
        truncated = false;

        do
        {
            session.TryFindObjects(search, buffer, out int written, out hasMore);
            for (int i = 0; i < written; i++)
            {
                results.Add(buffer[i]);
                if (results.Count >= maxCount)
                {
                    truncated = hasMore || i + 1 < written;
                    return results;
                }
            }
        }
        while (hasMore);

        return results;
    }

    public static string DescribeCapabilities(HsmKeyObjectSummary summary)
    {
        List<string> capabilities = [];
        if (summary.CanEncrypt == true) capabilities.Add("Encrypt");
        if (summary.CanDecrypt == true) capabilities.Add("Decrypt");
        if (summary.CanSign == true) capabilities.Add("Sign");
        if (summary.CanVerify == true) capabilities.Add("Verify");
        if (summary.CanWrap == true) capabilities.Add("Wrap");
        if (summary.CanUnwrap == true) capabilities.Add("Unwrap");
        return capabilities.Count == 0 ? "<none>" : string.Join(", ", capabilities);
    }

    public static string DescribeObjectClass(nuint? value)
        => value switch
        {
            null => "n/a",
            0x00000000u => "Data",
            0x00000001u => "Certificate",
            0x00000002u => "PublicKey",
            0x00000003u => "PrivateKey",
            0x00000004u => "SecretKey",
            _ => $"0x{value:x}"
        };

    public static string DescribeKeyType(nuint? value)
        => value switch
        {
            null => "n/a",
            0x00000000u => "RSA",
            0x00000001u => "DSA",
            0x00000002u => "DH",
            0x00000003u => "EC",
            0x00000010u => "GenericSecret",
            0x0000001fu => "AES",
            _ => $"0x{value:x}"
        };

    private static ObjectEditCapabilities BuildEditCapabilities(Pkcs11Session session, Pkcs11ObjectHandle handle)
    {
        bool modifiable = ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Modifiable) == true;
        nuint? objectClass = ReadNuintAttribute(session, handle, Pkcs11AttributeTypes.Class);
        bool isSecretOrPrivate = objectClass is 0x00000003u or 0x00000004u;
        bool isSecret = objectClass == 0x00000004u;
        bool isPrivate = objectClass == 0x00000003u;
        bool isPublic = objectClass == 0x00000002u;

        List<string> warnings = [];
        if (!modifiable)
        {
            warnings.Add("CKA_MODIFIABLE is not true/readable for this object, so token-side SetAttributeValue may reject edits.");
        }

        return new ObjectEditCapabilities(
            modifiable,
            modifiable,
            modifiable && isSecretOrPrivate,
            modifiable && isSecretOrPrivate,
            modifiable && (isSecret || isPublic),
            modifiable && (isSecret || isPrivate),
            modifiable && isPrivate,
            modifiable && isPublic,
            modifiable && isSecret,
            modifiable && isSecret,
            modifiable && isPrivate,
            warnings);
    }

    private static HsmObjectAttributeView? ReadAttributeView(Pkcs11Session session, Pkcs11ObjectHandle handle, AttributeDescriptor descriptor)
    {
        if (!TryGetAttributeValueInfo(session, handle, descriptor.Type, out Pkcs11AttributeReadResult info))
        {
            return null;
        }

        if (descriptor.TreatUnreadableAsSensitive && info.Status == Pkcs11AttributeReadStatus.Sensitive)
        {
            return new HsmObjectAttributeView(descriptor.Name, "[sensitive]", true);
        }

        if (!info.IsReadable || info.Length > int.MaxValue)
        {
            return null;
        }

        string? value = descriptor.Kind switch
        {
            AttributeValueKind.Boolean => ReadBooleanAttribute(session, handle, descriptor.Type)?.ToString(),
            AttributeValueKind.Nuint => ReadNuintAttribute(session, handle, descriptor.Type)?.ToString(CultureInfo.InvariantCulture),
            AttributeValueKind.Utf8 => ReadUtf8Attribute(session, handle, descriptor.Type),
            AttributeValueKind.Hex => ReadHexAttribute(session, handle, descriptor.Type),
            AttributeValueKind.ObjectClass => DescribeObjectClass(ReadNuintAttribute(session, handle, descriptor.Type)),
            AttributeValueKind.KeyType => DescribeKeyType(ReadNuintAttribute(session, handle, descriptor.Type)),
            _ => null
        };

        return string.IsNullOrWhiteSpace(value) ? null : new HsmObjectAttributeView(descriptor.Name, value);
    }

    private static string? ReadUtf8Attribute(IReadOnlyList<Pkcs11AttributeValue> values, Pkcs11AttributeType attributeType)
    {
        if (!TryGetValue(values, attributeType, out Pkcs11AttributeValue value) || value.Value is null || value.Value.Length == 0)
        {
            return null;
        }

        return Encoding.UTF8.GetString(value.Value).TrimEnd('\0');
    }

    private static string? ReadHexAttribute(IReadOnlyList<Pkcs11AttributeValue> values, Pkcs11AttributeType attributeType)
    {
        if (!TryGetValue(values, attributeType, out Pkcs11AttributeValue value) || value.Value is null || value.Value.Length == 0)
        {
            return null;
        }

        return Convert.ToHexString(value.Value);
    }

    private static bool? ReadBooleanAttribute(IReadOnlyList<Pkcs11AttributeValue> values, Pkcs11AttributeType attributeType)
    {
        if (!TryGetValue(values, attributeType, out Pkcs11AttributeValue value) || value.Value is null || value.Value.Length != 1)
        {
            return null;
        }

        return value.Value[0] != 0;
    }

    private static nuint? ReadNuintAttribute(IReadOnlyList<Pkcs11AttributeValue> values, Pkcs11AttributeType attributeType)
    {
        if (!TryGetValue(values, attributeType, out Pkcs11AttributeValue value) || value.Value is null || value.Value.Length != IntPtr.Size)
        {
            return null;
        }

        return IntPtr.Size == sizeof(uint)
            ? (nuint)BitConverter.ToUInt32(value.Value)
            : (nuint)BitConverter.ToUInt64(value.Value);
    }

    private static bool TryGetValue(IReadOnlyList<Pkcs11AttributeValue> values, Pkcs11AttributeType attributeType, out Pkcs11AttributeValue value)
    {
        for (int i = 0; i < values.Count; i++)
        {
            if (values[i].Type == attributeType)
            {
                value = values[i];
                return true;
            }
        }

        value = default;
        return false;
    }

    private static string? ReadUtf8Attribute(Pkcs11Session session, Pkcs11ObjectHandle handle, Pkcs11AttributeType attributeType)
    {
        if (!TryGetAttributeValueInfo(session, handle, attributeType, out Pkcs11AttributeReadResult info))
        {
            return null;
        }

        if (!info.IsReadable || info.Length > int.MaxValue || info.Length == 0)
        {
            return null;
        }

        byte[] buffer = new byte[(int)info.Length];
        if (!session.TryGetAttributeValue(handle, attributeType, buffer, out int written, out _))
        {
            return null;
        }

        return Encoding.UTF8.GetString(buffer, 0, written).TrimEnd('\0');
    }

    private static string? ReadHexAttribute(Pkcs11Session session, Pkcs11ObjectHandle handle, Pkcs11AttributeType attributeType)
    {
        if (!TryGetAttributeValueInfo(session, handle, attributeType, out Pkcs11AttributeReadResult info))
        {
            return null;
        }

        if (!info.IsReadable || info.Length > int.MaxValue || info.Length == 0)
        {
            return null;
        }

        byte[] buffer = new byte[(int)info.Length];
        if (!session.TryGetAttributeValue(handle, attributeType, buffer, out int written, out _))
        {
            return null;
        }

        return Convert.ToHexString(buffer.AsSpan(0, written));
    }

    private static bool? ReadBooleanAttribute(Pkcs11Session session, Pkcs11ObjectHandle handle, Pkcs11AttributeType attributeType)
    {
        if (!TryGetAttributeValueInfo(session, handle, attributeType, out _))
        {
            return null;
        }

        return session.TryGetAttributeBoolean(handle, attributeType, out bool value, out _) ? value : null;
    }

    private static nuint? ReadNuintAttribute(Pkcs11Session session, Pkcs11ObjectHandle handle, Pkcs11AttributeType attributeType)
    {
        if (!TryGetAttributeValueInfo(session, handle, attributeType, out _))
        {
            return null;
        }

        return session.TryGetAttributeNuint(handle, attributeType, out nuint value, out _) ? value : null;
    }

    private static bool TryGetAttributeValueInfo(Pkcs11Session session, Pkcs11ObjectHandle handle, Pkcs11AttributeType attributeType, out Pkcs11AttributeReadResult info)
    {
        try
        {
            info = session.GetAttributeValueInfo(handle, attributeType);
            return true;
        }
        catch
        {
            info = new Pkcs11AttributeReadResult(Pkcs11AttributeReadStatus.TypeInvalid, nuint.MaxValue);
            return false;
        }
    }

    private static nuint? ReadObjectSize(Pkcs11Session session, Pkcs11ObjectHandle handle)
    {
        try
        {
            return session.GetObjectSize(handle);
        }
        catch
        {
            return null;
        }
    }

    private enum AttributeValueKind
    {
        Utf8 = 0,
        Hex = 1,
        Boolean = 2,
        Nuint = 3,
        ObjectClass = 4,
        KeyType = 5
    }

    private sealed record AttributeDescriptor(string Name, Pkcs11AttributeType Type, AttributeValueKind Kind, bool TreatUnreadableAsSensitive = false);
}
