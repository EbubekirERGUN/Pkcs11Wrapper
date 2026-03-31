using System.Globalization;
using System.Text;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Services;

public sealed class HsmAdminService(DeviceProfileService deviceProfiles, AuditLogService auditLog, AdminSessionRegistry sessionRegistry)
{
    private const string DestroyConfirmationPrefix = "DESTROY ";

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

    public Task<IReadOnlyList<HsmDeviceProfile>> GetDevicesAsync(CancellationToken cancellationToken = default)
        => deviceProfiles.GetAllAsync(cancellationToken);

    public Task<HsmDeviceProfile> SaveDeviceAsync(Guid? id, HsmDeviceProfileInput input, CancellationToken cancellationToken = default)
        => deviceProfiles.UpsertAsync(id, input, cancellationToken);

    public async Task DeleteDeviceAsync(Guid id, CancellationToken cancellationToken = default)
    {
        HsmDeviceProfile? existing = await deviceProfiles.GetAsync(id, cancellationToken);
        await deviceProfiles.DeleteAsync(id, cancellationToken);
        await auditLog.WriteAsync("Device", "Delete", existing?.Name ?? id.ToString(), "Success", "Device profile removed.", cancellationToken: cancellationToken);
    }

    public IReadOnlyList<AdminSessionSnapshot> GetSessions() => sessionRegistry.GetSnapshots();

    public Task<IReadOnlyList<AdminAuditLogEntry>> GetAuditLogsAsync(int take = 200, CancellationToken cancellationToken = default)
        => auditLog.GetRecentAsync(take, cancellationToken);

    public async Task<DashboardSummary> GetDashboardAsync(CancellationToken cancellationToken = default)
    {
        IReadOnlyList<HsmDeviceProfile> devices = await deviceProfiles.GetAllAsync(cancellationToken);
        IReadOnlyList<AdminAuditLogEntry> logs = await auditLog.GetRecentAsync(25, cancellationToken);
        return new DashboardSummary(devices.Count, devices.Count(x => x.IsEnabled), sessionRegistry.GetSnapshots().Count, logs.Count);
    }

    public async Task<HsmConnectionTestResult> TestConnectionAsync(Guid deviceId, CancellationToken cancellationToken = default)
    {
        HsmDeviceProfile device = await RequireDeviceAsync(deviceId, cancellationToken);

        try
        {
            using Pkcs11Module module = CreateInitializedModule(device);
            Pkcs11ModuleInfo info = module.GetInfo();
            int slotCount = module.GetSlotCount();
            HsmConnectionTestResult result = new(true, $"Connected. Slots discovered: {slotCount}.", slotCount, module.SupportsInterfaceDiscovery, info.LibraryDescription, info.ManufacturerId);
            await auditLog.WriteAsync("Device", "TestConnection", device.Name, "Success", result.Message, cancellationToken: cancellationToken);
            return result;
        }
        catch (Exception ex)
        {
            await auditLog.WriteAsync("Device", "TestConnection", device.Name, "Failure", ex.Message, cancellationToken: cancellationToken);
            return new(false, ex.Message, 0, false, null, null, ex.GetType().Name);
        }
    }

    public async Task<IReadOnlyList<HsmSlotSummary>> GetSlotsAsync(Guid deviceId, CancellationToken cancellationToken = default)
    {
        HsmDeviceProfile device = await RequireDeviceAsync(deviceId, cancellationToken);
        using Pkcs11Module module = CreateInitializedModule(device);

        int slotCount = module.GetSlotCount();
        if (slotCount == 0)
        {
            await auditLog.WriteAsync("Slot", "List", device.Name, "Success", "No slots found.", cancellationToken: cancellationToken);
            return [];
        }

        Pkcs11SlotId[] slots = new Pkcs11SlotId[slotCount];
        if (!module.TryGetSlots(slots, out int written))
        {
            throw new InvalidOperationException("Failed to read slot list.");
        }

        List<HsmSlotSummary> summaries = [];
        for (int i = 0; i < written; i++)
        {
            Pkcs11SlotId slotId = slots[i];
            Pkcs11SlotInfo slotInfo = module.GetSlotInfo(slotId);
            bool hasToken = module.TryGetTokenInfo(slotId, out Pkcs11TokenInfo tokenInfo);
            int mechanismCount = 0;
            try
            {
                mechanismCount = module.GetMechanismCount(slotId);
            }
            catch
            {
                mechanismCount = 0;
            }

            summaries.Add(new HsmSlotSummary(
                device.Id,
                slotId.Value,
                slotInfo.SlotDescription,
                slotInfo.ManufacturerId,
                slotInfo.Flags.ToString(),
                hasToken,
                hasToken ? tokenInfo.Label : null,
                hasToken ? tokenInfo.Model : null,
                hasToken ? tokenInfo.SerialNumber : null,
                hasToken ? tokenInfo.Flags.ToString() : null,
                mechanismCount));
        }

        await auditLog.WriteAsync("Slot", "List", device.Name, "Success", $"Loaded {summaries.Count} slot(s).", cancellationToken: cancellationToken);
        return summaries;
    }

    public async Task<IReadOnlyList<HsmKeyObjectSummary>> GetKeysAsync(Guid deviceId, nuint slotIdValue, string? userPin, string? labelFilter, CancellationToken cancellationToken = default)
    {
        HsmDeviceProfile device = await RequireDeviceAsync(deviceId, cancellationToken);
        using Pkcs11Module module = CreateInitializedModule(device);
        using Pkcs11Session session = module.OpenSession(new Pkcs11SlotId(slotIdValue));

        string pinNote = LoginIfProvided(session, userPin);
        Pkcs11ObjectSearchParameters search = new(label: string.IsNullOrWhiteSpace(labelFilter) ? default : Encoding.UTF8.GetBytes(labelFilter));
        List<Pkcs11ObjectHandle> handles = EnumerateObjectHandles(session, search);
        List<HsmKeyObjectSummary> keys = handles.Select(handle => ReadObjectSummary(deviceId, slotIdValue, session, handle)).ToList();
        await auditLog.WriteAsync("Key", "List", $"{device.Name}/slot-{slotIdValue}", "Success", $"Loaded {keys.Count} key/object record(s) via {pinNote}.", cancellationToken: cancellationToken);
        return keys;
    }

    public async Task<HsmObjectDetail> GetObjectDetailAsync(Guid deviceId, nuint slotIdValue, nuint handleValue, string? userPin, CancellationToken cancellationToken = default)
    {
        HsmDeviceProfile device = await RequireDeviceAsync(deviceId, cancellationToken);
        using Pkcs11Module module = CreateInitializedModule(device);
        using Pkcs11Session session = module.OpenSession(new Pkcs11SlotId(slotIdValue));
        string pinNote = LoginIfProvided(session, userPin);

        HsmObjectDetail detail = ReadObjectDetail(deviceId, slotIdValue, session, new Pkcs11ObjectHandle(handleValue));
        await auditLog.WriteAsync("Key", "Detail", $"{device.Name}/slot-{slotIdValue}/handle-{handleValue}", "Success", $"Loaded object detail via {pinNote}.", cancellationToken: cancellationToken);
        return detail;
    }

    public async Task<KeyManagementResult> GenerateAesKeyAsync(Guid deviceId, nuint slotIdValue, GenerateAesKeyRequest request, string userPin, CancellationToken cancellationToken = default)
    {
        ValidateGenerateAesKeyRequest(request);
        byte[] id = ParseOptionalHex(request.IdHex, nameof(request.IdHex));
        byte[] label = Encoding.UTF8.GetBytes(request.Label.Trim());

        HsmDeviceProfile device = await RequireDeviceAsync(deviceId, cancellationToken);
        using Pkcs11Module module = CreateInitializedModule(device);
        using Pkcs11Session session = module.OpenSession(new Pkcs11SlotId(slotIdValue), readWrite: true);
        RequireUserPin(userPin, "generate AES keys");
        session.Login(Pkcs11UserType.User, Encoding.UTF8.GetBytes(userPin));

        Pkcs11ObjectHandle handle = session.GenerateKey(new Pkcs11Mechanism(Pkcs11MechanismTypes.AesKeyGen), CreateAesTemplate(request, label, id));
        string idHex = id.Length == 0 ? "(empty)" : Convert.ToHexString(id);
        KeyManagementResult result = new("GenerateAesKey", $"Generated AES-{request.SizeBytes * 8} key '{request.Label.Trim()}' (handle {handle.Value}).", [handle.Value], request.Label.Trim(), id.Length == 0 ? null : idHex);
        await auditLog.WriteAsync("Key", "GenerateAes", $"{device.Name}/slot-{slotIdValue}/handle-{handle.Value}", "Success", result.Summary, cancellationToken: cancellationToken);
        return result;
    }

    public async Task<KeyManagementResult> GenerateRsaKeyPairAsync(Guid deviceId, nuint slotIdValue, GenerateRsaKeyPairRequest request, string userPin, CancellationToken cancellationToken = default)
    {
        ValidateGenerateRsaKeyPairRequest(request);
        byte[] id = ParseOptionalHex(request.IdHex, nameof(request.IdHex));
        byte[] label = Encoding.UTF8.GetBytes(request.Label.Trim());
        byte[] exponent = ParseRequiredHex(request.PublicExponentHex, nameof(request.PublicExponentHex));

        HsmDeviceProfile device = await RequireDeviceAsync(deviceId, cancellationToken);
        using Pkcs11Module module = CreateInitializedModule(device);
        using Pkcs11Session session = module.OpenSession(new Pkcs11SlotId(slotIdValue), readWrite: true);
        RequireUserPin(userPin, "generate RSA key pairs");
        session.Login(Pkcs11UserType.User, Encoding.UTF8.GetBytes(userPin));

        Pkcs11GeneratedKeyPair pair = session.GenerateKeyPair(
            new Pkcs11Mechanism(Pkcs11MechanismTypes.RsaPkcsKeyPairGen),
            CreateRsaPublicTemplate(request, label, id, exponent),
            CreateRsaPrivateTemplate(request, label, id));

        string summary = $"Generated RSA-{request.ModulusBits} key pair '{request.Label.Trim()}' (public {pair.PublicKeyHandle.Value}, private {pair.PrivateKeyHandle.Value}).";
        KeyManagementResult result = new("GenerateRsaKeyPair", summary, [pair.PublicKeyHandle.Value, pair.PrivateKeyHandle.Value], request.Label.Trim(), id.Length == 0 ? null : Convert.ToHexString(id));
        await auditLog.WriteAsync("Key", "GenerateRsa", $"{device.Name}/slot-{slotIdValue}", "Success", summary, cancellationToken: cancellationToken);
        return result;
    }

    public async Task<AdminSessionSnapshot> OpenSessionAsync(Guid deviceId, nuint slotIdValue, bool readWrite, string? userPin, CancellationToken cancellationToken = default)
    {
        HsmDeviceProfile device = await RequireDeviceAsync(deviceId, cancellationToken);
        Pkcs11Module module = CreateInitializedModule(device);
        try
        {
            Pkcs11Session session = module.OpenSession(new Pkcs11SlotId(slotIdValue), readWrite);
            string notes = "Public session";
            if (!string.IsNullOrWhiteSpace(userPin))
            {
                session.Login(Pkcs11UserType.User, Encoding.UTF8.GetBytes(userPin));
                notes = "User-authenticated session";
            }

            AdminSessionSnapshot snapshot = sessionRegistry.Register(device.Id, device.Name, module, session, readWrite, notes);
            await auditLog.WriteAsync("Session", "Open", $"{device.Name}/slot-{slotIdValue}", "Success", $"Opened {(readWrite ? "read-write" : "read-only")} session.", cancellationToken: cancellationToken);
            return snapshot;
        }
        catch
        {
            module.Dispose();
            throw;
        }
    }

    public async Task<bool> CloseSessionAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        bool closed = await sessionRegistry.CloseAsync(sessionId);
        await auditLog.WriteAsync("Session", "Close", sessionId.ToString(), closed ? "Success" : "NotFound", closed ? "Session closed." : "Session was not found.", cancellationToken: cancellationToken);
        return closed;
    }

    public async Task CloseAllSessionsAsync(Guid deviceId, nuint slotIdValue, CancellationToken cancellationToken = default)
    {
        HsmDeviceProfile device = await RequireDeviceAsync(deviceId, cancellationToken);
        using Pkcs11Module module = CreateInitializedModule(device);
        module.CloseAllSessions(new Pkcs11SlotId(slotIdValue));
        await auditLog.WriteAsync("Session", "CloseAll", $"{device.Name}/slot-{slotIdValue}", "Success", "Invoked CloseAllSessions on slot.", cancellationToken: cancellationToken);
    }

    public async Task DestroyObjectAsync(Guid deviceId, nuint slotIdValue, DestroyObjectRequest request, CancellationToken cancellationToken = default)
    {
        ValidateDestroyRequest(request);

        HsmDeviceProfile device = await RequireDeviceAsync(deviceId, cancellationToken);
        using Pkcs11Module module = CreateInitializedModule(device);
        using Pkcs11Session session = module.OpenSession(new Pkcs11SlotId(slotIdValue), readWrite: true);
        session.Login(Pkcs11UserType.User, Encoding.UTF8.GetBytes(request.UserPin));
        session.DestroyObject(new Pkcs11ObjectHandle(request.Handle));
        await auditLog.WriteAsync("Key", "Destroy", $"{device.Name}/slot-{slotIdValue}/handle-{request.Handle}", "Success", "Object destroyed through admin panel after typed confirmation.", cancellationToken: cancellationToken);
    }

    public static void ValidateGenerateAesKeyRequest(GenerateAesKeyRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Label))
        {
            throw new ArgumentException("Label is required.", nameof(request));
        }

        if (!request.AllowEncrypt && !request.AllowDecrypt && !request.AllowWrap && !request.AllowUnwrap)
        {
            throw new ArgumentException("Select at least one AES capability.", nameof(request));
        }

        if (request.SizeBytes is not (16 or 24 or 32 or 48 or 64))
        {
            throw new ArgumentOutOfRangeException(nameof(request), "AES key size must be one of: 16, 24, 32, 48, or 64 bytes.");
        }

        _ = ParseOptionalHex(request.IdHex, nameof(request.IdHex));
    }

    public static void ValidateGenerateRsaKeyPairRequest(GenerateRsaKeyPairRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Label))
        {
            throw new ArgumentException("Label is required.", nameof(request));
        }

        if (!request.AllowSign && !request.AllowDecrypt)
        {
            throw new ArgumentException("Private key must allow sign and/or decrypt.", nameof(request));
        }

        if (!request.AllowVerify && !request.AllowEncrypt)
        {
            throw new ArgumentException("Public key must allow verify and/or encrypt.", nameof(request));
        }

        if (request.ModulusBits < 1024 || request.ModulusBits % 256 != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "RSA modulus bits must be at least 1024 and aligned to 256-bit steps.");
        }

        byte[] exponent = ParseRequiredHex(request.PublicExponentHex, nameof(request.PublicExponentHex));
        if (exponent.Length == 0)
        {
            throw new ArgumentException("Public exponent cannot be empty.", nameof(request));
        }

        _ = ParseOptionalHex(request.IdHex, nameof(request.IdHex));
    }

    public static void ValidateDestroyRequest(DestroyObjectRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        RequireUserPin(request.UserPin, "destroy objects");

        if (!request.AcknowledgePermanentDeletion)
        {
            throw new InvalidOperationException("Permanent deletion must be explicitly acknowledged.");
        }

        string expected = BuildDestroyConfirmationText(request.Handle, request.Label);
        if (!string.Equals(request.ConfirmationText?.Trim(), expected, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Confirmation text mismatch. Type '{expected}' to destroy the object.");
        }
    }

    public static string BuildDestroyConfirmationText(nuint handle, string? label)
        => string.IsNullOrWhiteSpace(label)
            ? $"{DestroyConfirmationPrefix}{handle}"
            : $"{DestroyConfirmationPrefix}{handle} {label.Trim()}";

    private static HsmKeyObjectSummary ReadObjectSummary(Guid deviceId, nuint slotIdValue, Pkcs11Session session, Pkcs11ObjectHandle handle)
    {
        string? label = ReadUtf8Attribute(session, handle, Pkcs11AttributeTypes.Label);
        string? idHex = ReadHexAttribute(session, handle, Pkcs11AttributeTypes.Id);
        string objectClass = DescribeObjectClass(ReadNuintAttribute(session, handle, Pkcs11AttributeTypes.Class));
        string keyType = DescribeKeyType(ReadNuintAttribute(session, handle, Pkcs11AttributeTypes.KeyType));
        bool? canEncrypt = ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Encrypt);
        bool? canDecrypt = ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Decrypt);
        bool? canSign = ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Sign);
        bool? canVerify = ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Verify);
        bool? canWrap = ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Wrap);
        bool? canUnwrap = ReadBooleanAttribute(session, handle, Pkcs11AttributeTypes.Unwrap);

        return new HsmKeyObjectSummary(deviceId, slotIdValue, handle.Value, label, idHex, objectClass, keyType, canEncrypt, canDecrypt, canSign, canVerify, canWrap, canUnwrap);
    }

    private static HsmObjectDetail ReadObjectDetail(Guid deviceId, nuint slotIdValue, Pkcs11Session session, Pkcs11ObjectHandle handle)
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
            attributes);
    }

    private static HsmObjectAttributeView? ReadAttributeView(Pkcs11Session session, Pkcs11ObjectHandle handle, AttributeDescriptor descriptor)
    {
        Pkcs11AttributeReadResult info = session.GetAttributeValueInfo(handle, descriptor.Type);
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

    private static List<Pkcs11ObjectHandle> EnumerateObjectHandles(Pkcs11Session session, Pkcs11ObjectSearchParameters search)
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

    private static string LoginIfProvided(Pkcs11Session session, string? userPin)
    {
        if (string.IsNullOrWhiteSpace(userPin))
        {
            return "public";
        }

        session.Login(Pkcs11UserType.User, Encoding.UTF8.GetBytes(userPin));
        return "user-login";
    }

    private static string? ReadUtf8Attribute(Pkcs11Session session, Pkcs11ObjectHandle handle, Pkcs11AttributeType attributeType)
    {
        Pkcs11AttributeReadResult info = session.GetAttributeValueInfo(handle, attributeType);
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
        Pkcs11AttributeReadResult info = session.GetAttributeValueInfo(handle, attributeType);
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
        => session.TryGetAttributeBoolean(handle, attributeType, out bool value, out _) ? value : null;

    private static nuint? ReadNuintAttribute(Pkcs11Session session, Pkcs11ObjectHandle handle, Pkcs11AttributeType attributeType)
        => session.TryGetAttributeNuint(handle, attributeType, out nuint value, out _) ? value : null;

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

    private static string DescribeObjectClass(nuint? value)
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

    private static string DescribeKeyType(nuint? value)
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

    private static byte[] ParseOptionalHex(string? value, string paramName)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return [];
        }

        return ParseRequiredHex(value, paramName);
    }

    private static byte[] ParseRequiredHex(string? value, string paramName)
    {
        string normalized = new((value ?? string.Empty).Where(ch => !char.IsWhiteSpace(ch) && ch != '-' && ch != ':').ToArray());
        if (string.IsNullOrWhiteSpace(normalized))
        {
            throw new ArgumentException("Hex input is required.", paramName);
        }

        if (normalized.Length % 2 != 0)
        {
            throw new ArgumentException("Hex input must contain an even number of characters.", paramName);
        }

        try
        {
            return Convert.FromHexString(normalized);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("Hex input contains invalid characters.", paramName, ex);
        }
    }

    private static void RequireUserPin(string? userPin, string operation)
    {
        if (string.IsNullOrWhiteSpace(userPin))
        {
            throw new InvalidOperationException($"User PIN is required to {operation}.");
        }
    }

    private static Pkcs11ObjectAttribute[] CreateAesTemplate(GenerateAesKeyRequest request, byte[] label, byte[] id)
        =>
        [
            Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.SecretKey),
            Pkcs11ObjectAttribute.KeyType(Pkcs11AttributeTypes.KeyType, Pkcs11KeyTypes.Aes),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, request.Token),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, request.Private),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Encrypt, request.AllowEncrypt),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Decrypt, request.AllowDecrypt),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Wrap, request.AllowWrap),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Unwrap, request.AllowUnwrap),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Sensitive, request.Sensitive),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Extractable, request.Extractable),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, label),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Id, id),
            Pkcs11ObjectAttribute.Nuint(Pkcs11AttributeTypes.ValueLen, (nuint)request.SizeBytes)
        ];

    private static Pkcs11ObjectAttribute[] CreateRsaPublicTemplate(GenerateRsaKeyPairRequest request, byte[] label, byte[] id, byte[] exponent)
        =>
        [
            Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.PublicKey),
            Pkcs11ObjectAttribute.KeyType(Pkcs11AttributeTypes.KeyType, Pkcs11KeyTypes.Rsa),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, request.Token),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, false),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Verify, request.AllowVerify),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Encrypt, request.AllowEncrypt),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, label),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Id, id),
            Pkcs11ObjectAttribute.Nuint(Pkcs11AttributeTypes.ModulusBits, (nuint)request.ModulusBits),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.PublicExponent, exponent)
        ];

    private static Pkcs11ObjectAttribute[] CreateRsaPrivateTemplate(GenerateRsaKeyPairRequest request, byte[] label, byte[] id)
        =>
        [
            Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.PrivateKey),
            Pkcs11ObjectAttribute.KeyType(Pkcs11AttributeTypes.KeyType, Pkcs11KeyTypes.Rsa),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, request.Token),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, true),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Sign, request.AllowSign),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Decrypt, request.AllowDecrypt),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Sensitive, request.Sensitive),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Extractable, request.Extractable),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, label),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Id, id)
        ];

    private static Pkcs11Module CreateInitializedModule(HsmDeviceProfile device)
    {
        Pkcs11Module module = Pkcs11Module.Load(device.ModulePath);
        module.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));
        return module;
    }

    private async Task<HsmDeviceProfile> RequireDeviceAsync(Guid deviceId, CancellationToken cancellationToken)
    {
        HsmDeviceProfile? device = await deviceProfiles.GetAsync(deviceId, cancellationToken);
        return device ?? throw new InvalidOperationException($"Device profile '{deviceId}' was not found.");
    }

    private enum AttributeValueKind
    {
        Utf8,
        Hex,
        Boolean,
        Nuint,
        ObjectClass,
        KeyType
    }

    private sealed record AttributeDescriptor(string Name, Pkcs11AttributeType Type, AttributeValueKind Kind, bool TreatUnreadableAsSensitive = false);
}
