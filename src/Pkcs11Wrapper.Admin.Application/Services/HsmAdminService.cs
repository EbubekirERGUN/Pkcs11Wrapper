using System.Text;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Services;

public sealed class HsmAdminService(DeviceProfileService deviceProfiles, AuditLogService auditLog, AdminSessionRegistry sessionRegistry)
{
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

        string pinNote = "public";
        if (!string.IsNullOrWhiteSpace(userPin))
        {
            session.Login(Pkcs11UserType.User, Encoding.UTF8.GetBytes(userPin));
            pinNote = "user-login";
        }

        Pkcs11ObjectSearchParameters search = new(label: string.IsNullOrWhiteSpace(labelFilter) ? default : Encoding.UTF8.GetBytes(labelFilter));
        List<Pkcs11ObjectHandle> handles = EnumerateObjectHandles(session, search);
        List<HsmKeyObjectSummary> keys = handles.Select(handle => ReadObjectSummary(deviceId, slotIdValue, session, handle)).ToList();
        await auditLog.WriteAsync("Key", "List", $"{device.Name}/slot-{slotIdValue}", "Success", $"Loaded {keys.Count} key/object record(s) via {pinNote}.", cancellationToken: cancellationToken);
        return keys;
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

    public async Task DestroyObjectAsync(Guid deviceId, nuint slotIdValue, nuint handleValue, string userPin, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(userPin))
        {
            throw new InvalidOperationException("User PIN is required to destroy objects.");
        }

        HsmDeviceProfile device = await RequireDeviceAsync(deviceId, cancellationToken);
        using Pkcs11Module module = CreateInitializedModule(device);
        using Pkcs11Session session = module.OpenSession(new Pkcs11SlotId(slotIdValue), readWrite: true);
        session.Login(Pkcs11UserType.User, Encoding.UTF8.GetBytes(userPin));
        session.DestroyObject(new Pkcs11ObjectHandle(handleValue));
        await auditLog.WriteAsync("Key", "Destroy", $"{device.Name}/slot-{slotIdValue}/handle-{handleValue}", "Success", "Object destroyed through admin panel.", cancellationToken: cancellationToken);
    }

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

        return Encoding.UTF8.GetString(buffer, 0, written).TrimEnd(' ');
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
}
