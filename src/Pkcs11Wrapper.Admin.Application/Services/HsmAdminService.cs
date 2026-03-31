using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.Json;
using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Application.Services;

public sealed class HsmAdminService(DeviceProfileService deviceProfiles, AuditLogService auditLog, AdminSessionRegistry sessionRegistry, IAdminAuthorizationService authorization)
{
    private const string DestroyConfirmationPrefix = "DESTROY ";
    private const string ConfigurationFormat = "Pkcs11Wrapper.Admin.Configuration";
    private const int ConfigurationSchemaVersion = 1;

    private static readonly string[] ConfigurationIncludedSections =
    [
        "DeviceProfiles"
    ];

    private static readonly string[] ConfigurationExcludedSections =
    [
        "AdminUsers",
        "BootstrapCredentials",
        "AuditLog",
        "ProtectedPinCache",
        "DataProtectionKeys"
    ];

    private static readonly (Pkcs11MechanismType Type, string Name)[] KeyMechanisms =
    [
        (Pkcs11MechanismTypes.AesKeyGen, "CKM_AES_KEY_GEN"),
        (Pkcs11MechanismTypes.RsaPkcsKeyPairGen, "CKM_RSA_PKCS_KEY_PAIR_GEN"),
        (Pkcs11MechanismTypes.AesCbc, "CKM_AES_CBC"),
        (Pkcs11MechanismTypes.AesKeyWrapPad, "CKM_AES_KEY_WRAP_PAD"),
        (Pkcs11MechanismTypes.RsaPkcs, "CKM_RSA_PKCS")
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

    public Task<IReadOnlyList<HsmDeviceProfile>> GetDevicesAsync(CancellationToken cancellationToken = default)
    {
        authorization.DemandViewer();
        return deviceProfiles.GetAllAsync(cancellationToken);
    }

    public Task<HsmDeviceProfile> SaveDeviceAsync(Guid? id, HsmDeviceProfileInput input, CancellationToken cancellationToken = default)
    {
        authorization.DemandAdmin();
        return deviceProfiles.UpsertAsync(id, input, cancellationToken);
    }

    public async Task DeleteDeviceAsync(Guid id, CancellationToken cancellationToken = default)
    {
        authorization.DemandAdmin();
        HsmDeviceProfile? existing = await deviceProfiles.GetAsync(id, cancellationToken);
        await deviceProfiles.DeleteAsync(id, cancellationToken);
        await auditLog.WriteAsync("Device", "Delete", existing?.Name ?? id.ToString(), "Success", "Device profile removed.", cancellationToken: cancellationToken);
    }

    public IReadOnlyList<AdminSessionSnapshot> GetSessions()
    {
        authorization.DemandViewer();
        return sessionRegistry.GetSnapshots();
    }

    public Task<IReadOnlyList<AdminAuditLogEntry>> GetAuditLogsAsync(int take = 200, CancellationToken cancellationToken = default)
    {
        authorization.DemandViewer();
        return auditLog.GetRecentAsync(take, cancellationToken);
    }

    public Task<AuditIntegrityStatus> GetAuditIntegrityAsync(CancellationToken cancellationToken = default)
    {
        authorization.DemandViewer();
        return auditLog.VerifyIntegrityAsync(cancellationToken);
    }

    public async Task<DashboardSummary> GetDashboardAsync(CancellationToken cancellationToken = default)
    {
        authorization.DemandViewer();
        IReadOnlyList<HsmDeviceProfile> devices = await deviceProfiles.GetAllAsync(cancellationToken);
        IReadOnlyList<AdminAuditLogEntry> logs = await auditLog.GetRecentAsync(25, cancellationToken);
        return new DashboardSummary(devices.Count, devices.Count(x => x.IsEnabled), sessionRegistry.GetSnapshots().Count, logs.Count);
    }

    public async Task<AdminConfigurationExportBundle> ExportConfigurationAsync(CancellationToken cancellationToken = default)
    {
        authorization.DemandAdmin();

        try
        {
            IReadOnlyList<HsmDeviceProfile> devices = await deviceProfiles.GetAllAsync(cancellationToken);
            AdminConfigurationExportBundle bundle = new()
            {
                Format = ConfigurationFormat,
                SchemaVersion = ConfigurationSchemaVersion,
                ProductName = "Pkcs11Wrapper Admin",
                ProductVersion = GetCurrentProductVersion(),
                ExportedUtc = DateTimeOffset.UtcNow,
                IncludedSections = [.. ConfigurationIncludedSections],
                ExcludedSections = [.. ConfigurationExcludedSections],
                DeviceProfiles = [.. devices]
            };

            await auditLog.WriteAsync(
                "Configuration",
                "Export",
                "DeviceProfiles",
                "Success",
                $"Exported {devices.Count} device profile(s). Excluded sections: {string.Join(", ", ConfigurationExcludedSections)}.",
                cancellationToken: cancellationToken);

            return bundle;
        }
        catch (Exception ex)
        {
            await auditLog.WriteAsync("Configuration", "Export", "DeviceProfiles", "Failure", ex.Message, cancellationToken: cancellationToken);
            throw;
        }
    }

    public async Task<AdminConfigurationImportResult> ImportConfigurationAsync(Stream stream, string? sourceName, AdminConfigurationImportMode mode, bool acknowledgeReplaceAll, CancellationToken cancellationToken = default)
    {
        authorization.DemandAdmin();
        ArgumentNullException.ThrowIfNull(stream);

        if (mode == AdminConfigurationImportMode.ReplaceAll && !acknowledgeReplaceAll)
        {
            throw new InvalidOperationException("Replace-all import requires explicit acknowledgement before existing configuration is overwritten.");
        }

        string importTarget = string.IsNullOrWhiteSpace(sourceName) ? "uploaded bundle" : sourceName;

        try
        {
            AdminConfigurationExportBundle? bundle = await JsonSerializer.DeserializeAsync(stream, AdminApplicationJsonContext.Default.AdminConfigurationExportBundle, cancellationToken);
            if (bundle is null)
            {
                throw new InvalidOperationException("Configuration file was empty or unreadable.");
            }

            ValidateConfigurationBundle(bundle);
            AdminConfigurationImportResult importResult = await deviceProfiles.ImportAsync(bundle.DeviceProfiles, mode, cancellationToken);

            List<string> warnings = [.. importResult.Warnings];
            string currentVersion = GetCurrentProductVersion();
            if (!string.IsNullOrWhiteSpace(bundle.ProductVersion) && !string.Equals(bundle.ProductVersion, currentVersion, StringComparison.OrdinalIgnoreCase))
            {
                warnings.Add($"Bundle was exported from admin version {bundle.ProductVersion}; current version is {currentVersion}.");
            }

            AdminConfigurationImportResult result = warnings.Count == importResult.Warnings.Count
                ? importResult
                : importResult with { Warnings = warnings };

            string warningSuffix = result.Warnings.Count == 0
                ? string.Empty
                : $" Warnings: {string.Join(" | ", result.Warnings)}";
            await auditLog.WriteAsync(
                "Configuration",
                "Import",
                importTarget,
                "Success",
                $"{result.Summary}{warningSuffix}",
                cancellationToken: cancellationToken);

            return result;
        }
        catch (Exception ex)
        {
            await auditLog.WriteAsync("Configuration", "Import", importTarget, "Failure", ex.Message, cancellationToken: cancellationToken);
            throw;
        }
    }

    public async Task<Pkcs11LabExecutionResult> ExecuteLabAsync(Pkcs11LabRequest request, CancellationToken cancellationToken = default)
    {
        authorization.DemandOperator();
        ArgumentNullException.ThrowIfNull(request);
        ValidateLabRequest(request);

        HsmDeviceProfile device = await RequireDeviceAsync(request.DeviceId, cancellationToken);
        string target = request.SlotId is nuint slotIdValue
            ? $"{device.Name}/slot-{slotIdValue}"
            : device.Name;
        Stopwatch stopwatch = Stopwatch.StartNew();

        try
        {
            using Pkcs11Module module = CreateInitializedModule(device);
            (string Summary, string OutputText, List<string> Notes) execution = request.Operation switch
            {
                Pkcs11LabOperation.ModuleInfo => ExecuteModuleInfoLab(module),
                Pkcs11LabOperation.InterfaceDiscovery => ExecuteInterfaceDiscoveryLab(module),
                Pkcs11LabOperation.SlotSnapshot => ExecuteSlotSnapshotLab(module),
                Pkcs11LabOperation.MechanismList => ExecuteMechanismListLab(module, request.SlotId!.Value),
                Pkcs11LabOperation.MechanismInfo => ExecuteMechanismInfoLab(module, request.SlotId!.Value, request.MechanismTypeText!),
                Pkcs11LabOperation.SessionInfo => ExecuteSessionInfoLab(module, request),
                Pkcs11LabOperation.GenerateRandom => ExecuteGenerateRandomLab(module, request),
                Pkcs11LabOperation.DigestText => ExecuteDigestTextLab(module, request),
                Pkcs11LabOperation.FindObjects => ExecuteFindObjectsLab(device.Id, module, request),
                _ => throw new ArgumentOutOfRangeException(nameof(request.Operation), request.Operation, "Unsupported PKCS#11 lab operation.")
            };

            stopwatch.Stop();
            await auditLog.WriteAsync("Lab", request.Operation.ToString(), target, "Success", execution.Summary, cancellationToken: cancellationToken);
            return new(request.Operation.ToString(), true, execution.Summary, execution.OutputText, execution.Notes, stopwatch.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            string summary = $"{request.Operation} failed: {ex.Message}";
            string output = $"{ex.GetType().Name}: {ex.Message}";
            await auditLog.WriteAsync("Lab", request.Operation.ToString(), target, "Failure", ex.Message, cancellationToken: cancellationToken);
            return new(request.Operation.ToString(), false, summary, output, [], stopwatch.ElapsedMilliseconds);
        }
    }

    public async Task<HsmConnectionTestResult> TestConnectionAsync(Guid deviceId, CancellationToken cancellationToken = default)
    {
        authorization.DemandOperator();
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
        authorization.DemandViewer();
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
        authorization.DemandViewer();
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
        authorization.DemandViewer();
        HsmDeviceProfile device = await RequireDeviceAsync(deviceId, cancellationToken);
        using Pkcs11Module module = CreateInitializedModule(device);
        using Pkcs11Session session = module.OpenSession(new Pkcs11SlotId(slotIdValue));
        string pinNote = LoginIfProvided(session, userPin);

        HsmObjectDetail detail = ReadObjectDetail(deviceId, slotIdValue, session, new Pkcs11ObjectHandle(handleValue));
        await auditLog.WriteAsync("Key", "Detail", $"{device.Name}/slot-{slotIdValue}/handle-{handleValue}", "Success", $"Loaded object detail via {pinNote}.", cancellationToken: cancellationToken);
        return detail;
    }

    public async Task<KeyManagementSlotCapabilities> GetKeyManagementCapabilitiesAsync(Guid deviceId, nuint slotIdValue, CancellationToken cancellationToken = default)
    {
        authorization.DemandViewer();
        HsmDeviceProfile device = await RequireDeviceAsync(deviceId, cancellationToken);
        using Pkcs11Module module = CreateInitializedModule(device);

        bool tokenPresent = module.TryGetTokenInfo(new Pkcs11SlotId(slotIdValue), out _);
        List<string> warnings = [];
        if (!tokenPresent)
        {
            warnings.Add("No token is present in the selected slot, so key-management operations are unavailable.");
        }

        List<SlotMechanismSupport> mechanisms = [];
        HashSet<nuint> available = [];

        try
        {
            int mechanismCount = module.GetMechanismCount(new Pkcs11SlotId(slotIdValue));
            if (mechanismCount > 0)
            {
                Pkcs11MechanismType[] buffer = new Pkcs11MechanismType[mechanismCount];
                if (module.TryGetMechanisms(new Pkcs11SlotId(slotIdValue), buffer, out int written))
                {
                    for (int i = 0; i < written; i++)
                    {
                        available.Add(buffer[i].Value);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            warnings.Add($"Could not read mechanism list for the slot: {ex.Message}");
        }

        foreach ((Pkcs11MechanismType type, string name) in KeyMechanisms)
        {
            bool present = available.Contains(type.Value);
            Pkcs11MechanismFlags flags = 0;
            if (present)
            {
                try
                {
                    flags = module.GetMechanismInfo(new Pkcs11SlotId(slotIdValue), type).Flags;
                }
                catch (Exception ex)
                {
                    warnings.Add($"Could not read {name} info: {ex.Message}");
                }
            }

            mechanisms.Add(new SlotMechanismSupport(
                name,
                $"0x{type.Value:x}",
                present,
                present && flags.HasFlag(Pkcs11MechanismFlags.Generate),
                present && flags.HasFlag(Pkcs11MechanismFlags.GenerateKeyPair),
                present && flags.HasFlag(Pkcs11MechanismFlags.Encrypt),
                present && flags.HasFlag(Pkcs11MechanismFlags.Decrypt),
                present && flags.HasFlag(Pkcs11MechanismFlags.Sign),
                present && flags.HasFlag(Pkcs11MechanismFlags.Verify),
                present && flags.HasFlag(Pkcs11MechanismFlags.Wrap),
                present && flags.HasFlag(Pkcs11MechanismFlags.Unwrap),
                present ? flags.ToString() : "Not exposed by slot"));
        }

        bool supportsAesGen = mechanisms.Any(x => x.Name == "CKM_AES_KEY_GEN" && x.SupportsGenerate);
        bool supportsRsaGen = mechanisms.Any(x => x.Name == "CKM_RSA_PKCS_KEY_PAIR_GEN" && x.SupportsGenerateKeyPair);
        bool supportsCreateObject = tokenPresent;

        if (!supportsAesGen)
        {
            warnings.Add("AES generate is gated because CKM_AES_KEY_GEN with generate support is not exposed by the selected slot.");
        }

        if (!supportsRsaGen)
        {
            warnings.Add("RSA key-pair generate is gated because CKM_RSA_PKCS_KEY_PAIR_GEN with generate-key-pair support is not exposed by the selected slot.");
        }

        return new KeyManagementSlotCapabilities(deviceId, slotIdValue, tokenPresent, supportsAesGen, supportsRsaGen, supportsCreateObject, warnings, mechanisms);
    }

    public async Task<KeyManagementResult> GenerateAesKeyAsync(Guid deviceId, nuint slotIdValue, GenerateAesKeyRequest request, string userPin, CancellationToken cancellationToken = default)
    {
        authorization.DemandOperator();
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

    public async Task<KeyManagementResult> ImportAesKeyAsync(Guid deviceId, nuint slotIdValue, ImportAesKeyRequest request, string userPin, CancellationToken cancellationToken = default)
    {
        authorization.DemandOperator();
        ValidateImportAesKeyRequest(request);
        byte[] id = ParseOptionalHex(request.IdHex, nameof(request.IdHex));
        byte[] label = Encoding.UTF8.GetBytes(request.Label.Trim());
        byte[] value = ParseRequiredHex(request.ValueHex, nameof(request.ValueHex));

        HsmDeviceProfile device = await RequireDeviceAsync(deviceId, cancellationToken);
        using Pkcs11Module module = CreateInitializedModule(device);
        using Pkcs11Session session = module.OpenSession(new Pkcs11SlotId(slotIdValue), readWrite: true);
        RequireUserPin(userPin, "import AES keys");
        session.Login(Pkcs11UserType.User, Encoding.UTF8.GetBytes(userPin));

        Pkcs11ObjectHandle handle = session.CreateObject(CreateImportedAesTemplate(request, label, id, value));
        string idHex = id.Length == 0 ? "(empty)" : Convert.ToHexString(id);
        KeyManagementResult result = new("ImportAesKey", $"Imported AES-{value.Length * 8} key '{request.Label.Trim()}' (handle {handle.Value}).", [handle.Value], request.Label.Trim(), id.Length == 0 ? null : idHex);
        await auditLog.WriteAsync("Key", "ImportAes", $"{device.Name}/slot-{slotIdValue}/handle-{handle.Value}", "Success", result.Summary, cancellationToken: cancellationToken);
        return result;
    }

    public async Task<KeyManagementResult> GenerateRsaKeyPairAsync(Guid deviceId, nuint slotIdValue, GenerateRsaKeyPairRequest request, string userPin, CancellationToken cancellationToken = default)
    {
        authorization.DemandOperator();
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
        authorization.DemandOperator();
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
        authorization.DemandOperator();
        bool closed = await sessionRegistry.CloseAsync(sessionId);
        await auditLog.WriteAsync("Session", "Close", sessionId.ToString(), closed ? "Success" : "NotFound", closed ? "Session closed." : "Session was not found.", cancellationToken: cancellationToken);
        return closed;
    }

    public Task<AdminSessionSnapshot?> GetSessionAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        authorization.DemandViewer();
        return Task.FromResult(sessionRegistry.GetSnapshots().FirstOrDefault(x => x.SessionId == sessionId));
    }

    public async Task<AdminSessionSnapshot> LoginTrackedSessionAsync(Guid sessionId, string userPin, CancellationToken cancellationToken = default)
    {
        authorization.DemandOperator();
        RequireUserPin(userPin, "log in to a tracked session");
        AdminSessionRegistry.AdminTrackedSession tracked = GetTrackedSession(sessionId);
        tracked.Session.Login(Pkcs11UserType.User, Encoding.UTF8.GetBytes(userPin));
        sessionRegistry.TryTouch(sessionId, "Login(User)");
        await auditLog.WriteAsync("Session", "Login", sessionId.ToString(), "Success", "Logged in tracked session as CKU_USER.", cancellationToken: cancellationToken);
        return GetRequiredSessionSnapshot(sessionId);
    }

    public async Task<AdminSessionSnapshot> LogoutTrackedSessionAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        authorization.DemandOperator();
        AdminSessionRegistry.AdminTrackedSession tracked = GetTrackedSession(sessionId);
        tracked.Session.Logout();
        sessionRegistry.TryTouch(sessionId, "Logout");
        await auditLog.WriteAsync("Session", "Logout", sessionId.ToString(), "Success", "Logged out tracked session.", cancellationToken: cancellationToken);
        return GetRequiredSessionSnapshot(sessionId);
    }

    public async Task<AdminSessionSnapshot> CancelTrackedSessionOperationsAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        authorization.DemandOperator();
        AdminSessionRegistry.AdminTrackedSession tracked = GetTrackedSession(sessionId);
        tracked.Session.SessionCancel();
        sessionRegistry.TryTouch(sessionId, "SessionCancel");
        await auditLog.WriteAsync("Session", "Cancel", sessionId.ToString(), "Success", "Issued C_SessionCancel on tracked session.", cancellationToken: cancellationToken);
        return GetRequiredSessionSnapshot(sessionId);
    }

    public async Task CloseAllSessionsAsync(Guid deviceId, nuint slotIdValue, CancellationToken cancellationToken = default)
    {
        authorization.DemandOperator();
        HsmDeviceProfile device = await RequireDeviceAsync(deviceId, cancellationToken);
        using Pkcs11Module module = CreateInitializedModule(device);
        module.CloseAllSessions(new Pkcs11SlotId(slotIdValue));
        sessionRegistry.MarkInvalidatedForSlot(deviceId, slotIdValue, "Invalidated by CloseAllSessions on the same slot.", "CloseAllSessions");
        await auditLog.WriteAsync("Session", "CloseAll", $"{device.Name}/slot-{slotIdValue}", "Success", "Invoked CloseAllSessions on slot.", cancellationToken: cancellationToken);
    }

    public async Task DestroyObjectAsync(Guid deviceId, nuint slotIdValue, DestroyObjectRequest request, CancellationToken cancellationToken = default)
    {
        authorization.DemandOperator();
        ValidateDestroyRequest(request);

        HsmDeviceProfile device = await RequireDeviceAsync(deviceId, cancellationToken);
        using Pkcs11Module module = CreateInitializedModule(device);
        using Pkcs11Session session = module.OpenSession(new Pkcs11SlotId(slotIdValue), readWrite: true);
        session.Login(Pkcs11UserType.User, Encoding.UTF8.GetBytes(request.UserPin));
        session.DestroyObject(new Pkcs11ObjectHandle(request.Handle));
        await auditLog.WriteAsync("Key", "Destroy", $"{device.Name}/slot-{slotIdValue}/handle-{request.Handle}", "Success", "Object destroyed through admin panel after typed confirmation.", cancellationToken: cancellationToken);
    }

    public async Task<KeyManagementResult> UpdateObjectAttributesAsync(Guid deviceId, nuint slotIdValue, UpdateObjectAttributesRequest request, string userPin, CancellationToken cancellationToken = default)
    {
        authorization.DemandOperator();
        ValidateUpdateObjectAttributesRequest(request);

        HsmDeviceProfile device = await RequireDeviceAsync(deviceId, cancellationToken);
        using Pkcs11Module module = CreateInitializedModule(device);
        using Pkcs11Session session = module.OpenSession(new Pkcs11SlotId(slotIdValue), readWrite: true);
        RequireUserPin(userPin, "update object attributes");
        session.Login(Pkcs11UserType.User, Encoding.UTF8.GetBytes(userPin));

        byte[] id = ParseOptionalHex(request.IdHex, nameof(request.IdHex));
        session.SetAttributeValue(new Pkcs11ObjectHandle(request.Handle), CreateEditableAttributeTemplate(request, id));

        string summary = $"Updated editable attributes for handle {request.Handle} ({request.Label.Trim()}).";
        await auditLog.WriteAsync("Key", "UpdateAttributes", $"{device.Name}/slot-{slotIdValue}/handle-{request.Handle}", "Success", summary, cancellationToken: cancellationToken);
        return new KeyManagementResult("UpdateObjectAttributes", summary, [request.Handle], request.Label.Trim(), id.Length == 0 ? null : Convert.ToHexString(id));
    }

    public async Task<KeyManagementResult> CopyObjectAsync(Guid deviceId, nuint slotIdValue, CopyObjectRequest request, string userPin, CancellationToken cancellationToken = default)
    {
        authorization.DemandOperator();
        ValidateCopyObjectRequest(request);

        HsmDeviceProfile device = await RequireDeviceAsync(deviceId, cancellationToken);
        using Pkcs11Module module = CreateInitializedModule(device);
        using Pkcs11Session session = module.OpenSession(new Pkcs11SlotId(slotIdValue), readWrite: true);
        RequireUserPin(userPin, "copy objects");
        session.Login(Pkcs11UserType.User, Encoding.UTF8.GetBytes(userPin));

        byte[] id = ParseOptionalHex(request.IdHex, nameof(request.IdHex));
        Pkcs11ObjectHandle copied = session.CopyObject(new Pkcs11ObjectHandle(request.SourceHandle), CreateCopyTemplate(request, id));
        string summary = $"Copied handle {request.SourceHandle} to new handle {copied.Value} with label '{request.Label.Trim()}'.";
        await auditLog.WriteAsync("Key", "CopyObject", $"{device.Name}/slot-{slotIdValue}/handle-{copied.Value}", "Success", summary, cancellationToken: cancellationToken);
        return new KeyManagementResult("CopyObject", summary, [copied.Value], request.Label.Trim(), id.Length == 0 ? null : Convert.ToHexString(id));
    }

    public static void ValidateLabRequest(Pkcs11LabRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (request.DeviceId == Guid.Empty)
        {
            throw new ArgumentException("Device selection is required.", nameof(request));
        }

        if (OperationRequiresSlot(request.Operation) && request.SlotId is null)
        {
            throw new InvalidOperationException($"Operation '{request.Operation}' requires a slot selection.");
        }

        if (request.Operation == Pkcs11LabOperation.MechanismInfo && string.IsNullOrWhiteSpace(request.MechanismTypeText))
        {
            throw new ArgumentException("Mechanism type is required for mechanism-info queries.", nameof(request));
        }

        if (request.Operation == Pkcs11LabOperation.GenerateRandom && (request.RandomLength < 1 || request.RandomLength > 4096))
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Random length must be between 1 and 4096 bytes.");
        }

        if (request.Operation == Pkcs11LabOperation.DigestText && string.IsNullOrWhiteSpace(request.TextInput))
        {
            throw new ArgumentException("Digest input text is required.", nameof(request));
        }

        if (request.Operation == Pkcs11LabOperation.FindObjects && (request.MaxObjects < 1 || request.MaxObjects > 256))
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Maximum object count must be between 1 and 256.");
        }

        if (!string.IsNullOrWhiteSpace(request.IdHex))
        {
            _ = ParseOptionalHex(request.IdHex, nameof(request.IdHex));
        }
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

    public static void ValidateImportAesKeyRequest(ImportAesKeyRequest request)
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

        byte[] value = ParseRequiredHex(request.ValueHex, nameof(request.ValueHex));
        if (value.Length is not (16 or 24 or 32 or 48 or 64))
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Imported AES key value must be 16, 24, 32, 48, or 64 bytes.");
        }

        _ = ParseOptionalHex(request.IdHex, nameof(request.IdHex));
    }

    public static void ValidateUpdateObjectAttributesRequest(UpdateObjectAttributesRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Handle == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Handle is required.");
        }

        if (string.IsNullOrWhiteSpace(request.Label))
        {
            throw new ArgumentException("Label is required.", nameof(request));
        }

        _ = ParseOptionalHex(request.IdHex, nameof(request.IdHex));
    }

    public static void ValidateCopyObjectRequest(CopyObjectRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.SourceHandle == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request), "Source handle is required.");
        }

        if (string.IsNullOrWhiteSpace(request.Label))
        {
            throw new ArgumentException("Label is required.", nameof(request));
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

    private static bool OperationRequiresSlot(Pkcs11LabOperation operation)
        => operation is Pkcs11LabOperation.MechanismList
            or Pkcs11LabOperation.MechanismInfo
            or Pkcs11LabOperation.SessionInfo
            or Pkcs11LabOperation.GenerateRandom
            or Pkcs11LabOperation.DigestText
            or Pkcs11LabOperation.FindObjects;

    private static (string Summary, string OutputText, List<string> Notes) ExecuteModuleInfoLab(Pkcs11Module module)
    {
        Pkcs11ModuleInfo info = module.GetInfo();
        StringBuilder output = new();
        output.AppendLine($"Cryptoki version: {info.CryptokiVersion}");
        output.AppendLine($"Function list version: {module.FunctionListVersion}");
        output.AppendLine($"Manufacturer: {info.ManufacturerId}");
        output.AppendLine($"Library description: {info.LibraryDescription}");
        output.AppendLine($"Library version: {info.LibraryVersion}");
        output.AppendLine($"Flags: 0x{info.Flags:x}");
        output.AppendLine($"Interface discovery exported: {module.SupportsInterfaceDiscovery}");

        List<string> notes = [];
        if (!module.SupportsInterfaceDiscovery)
        {
            notes.Add("Many PKCS#11 modules still expose only the classic function list; this is normal when interface discovery is false.");
        }

        return ("Read module-level PKCS#11 metadata.", output.ToString(), notes);
    }

    private static (string Summary, string OutputText, List<string> Notes) ExecuteInterfaceDiscoveryLab(Pkcs11Module module)
    {
        StringBuilder output = new();
        List<string> notes = [];

        if (!module.SupportsInterfaceDiscovery)
        {
            output.AppendLine("Interface discovery is not exported by this module.");
            notes.Add("`C_GetInterface*` support is optional and many deployed modules still omit it.");
            return ("Module does not expose PKCS#11 interface discovery.", output.ToString(), notes);
        }

        int interfaceCount = module.GetInterfaceCount();
        output.AppendLine($"Interface count: {interfaceCount}");
        if (interfaceCount == 0)
        {
            return ("Module exported interface discovery but returned no interfaces.", output.ToString(), notes);
        }

        Pkcs11Interface[] interfaces = new Pkcs11Interface[interfaceCount];
        if (!module.TryGetInterfaces(interfaces, out int written))
        {
            throw new InvalidOperationException("Failed to read PKCS#11 interface list.");
        }

        for (int i = 0; i < written; i++)
        {
            Pkcs11Interface current = interfaces[i];
            output.AppendLine($"- {current.Name} | Version={current.Version} | Flags={current.Flags}");
        }

        return ($"Read {written} PKCS#11 interface declaration(s).", output.ToString(), notes);
    }

    private static (string Summary, string OutputText, List<string> Notes) ExecuteSlotSnapshotLab(Pkcs11Module module)
    {
        int slotCount = module.GetSlotCount();
        StringBuilder output = new();
        output.AppendLine($"Slot count: {slotCount}");

        if (slotCount == 0)
        {
            return ("Module reported zero slots.", output.ToString(), []);
        }

        Pkcs11SlotId[] slots = new Pkcs11SlotId[slotCount];
        if (!module.TryGetSlots(slots, out int written))
        {
            throw new InvalidOperationException("Failed to enumerate slot identifiers.");
        }

        for (int i = 0; i < written; i++)
        {
            Pkcs11SlotId slotId = slots[i];
            Pkcs11SlotInfo slotInfo = module.GetSlotInfo(slotId);
            output.AppendLine($"[{slotId.Value}] {slotInfo.SlotDescription}");
            output.AppendLine($"  Manufacturer: {slotInfo.ManufacturerId}");
            output.AppendLine($"  Flags: {slotInfo.Flags}");
            output.AppendLine($"  HW/FW: {slotInfo.HardwareVersion} / {slotInfo.FirmwareVersion}");
            if (module.TryGetTokenInfo(slotId, out Pkcs11TokenInfo tokenInfo))
            {
                output.AppendLine($"  Token: {tokenInfo.Label} | {tokenInfo.Model} | Serial={tokenInfo.SerialNumber}");
                output.AppendLine($"  TokenFlags: {tokenInfo.Flags}");
                output.AppendLine($"  Sessions: {tokenInfo.SessionCount}/{tokenInfo.MaxSessionCount} | RW={tokenInfo.RwSessionCount}/{tokenInfo.MaxRwSessionCount}");
                output.AppendLine($"  Memory public/private free: {tokenInfo.FreePublicMemory}/{tokenInfo.FreePrivateMemory}");
            }
            else
            {
                output.AppendLine("  Token: not present");
            }
        }

        return ($"Read snapshot information for {written} slot(s).", output.ToString(), []);
    }

    private static (string Summary, string OutputText, List<string> Notes) ExecuteMechanismListLab(Pkcs11Module module, nuint slotIdValue)
    {
        Pkcs11SlotId slotId = new(slotIdValue);
        int mechanismCount = module.GetMechanismCount(slotId);
        StringBuilder output = new();
        output.AppendLine($"Slot: {slotIdValue}");
        output.AppendLine($"Mechanism count: {mechanismCount}");

        if (mechanismCount == 0)
        {
            return ($"Slot {slotIdValue} reported zero mechanisms.", output.ToString(), []);
        }

        Pkcs11MechanismType[] mechanisms = new Pkcs11MechanismType[mechanismCount];
        if (!module.TryGetMechanisms(slotId, mechanisms, out int written))
        {
            throw new InvalidOperationException($"Failed to enumerate mechanisms for slot {slotIdValue}.");
        }

        for (int i = 0; i < written; i++)
        {
            Pkcs11MechanismType mechanism = mechanisms[i];
            Pkcs11MechanismInfo info = module.GetMechanismInfo(slotId, mechanism);
            output.AppendLine($"- {DescribeMechanismType(mechanism)} | MinKey={info.MinKeySize} | MaxKey={info.MaxKeySize} | Flags={info.Flags}");
        }

        return ($"Enumerated {written} mechanism(s) for slot {slotIdValue}.", output.ToString(), []);
    }

    private static (string Summary, string OutputText, List<string> Notes) ExecuteMechanismInfoLab(Pkcs11Module module, nuint slotIdValue, string mechanismTypeText)
    {
        Pkcs11MechanismType mechanismType = ParseMechanismTypeText(mechanismTypeText);
        Pkcs11MechanismInfo info = module.GetMechanismInfo(new Pkcs11SlotId(slotIdValue), mechanismType);
        StringBuilder output = new();
        output.AppendLine($"Slot: {slotIdValue}");
        output.AppendLine($"Mechanism: {DescribeMechanismType(mechanismType)}");
        output.AppendLine($"Minimum key size: {info.MinKeySize}");
        output.AppendLine($"Maximum key size: {info.MaxKeySize}");
        output.AppendLine($"Flags: {info.Flags}");
        return ($"Read mechanism details for {DescribeMechanismType(mechanismType)}.", output.ToString(), []);
    }

    private static (string Summary, string OutputText, List<string> Notes) ExecuteSessionInfoLab(Pkcs11Module module, Pkcs11LabRequest request)
    {
        List<string> notes = [];
        using Pkcs11Session session = module.OpenSession(new Pkcs11SlotId(request.SlotId!.Value), request.OpenReadWriteSession);
        string authMode = LoginLabSessionIfRequested(session, request, notes);
        Pkcs11SessionInfo info = session.GetInfo();

        StringBuilder output = new();
        output.AppendLine($"Slot: {info.SlotId.Value}");
        output.AppendLine($"Mode: {(request.OpenReadWriteSession ? "Read-write" : "Read-only")}");
        output.AppendLine($"Auth mode: {authMode}");
        output.AppendLine($"State: {info.State}");
        output.AppendLine($"Flags: {info.Flags}");
        output.AppendLine($"Device error: {info.DeviceError}");
        return ($"Opened a transient {(request.OpenReadWriteSession ? "RW" : "RO")} session and read `C_GetSessionInfo`.", output.ToString(), notes);
    }

    private static (string Summary, string OutputText, List<string> Notes) ExecuteGenerateRandomLab(Pkcs11Module module, Pkcs11LabRequest request)
    {
        List<string> notes = [];
        using Pkcs11Session session = module.OpenSession(new Pkcs11SlotId(request.SlotId!.Value), readWrite: false);
        string authMode = LoginLabSessionIfRequested(session, request, notes);
        byte[] random = new byte[request.RandomLength];
        session.GenerateRandom(random);

        StringBuilder output = new();
        output.AppendLine($"Slot: {request.SlotId.Value}");
        output.AppendLine($"Auth mode: {authMode}");
        output.AppendLine($"Random length: {request.RandomLength}");
        output.AppendLine($"Random hex: {Convert.ToHexString(random)}");
        return ($"Generated {request.RandomLength} random byte(s) from the token RNG.", output.ToString(), notes);
    }

    private static (string Summary, string OutputText, List<string> Notes) ExecuteDigestTextLab(Pkcs11Module module, Pkcs11LabRequest request)
    {
        List<string> notes = [];
        using Pkcs11Session session = module.OpenSession(new Pkcs11SlotId(request.SlotId!.Value), readWrite: false);
        string authMode = LoginLabSessionIfRequested(session, request, notes);
        Pkcs11MechanismType mechanismType = ResolveDigestMechanism(request.DigestAlgorithm);
        byte[] data = Encoding.UTF8.GetBytes(request.TextInput ?? string.Empty);
        int digestLength = session.GetDigestOutputLength(new Pkcs11Mechanism(mechanismType), data);
        byte[] digest = new byte[Math.Max(digestLength, 64)];
        if (!session.TryDigest(new Pkcs11Mechanism(mechanismType), data, digest, out int written))
        {
            throw new InvalidOperationException("The module did not produce a digest output buffer.");
        }

        StringBuilder output = new();
        output.AppendLine($"Slot: {request.SlotId.Value}");
        output.AppendLine($"Auth mode: {authMode}");
        output.AppendLine($"Mechanism: {DescribeMechanismType(mechanismType)}");
        output.AppendLine($"Input bytes: {data.Length}");
        output.AppendLine($"Input text: {request.TextInput}");
        output.AppendLine($"Digest hex: {Convert.ToHexString(digest, 0, written)}");
        return ($"Computed {DescribeMechanismType(mechanismType)} digest for {data.Length} byte(s) of UTF-8 input.", output.ToString(), notes);
    }

    private static (string Summary, string OutputText, List<string> Notes) ExecuteFindObjectsLab(Guid deviceId, Pkcs11Module module, Pkcs11LabRequest request)
    {
        List<string> notes = [];
        using Pkcs11Session session = module.OpenSession(new Pkcs11SlotId(request.SlotId!.Value), readWrite: false);
        string authMode = LoginLabSessionIfRequested(session, request, notes);
        byte[] label = string.IsNullOrWhiteSpace(request.LabelFilter) ? [] : Encoding.UTF8.GetBytes(request.LabelFilter.Trim());
        byte[] id = ParseOptionalHex(request.IdHex, nameof(request.IdHex));
        Pkcs11ObjectClass? objectClass = ResolveLabObjectClass(request.ObjectClassFilter);
        Pkcs11ObjectSearchParameters search = new(label, id, objectClass);
        List<Pkcs11ObjectHandle> handles = EnumerateObjectHandles(session, search, request.MaxObjects, out bool truncated);

        if (label.Length == 0 && id.Length == 0 && objectClass is null)
        {
            notes.Add("No search filters were supplied; the lab is showing the first matching objects up to the max-object limit.");
        }

        if (string.IsNullOrWhiteSpace(request.UserPin))
        {
            notes.Add("Without CKU_USER login, private objects may be omitted by token policy.");
        }

        StringBuilder output = new();
        output.AppendLine($"Slot: {request.SlotId.Value}");
        output.AppendLine($"Auth mode: {authMode}");
        output.AppendLine($"Max objects: {request.MaxObjects}");
        output.AppendLine($"Label filter: {(string.IsNullOrWhiteSpace(request.LabelFilter) ? "<none>" : request.LabelFilter.Trim())}");
        output.AppendLine($"ID filter: {(string.IsNullOrWhiteSpace(request.IdHex) ? "<none>" : request.IdHex.Trim())}");
        output.AppendLine($"Object class filter: {request.ObjectClassFilter}");
        output.AppendLine($"Returned objects: {handles.Count}{(truncated ? "+" : string.Empty)}");

        foreach (Pkcs11ObjectHandle handle in handles)
        {
            HsmKeyObjectSummary summary = ReadObjectSummary(deviceId, request.SlotId.Value, session, handle);
            output.AppendLine($"- Handle={summary.Handle} | Label={summary.Label ?? "<null>"} | Id={summary.IdHex ?? "<null>"} | Class={summary.ObjectClass} | KeyType={summary.KeyType} | Caps={DescribeCapabilities(summary)}");
        }

        string summaryText = truncated
            ? $"Found at least {handles.Count} object(s); output truncated at the configured limit."
            : $"Found {handles.Count} object(s) matching the current search filters.";
        return (summaryText, output.ToString(), notes);
    }

    private static string LoginLabSessionIfRequested(Pkcs11Session session, Pkcs11LabRequest request, List<string> notes)
    {
        if (string.IsNullOrWhiteSpace(request.UserPin))
        {
            return "public";
        }

        if (!request.LoginUserIfPinProvided)
        {
            notes.Add("A PIN was supplied but login was disabled for this run, so the operation stayed in public session state.");
            return "public";
        }

        session.Login(Pkcs11UserType.User, Encoding.UTF8.GetBytes(request.UserPin));
        notes.Add("Authenticated the transient lab session as CKU_USER using the supplied PIN.");
        return "user";
    }

    private static Pkcs11MechanismType ResolveDigestMechanism(Pkcs11LabDigestAlgorithm algorithm)
        => algorithm switch
        {
            Pkcs11LabDigestAlgorithm.Sha1 => Pkcs11MechanismTypes.Sha1,
            Pkcs11LabDigestAlgorithm.Sha256 => Pkcs11MechanismTypes.Sha256,
            Pkcs11LabDigestAlgorithm.Sha384 => Pkcs11MechanismTypes.Sha384,
            Pkcs11LabDigestAlgorithm.Sha512 => Pkcs11MechanismTypes.Sha512,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported digest algorithm.")
        };

    private static Pkcs11ObjectClass? ResolveLabObjectClass(Pkcs11LabObjectClassFilter filter)
        => filter switch
        {
            Pkcs11LabObjectClassFilter.Any => null,
            Pkcs11LabObjectClassFilter.Data => Pkcs11ObjectClasses.Data,
            Pkcs11LabObjectClassFilter.Certificate => Pkcs11ObjectClasses.Certificate,
            Pkcs11LabObjectClassFilter.PublicKey => Pkcs11ObjectClasses.PublicKey,
            Pkcs11LabObjectClassFilter.PrivateKey => Pkcs11ObjectClasses.PrivateKey,
            Pkcs11LabObjectClassFilter.SecretKey => Pkcs11ObjectClasses.SecretKey,
            _ => throw new ArgumentOutOfRangeException(nameof(filter), filter, "Unsupported object-class filter.")
        };

    private static Pkcs11MechanismType ParseMechanismTypeText(string value)
    {
        string trimmed = value.Trim();
        NumberStyles styles = NumberStyles.Integer;
        if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed[2..];
            styles = NumberStyles.AllowHexSpecifier;
        }

        if (!nuint.TryParse(trimmed, styles, CultureInfo.InvariantCulture, out nuint parsed))
        {
            throw new ArgumentException($"Mechanism type '{value}' is not a valid hex/decimal number.", nameof(value));
        }

        return new Pkcs11MechanismType(parsed);
    }

    private static string DescribeMechanismType(Pkcs11MechanismType type)
        => type.Value switch
        {
            0x00000000u => "CKM_RSA_PKCS_KEY_PAIR_GEN (0x0)",
            0x00000001u => "CKM_RSA_PKCS (0x1)",
            0x00000009u => "CKM_RSA_PKCS_OAEP (0x9)",
            0x00000220u => "CKM_SHA_1 (0x220)",
            0x00000250u => "CKM_SHA256 (0x250)",
            0x00000260u => "CKM_SHA384 (0x260)",
            0x00000270u => "CKM_SHA512 (0x270)",
            0x00001080u => "CKM_AES_KEY_GEN (0x1080)",
            0x00001082u => "CKM_AES_ECB (0x1082)",
            0x00001085u => "CKM_AES_CBC (0x1085)",
            0x00001086u => "CKM_AES_MAC (0x1086)",
            0x0000108au => "CKM_AES_CTR (0x108a)",
            0x0000108du => "CKM_AES_GCM (0x108d)",
            0x00002109u => "CKM_AES_KEY_WRAP_PAD (0x2109)",
            _ => $"0x{type.Value:x}"
        };

    private static string DescribeCapabilities(HsmKeyObjectSummary summary)
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

    private static void ValidateConfigurationBundle(AdminConfigurationExportBundle bundle)
    {
        if (!string.Equals(bundle.Format, ConfigurationFormat, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"Unsupported configuration format '{bundle.Format}'.");
        }

        if (bundle.SchemaVersion != ConfigurationSchemaVersion)
        {
            throw new InvalidOperationException($"Unsupported configuration schema version '{bundle.SchemaVersion}'.");
        }

        if (bundle.DeviceProfiles is null)
        {
            throw new InvalidOperationException("Configuration bundle does not contain a device profile section.");
        }
    }

    private static string GetCurrentProductVersion()
        => typeof(HsmAdminService).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
           ?? typeof(HsmAdminService).Assembly.GetName().Version?.ToString()
           ?? "unknown";

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

    private static List<Pkcs11ObjectHandle> EnumerateObjectHandles(Pkcs11Session session, Pkcs11ObjectSearchParameters search, int maxCount, out bool truncated)
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

    private static Pkcs11ObjectAttribute[] CreateImportedAesTemplate(ImportAesKeyRequest request, byte[] label, byte[] id, byte[] value)
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
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Value, value),
            Pkcs11ObjectAttribute.Nuint(Pkcs11AttributeTypes.ValueLen, (nuint)value.Length)
        ];

    private static Pkcs11ObjectAttribute[] CreateEditableAttributeTemplate(UpdateObjectAttributesRequest request, byte[] id)
    {
        List<Pkcs11ObjectAttribute> attributes =
        [
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, Encoding.UTF8.GetBytes(request.Label.Trim())),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Id, id)
        ];

        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Private, request.Private);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Token, request.Token);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Extractable, request.Extractable);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Encrypt, request.AllowEncrypt);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Decrypt, request.AllowDecrypt);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Sign, request.AllowSign);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Verify, request.AllowVerify);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Wrap, request.AllowWrap);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Unwrap, request.AllowUnwrap);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Derive, request.AllowDerive);
        return [.. attributes];
    }

    private static void AddOptionalBooleanAttribute(List<Pkcs11ObjectAttribute> attributes, Pkcs11AttributeType type, bool? value)
    {
        if (value.HasValue)
        {
            attributes.Add(Pkcs11ObjectAttribute.Boolean(type, value.Value));
        }
    }

    private static Pkcs11ObjectAttribute[] CreateCopyTemplate(CopyObjectRequest request, byte[] id)
    {
        List<Pkcs11ObjectAttribute> attributes =
        [
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, Encoding.UTF8.GetBytes(request.Label.Trim())),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Id, id)
        ];

        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Token, request.Token);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Private, request.Private);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Extractable, request.Extractable);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Encrypt, request.AllowEncrypt);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Decrypt, request.AllowDecrypt);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Sign, request.AllowSign);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Verify, request.AllowVerify);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Wrap, request.AllowWrap);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Unwrap, request.AllowUnwrap);
        AddOptionalBooleanAttribute(attributes, Pkcs11AttributeTypes.Derive, request.AllowDerive);
        return [.. attributes];
    }

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

    private AdminSessionRegistry.AdminTrackedSession GetTrackedSession(Guid sessionId)
        => sessionRegistry.TryGet(sessionId, out AdminSessionRegistry.AdminTrackedSession? tracked)
            ? tracked!
            : throw new InvalidOperationException($"Tracked session '{sessionId}' was not found.");

    private AdminSessionSnapshot GetRequiredSessionSnapshot(Guid sessionId)
        => sessionRegistry.GetSnapshots().FirstOrDefault(x => x.SessionId == sessionId)
            ?? throw new InvalidOperationException($"Tracked session '{sessionId}' was not found after the operation.");

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
