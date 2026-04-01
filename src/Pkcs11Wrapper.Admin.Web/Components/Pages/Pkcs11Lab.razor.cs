using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Rendering;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;
using Pkcs11Wrapper.Admin.Infrastructure;
using Pkcs11Wrapper.Admin.Web.Lab;

namespace Pkcs11Wrapper.Admin.Web.Components.Pages;

public partial class Pkcs11Lab
{
    [SupplyParameterFromQuery(Name = "device")]
    public Guid? QueryDevice { get; set; }

    [SupplyParameterFromQuery(Name = "slot")]
    public string? QuerySlot { get; set; }

    [SupplyParameterFromQuery(Name = "op")]
    public string? QueryOperation { get; set; }

    [SupplyParameterFromQuery(Name = "handle")]
    public string? QueryHandle { get; set; }

    [SupplyParameterFromQuery(Name = "label")]
    public string? QueryLabel { get; set; }

    [SupplyParameterFromQuery(Name = "id")]
    public string? QueryIdHex { get; set; }

    [SupplyParameterFromQuery(Name = "class")]
    public string? QueryObjectClass { get; set; }

    [SupplyParameterFromQuery(Name = "keyType")]
    public string? QueryKeyType { get; set; }

    [SupplyParameterFromQuery(Name = "wrapHandle")]
    public string? QuerySecondaryHandle { get; set; }

    [SupplyParameterFromQuery(Name = "wrapLabel")]
    public string? QuerySecondaryLabel { get; set; }

    [SupplyParameterFromQuery(Name = "wrapId")]
    public string? QuerySecondaryIdHex { get; set; }

    [SupplyParameterFromQuery(Name = "wrapClass")]
    public string? QuerySecondaryObjectClass { get; set; }

    [SupplyParameterFromQuery(Name = "wrapKeyType")]
    public string? QuerySecondaryKeyType { get; set; }

    [SupplyParameterFromQuery(Name = "mechanism")]
    public string? QueryMechanism { get; set; }

    [SupplyParameterFromQuery(Name = "attr")]
    public string? QueryAttributeType { get; set; }

    [SupplyParameterFromQuery(Name = "profile")]
    public string? QueryMechanismParameterProfile { get; set; }

    [SupplyParameterFromQuery(Name = "rsaHash")]
    public string? QueryRsaHashProfile { get; set; }

    [SupplyParameterFromQuery(Name = "pssSalt")]
    public int? QueryPssSaltLength { get; set; }

    private IReadOnlyList<HsmDeviceProfile> _devices = [];
    private IReadOnlyList<HsmSlotSummary> _slots = [];
    private string? _selectedDeviceId;
    private string? _selectedSlotId;
    private Pkcs11LabRequest _request = CreateDefaultRequest();
    private Pkcs11LabExecutionResult? _lastResult;
    private readonly List<LabHistoryItem> _history = [];
    private IReadOnlyList<Pkcs11LabSavedTemplate> _templates = [];
    private string? _statusMessage;
    private bool _statusIsError;
    private bool _rememberPin;
    private bool _isRunning;
    private string? _lastAppliedQuerySignature;
    private string _selectedAttributePresetKey = AttributePresetIdentity;
    private Pkcs11LabOperationCategory _operationPaletteCategory = Pkcs11LabOperationCategory.Diagnostics;
    private string _historySearchText = string.Empty;
    private string _historyStatusFilter = "all";
    private string _historyCategoryFilter = "all";
    private string _templateName = string.Empty;
    private string? _templateNotes;
    private string _templateSearchText = string.Empty;
    private string _templateCategoryFilter = "all";

    private const string AttributePresetIdentity = "Identity";
    private const string AttributePresetCapabilities = "Capabilities";
    private const string AttributePresetRsaPublic = "RsaPublic";
    private const string AttributePresetRsaPrivate = "RsaPrivate";
    private const string AttributePresetSecretKey = "SecretKey";
    private const string AttributePresetEcKey = "EcKey";

    private static readonly IReadOnlyDictionary<string, string> AttributePresetLibrary = new Dictionary<string, string>(StringComparer.Ordinal)
    {
        [AttributePresetIdentity] = "0x0, 0x3, 0x102, 0x100",
        [AttributePresetCapabilities] = "0x103, 0x104, 0x105, 0x106, 0x107, 0x108, 0x10a, 0x10c, 0x162, 0x170",
        [AttributePresetRsaPublic] = "0x0, 0x3, 0x102, 0x100, 0x121, 0x122, 0x104, 0x10a, 0x106",
        [AttributePresetRsaPrivate] = "0x0, 0x3, 0x102, 0x100, 0x103, 0x107, 0x108, 0x162, 0x170",
        [AttributePresetSecretKey] = "0x0, 0x3, 0x102, 0x100, 0x161, 0x103, 0x104, 0x105, 0x106, 0x107, 0x162",
        [AttributePresetEcKey] = "0x0, 0x3, 0x102, 0x100, 0x180, 0x181, 0x108, 0x10a"
    };

    private sealed record LabHistoryItem(DateTimeOffset RecordedAt, Pkcs11LabRequest Request, Pkcs11LabExecutionResult Result);

    private bool RequiresSlot => _request.Operation is Pkcs11LabOperation.MechanismList
        or Pkcs11LabOperation.MechanismInfo
        or Pkcs11LabOperation.SessionInfo
        or Pkcs11LabOperation.GenerateRandom
        or Pkcs11LabOperation.DigestText
        or Pkcs11LabOperation.FindObjects
        or Pkcs11LabOperation.SignData
        or Pkcs11LabOperation.VerifySignature
        or Pkcs11LabOperation.EncryptData
        or Pkcs11LabOperation.DecryptData
        or Pkcs11LabOperation.InspectObject
        or Pkcs11LabOperation.WrapKey
        or Pkcs11LabOperation.UnwrapAesKey
        or Pkcs11LabOperation.ReadAttribute;

    private bool CanRun => Guid.TryParse(_selectedDeviceId, out _) && (!RequiresSlot || ulong.TryParse(_selectedSlotId, out _));
    private IReadOnlyList<Pkcs11LabOperation> PaletteOperations => Enum.GetValues<Pkcs11LabOperation>()
        .Where(operation => Pkcs11LabView.GetCategory(operation) == _operationPaletteCategory)
        .ToArray();
    private IReadOnlyList<Pkcs11LabSavedTemplate> FilteredTemplates
    {
        get
        {
            LabTemplateViewRow[] rows = _templates
                .Select(template => new LabTemplateViewRow(
                    template,
                    new Pkcs11LabTemplateListItem(
                        template.Id,
                        template.Name,
                        template.Notes,
                        template.Request.Operation,
                        template.UpdatedUtc,
                        template.Request.DeviceId != Guid.Empty,
                        template.Request.SlotId is not null)))
                .ToArray();

            HashSet<Guid> allowedIds = Pkcs11LabView
                .ApplyTemplateFilters(rows.Select(row => row.View).ToArray(), _templateSearchText, _templateCategoryFilter)
                .Select(item => item.Id)
                .ToHashSet();

            return rows.Where(row => allowedIds.Contains(row.Template.Id)).Select(row => row.Template).ToArray();
        }
    }
    private IReadOnlyList<LabHistoryItem> FilteredHistory
    {
        get
        {
            LabHistoryViewRow[] rows = _history
                .Select(item => new LabHistoryViewRow(
                    item,
                    new Pkcs11LabHistoryListItem(
                        item.RecordedAt,
                        item.Request.Operation,
                        item.Result.Summary,
                        item.Result.Success,
                        item.Result.DurationMilliseconds,
                        item.Result.ArtifactKind,
                        item.Result.CreatedHandleText,
                        item.Result.ArtifactHex)))
                .ToArray();

            HashSet<Pkcs11LabHistoryListItem> allowed = Pkcs11LabView
                .ApplyHistoryFilters(rows.Select(row => row.View).ToArray(), _historySearchText, _historyStatusFilter, _historyCategoryFilter)
                .ToHashSet();

            return rows.Where(row => allowed.Contains(row.View)).Select(row => row.Item).ToArray();
        }
    }

    protected override async Task OnInitializedAsync()
    {
        _devices = await Admin.GetDevicesAsync();
        _selectedDeviceId = _devices.FirstOrDefault()?.Id.ToString();
        _operationPaletteCategory = Pkcs11LabView.GetCategory(_request.Operation);
        await LoadTemplatesAsync();
        await LoadSlotsForSelectedDeviceAsync();
    }

    protected override async Task OnParametersSetAsync()
    {
        if (_devices.Count == 0)
        {
            return;
        }

        string signature = $"{QueryDevice}|{QuerySlot}|{QueryOperation}|{QueryHandle}|{QueryLabel}|{QueryIdHex}|{QueryObjectClass}|{QueryKeyType}|{QuerySecondaryHandle}|{QuerySecondaryLabel}|{QuerySecondaryIdHex}|{QuerySecondaryObjectClass}|{QuerySecondaryKeyType}|{QueryMechanism}|{QueryAttributeType}|{QueryMechanismParameterProfile}|{QueryRsaHashProfile}|{QueryPssSaltLength}";
        if (signature == _lastAppliedQuerySignature)
        {
            return;
        }

        _lastAppliedQuerySignature = signature;

        if (QueryDevice is Guid deviceId && _devices.Any(device => device.Id == deviceId))
        {
            _selectedDeviceId = deviceId.ToString();
            await LoadSlotsForSelectedDeviceAsync();
        }

        if (ulong.TryParse(QuerySlot, out ulong slotId) && _slots.Any(slot => slot.SlotId == (nuint)slotId))
        {
            _selectedSlotId = slotId.ToString();
            await LoadProtectedPinAsync();
        }

        if (Enum.TryParse<Pkcs11LabOperation>(QueryOperation, ignoreCase: true, out Pkcs11LabOperation operation))
        {
            _request.Operation = operation;
            _operationPaletteCategory = Pkcs11LabView.GetCategory(operation);
        }

        if (!string.IsNullOrWhiteSpace(QueryHandle))
        {
            _request.KeyHandleText = QueryHandle;
        }

        if (!string.IsNullOrWhiteSpace(QueryLabel) || !string.IsNullOrWhiteSpace(QueryIdHex) || !string.IsNullOrWhiteSpace(QueryObjectClass) || !string.IsNullOrWhiteSpace(QueryKeyType))
        {
            _request.KeyLabel = QueryLabel;
            _request.KeyIdHex = QueryIdHex;
            _request.KeyObjectClass = QueryObjectClass;
            _request.KeyType = QueryKeyType;
        }

        if (!string.IsNullOrWhiteSpace(QuerySecondaryHandle))
        {
            _request.SecondaryKeyHandleText = QuerySecondaryHandle;
        }

        if (!string.IsNullOrWhiteSpace(QuerySecondaryLabel) || !string.IsNullOrWhiteSpace(QuerySecondaryIdHex) || !string.IsNullOrWhiteSpace(QuerySecondaryObjectClass) || !string.IsNullOrWhiteSpace(QuerySecondaryKeyType))
        {
            _request.SecondaryKeyLabel = QuerySecondaryLabel;
            _request.SecondaryKeyIdHex = QuerySecondaryIdHex;
            _request.SecondaryKeyObjectClass = QuerySecondaryObjectClass;
            _request.SecondaryKeyType = QuerySecondaryKeyType;
        }

        if (!string.IsNullOrWhiteSpace(QueryMechanism))
        {
            _request.MechanismTypeText = QueryMechanism;
        }

        if (Enum.TryParse<Pkcs11LabMechanismParameterProfile>(QueryMechanismParameterProfile, ignoreCase: true, out Pkcs11LabMechanismParameterProfile parameterProfile))
        {
            _request.MechanismParameterProfile = parameterProfile;
        }

        if (Enum.TryParse<Pkcs11LabRsaHashProfile>(QueryRsaHashProfile, ignoreCase: true, out Pkcs11LabRsaHashProfile rsaHashProfile))
        {
            _request.RsaHashProfile = rsaHashProfile;
        }

        if (QueryPssSaltLength is int pssSaltLength)
        {
            _request.PssSaltLength = pssSaltLength;
        }

        if (!string.IsNullOrWhiteSpace(QueryAttributeType))
        {
            _request.AttributeTypeText = QueryAttributeType;
        }
    }

    private async Task OnSelectedDeviceChangedAsync()
    {
        _selectedSlotId = null;
        _request.UserPin = null;
        _rememberPin = false;
        await LoadSlotsForSelectedDeviceAsync();
    }

    private async Task OnSelectedSlotChangedAsync()
    {
        await LoadProtectedPinAsync();
    }

    private async Task LoadSlotsForSelectedDeviceAsync()
    {
        _slots = [];
        if (!Guid.TryParse(_selectedDeviceId, out Guid deviceId))
        {
            return;
        }

        _slots = await Admin.GetSlotsAsync(deviceId);
        _selectedSlotId = _slots.FirstOrDefault()?.SlotId.ToString();
        await LoadProtectedPinAsync();
    }

    private async Task LoadProtectedPinAsync()
    {
        if (Guid.TryParse(_selectedDeviceId, out Guid deviceId) && ulong.TryParse(_selectedSlotId, out ulong slotId))
        {
            _request.UserPin = await PinStore.TryGetAsync(deviceId, (nuint)slotId, "lab");
            _rememberPin = !string.IsNullOrWhiteSpace(_request.UserPin);
        }
    }

    private async Task LoadTemplatesAsync()
        => _templates = await TemplateStore.GetAllAsync();

    private async Task SaveTemplateAsync()
    {
        try
        {
            Pkcs11LabSavedTemplate saved = await TemplateStore.SaveAsync(_templateName, _templateNotes, BuildTemplateDraft());
            _templateName = saved.Name;
            _templateNotes = saved.Notes;
            await LoadTemplatesAsync();
            _statusMessage = $"Saved lab template '{saved.Name}'. PIN values are never stored.";
            _statusIsError = false;
        }
        catch (Exception ex)
        {
            _statusMessage = ex.Message;
            _statusIsError = true;
        }
    }

    private void ResetTemplateDraft()
    {
        _templateName = string.Empty;
        _templateNotes = null;
    }

    private async Task ApplyTemplateAsync(Pkcs11LabSavedTemplate template)
    {
        await ApplyRequestAsync(template.Request);
        _templateName = template.Name;
        _templateNotes = template.Notes;
        _statusMessage = $"Applied lab template '{template.Name}'. Review the device/slot context, then run the operation.";
        _statusIsError = false;
    }

    private async Task DeleteTemplateAsync(Guid templateId)
    {
        await TemplateStore.DeleteAsync(templateId);
        await LoadTemplatesAsync();
        _statusMessage = "Lab template deleted.";
        _statusIsError = false;
    }

    private async Task RunAsync()
    {
        try
        {
            _isRunning = true;
            Pkcs11LabRequest request = BuildRequest();
            _lastResult = await Admin.ExecuteLabAsync(request);
            if (_lastResult.Success)
            {
                RecordHistory(request, _lastResult);
            }

            await PersistPinAsync(request);
            _statusMessage = _lastResult.Summary;
            _statusIsError = !_lastResult.Success;
        }
        catch (Exception ex)
        {
            _statusMessage = ex.Message;
            _statusIsError = true;
        }
        finally
        {
            _isRunning = false;
        }
    }

    private Pkcs11LabRequest BuildRequest()
    {
        if (!Guid.TryParse(_selectedDeviceId, out Guid deviceId))
        {
            throw new InvalidOperationException("Select a device first.");
        }

        nuint? slotId = null;
        if (RequiresSlot)
        {
            if (!ulong.TryParse(_selectedSlotId, out ulong parsedSlotId))
            {
                throw new InvalidOperationException("Selected operation requires a slot.");
            }

            slotId = (nuint)parsedSlotId;
        }

        return new Pkcs11LabRequest
        {
            DeviceId = deviceId,
            SlotId = slotId,
            Operation = _request.Operation,
            OpenReadWriteSession = _request.OpenReadWriteSession,
            LoginUserIfPinProvided = _request.LoginUserIfPinProvided,
            UserPin = _request.UserPin,
            MechanismTypeText = _request.MechanismTypeText,
            AttributeTypeText = _request.AttributeTypeText,
            MechanismParameterProfile = _request.MechanismParameterProfile,
            MechanismIvHex = _request.MechanismIvHex,
            MechanismAdditionalDataHex = _request.MechanismAdditionalDataHex,
            MechanismCounterBits = _request.MechanismCounterBits,
            MechanismTagBits = _request.MechanismTagBits,
            RsaHashProfile = _request.RsaHashProfile,
            RsaOaepSourceEncoding = _request.RsaOaepSourceEncoding,
            RsaOaepSourceText = _request.RsaOaepSourceText,
            RsaOaepSourceHex = _request.RsaOaepSourceHex,
            PssSaltLength = _request.PssSaltLength,
            KeyHandleText = _request.KeyHandleText,
            KeyLabel = _request.KeyLabel,
            KeyIdHex = _request.KeyIdHex,
            KeyObjectClass = _request.KeyObjectClass,
            KeyType = _request.KeyType,
            SecondaryKeyHandleText = _request.SecondaryKeyHandleText,
            SecondaryKeyLabel = _request.SecondaryKeyLabel,
            SecondaryKeyIdHex = _request.SecondaryKeyIdHex,
            SecondaryKeyObjectClass = _request.SecondaryKeyObjectClass,
            SecondaryKeyType = _request.SecondaryKeyType,
            DigestAlgorithm = _request.DigestAlgorithm,
            PayloadEncoding = _request.PayloadEncoding,
            TextInput = _request.TextInput,
            DataHex = _request.DataHex,
            SignatureHex = _request.SignatureHex,
            UnwrapTargetLabel = _request.UnwrapTargetLabel,
            UnwrapTargetIdHex = _request.UnwrapTargetIdHex,
            UnwrapTokenObject = _request.UnwrapTokenObject,
            UnwrapPrivateObject = _request.UnwrapPrivateObject,
            UnwrapSensitive = _request.UnwrapSensitive,
            UnwrapExtractable = _request.UnwrapExtractable,
            UnwrapAllowEncrypt = _request.UnwrapAllowEncrypt,
            UnwrapAllowDecrypt = _request.UnwrapAllowDecrypt,
            LabelFilter = _request.LabelFilter,
            IdHex = _request.IdHex,
            ObjectClassFilter = _request.ObjectClassFilter,
            RandomLength = _request.RandomLength,
            MaxObjects = _request.MaxObjects
        };
    }

    private Pkcs11LabRequest BuildTemplateDraft()
    {
        Pkcs11LabRequest request = CopyRequest(_request);
        request.UserPin = null;
        request.DeviceId = Guid.TryParse(_selectedDeviceId, out Guid deviceId) ? deviceId : Guid.Empty;
        request.SlotId = ulong.TryParse(_selectedSlotId, out ulong slotId) ? (nuint)slotId : null;
        return request;
    }

    private async Task PersistPinAsync(Pkcs11LabRequest request)
    {
        if (request.SlotId is not nuint slotId)
        {
            return;
        }

        if (_rememberPin && !string.IsNullOrWhiteSpace(request.UserPin))
        {
            await PinStore.SaveAsync(request.DeviceId, slotId, "lab", request.UserPin);
        }
        else
        {
            await PinStore.DeleteAsync(request.DeviceId, slotId, "lab");
        }
    }

    private void ResetOperation()
    {
        Pkcs11LabRequest fresh = CreateDefaultRequest();
        fresh.Operation = _request.Operation;
        fresh.UserPin = _request.UserPin;
        fresh.LoginUserIfPinProvided = _request.LoginUserIfPinProvided;
        _request = fresh;
        _operationPaletteCategory = Pkcs11LabView.GetCategory(_request.Operation);
        _lastResult = null;
        _statusMessage = null;
        _statusIsError = false;
    }

    private Task OnOperationChangedAsync()
    {
        _operationPaletteCategory = Pkcs11LabView.GetCategory(_request.Operation);
        return Task.CompletedTask;
    }

    private void SelectOperationCategory(Pkcs11LabOperationCategory category)
        => _operationPaletteCategory = category;

    private Task SelectOperation(Pkcs11LabOperation operation)
    {
        _request.Operation = operation;
        _operationPaletteCategory = Pkcs11LabView.GetCategory(operation);
        return Task.CompletedTask;
    }

    private static Pkcs11LabRequest CreateDefaultRequest()
        => new()
        {
            Operation = Pkcs11LabOperation.ModuleInfo,
            DigestAlgorithm = Pkcs11LabDigestAlgorithm.Sha256,
            PayloadEncoding = Pkcs11LabPayloadEncoding.Utf8Text,
            MechanismParameterProfile = Pkcs11LabMechanismParameterProfile.None,
            MechanismCounterBits = 128,
            MechanismTagBits = 128,
            RsaHashProfile = Pkcs11LabRsaHashProfile.Sha256,
            RsaOaepSourceEncoding = Pkcs11LabPayloadEncoding.Utf8Text,
            PssSaltLength = 32,
            LoginUserIfPinProvided = true,
            RandomLength = 32,
            MaxObjects = 20
        };

    private static string GetOperationLabel(Pkcs11LabOperation operation)
        => operation switch
        {
            Pkcs11LabOperation.ModuleInfo => "Module Info",
            Pkcs11LabOperation.InterfaceDiscovery => "Interface Discovery",
            Pkcs11LabOperation.SlotSnapshot => "Slot Snapshot",
            Pkcs11LabOperation.MechanismList => "Mechanism List",
            Pkcs11LabOperation.MechanismInfo => "Mechanism Info",
            Pkcs11LabOperation.SessionInfo => "Session Info",
            Pkcs11LabOperation.GenerateRandom => "Generate Random",
            Pkcs11LabOperation.DigestText => "Digest Text",
            Pkcs11LabOperation.FindObjects => "Find Objects",
            Pkcs11LabOperation.SignData => "Sign Data",
            Pkcs11LabOperation.VerifySignature => "Verify Signature",
            Pkcs11LabOperation.EncryptData => "Encrypt Data",
            Pkcs11LabOperation.DecryptData => "Decrypt Data",
            Pkcs11LabOperation.InspectObject => "Inspect Object",
            Pkcs11LabOperation.WrapKey => "Wrap Key",
            Pkcs11LabOperation.UnwrapAesKey => "Unwrap AES Key",
            Pkcs11LabOperation.ReadAttribute => "Read Attribute",
            _ => operation.ToString()
        };

    private static string GetOperationDescription(Pkcs11LabOperation operation)
        => operation switch
        {
            Pkcs11LabOperation.ModuleInfo => "`C_GetInfo` ve module-level metadata görünümü.",
            Pkcs11LabOperation.InterfaceDiscovery => "`C_GetInterfaceList` / PKCS#11 v3 interface discovery görünümü.",
            Pkcs11LabOperation.SlotSnapshot => "Slot ve token snapshot bilgilerini topluca oku.",
            Pkcs11LabOperation.MechanismList => "Seçilen slot için mechanism listesini ve flag özetlerini getir.",
            Pkcs11LabOperation.MechanismInfo => "Belirli bir mechanism tipi için detay oku.",
            Pkcs11LabOperation.SessionInfo => "Transient session açıp `C_GetSessionInfo` çıktısını gör.",
            Pkcs11LabOperation.GenerateRandom => "Token RNG üzerinden `C_GenerateRandom` çalıştır.",
            Pkcs11LabOperation.DigestText => "Metni UTF-8 olarak digest edip sonucu hex göster.",
            Pkcs11LabOperation.FindObjects => "`C_FindObjects*` ile obje arayıp özetleri göster.",
            Pkcs11LabOperation.SignData => "Seçilen handle ile `C_Sign` çalıştırıp imzayı hex olarak üret.",
            Pkcs11LabOperation.VerifySignature => "Seçilen handle ile `C_Verify` çalıştırıp sonucu doğrula.",
            Pkcs11LabOperation.EncryptData => "Seçilen handle ile `C_Encrypt` çalıştırıp ciphertext hex üret.",
            Pkcs11LabOperation.DecryptData => "Seçilen handle ile `C_Decrypt` çalıştırıp plaintext hex/UTF-8 çıktısı göster.",
            Pkcs11LabOperation.InspectObject => "Seçilen handle için common attribute snapshot ve capability görünümünü göster.",
            Pkcs11LabOperation.WrapKey => "Bir wrapping key handle ile başka bir key handle’ı `C_WrapKey` üzerinden sarıp blob üret.",
            Pkcs11LabOperation.UnwrapAesKey => "Wrapped blob’u kontrollü AES secret-key template ile `C_UnwrapKey` üzerinden aç.",
            Pkcs11LabOperation.ReadAttribute => "Seçilen handle üzerinde bir veya daha fazla ham attribute code okuyup status/length/raw hex görünümü al.",
            _ => operation.ToString()
        };

    private static string GetPrimaryHandleLabel(Pkcs11LabOperation operation)
        => operation switch
        {
            Pkcs11LabOperation.WrapKey => "Wrapped Target Handle",
            Pkcs11LabOperation.UnwrapAesKey => "Unwrapping Key Handle",
            Pkcs11LabOperation.ReadAttribute => "Key/Object Handle",
            _ => "Key/Object Handle"
        };

    private void AppendAttributePreset(string value)
        => _request.AttributeTypeText = string.IsNullOrWhiteSpace(_request.AttributeTypeText)
            ? value
            : $"{_request.AttributeTypeText}, {value}";

    private void ClearAttributePresets()
        => _request.AttributeTypeText = null;

    private void ApplySelectedAttributePreset()
        => _request.AttributeTypeText = AttributePresetLibrary[_selectedAttributePresetKey];

    private void AppendSelectedAttributePreset()
        => _request.AttributeTypeText = string.IsNullOrWhiteSpace(_request.AttributeTypeText)
            ? AttributePresetLibrary[_selectedAttributePresetKey]
            : $"{_request.AttributeTypeText}, {AttributePresetLibrary[_selectedAttributePresetKey]}";

    private void RecordHistory(Pkcs11LabRequest request, Pkcs11LabExecutionResult result)
    {
        _history.Insert(0, new LabHistoryItem(DateTimeOffset.UtcNow, CopyRequest(request), result));
        if (_history.Count > 8)
        {
            _history.RemoveRange(8, _history.Count - 8);
        }
    }

    private void ClearHistory()
        => _history.Clear();

    private async Task ApplyHistoryRequestAsync(LabHistoryItem item)
    {
        await ApplyRequestAsync(item.Request);
        _statusMessage = "Scenario request restored into the editor.";
        _statusIsError = false;
    }

    private async Task PrepareVerifyFromHistoryAsync(LabHistoryItem item)
    {
        Pkcs11LabPreparedRequest prepared = Pkcs11LabRequestReuse.PrepareVerify(item.Request, item.Result);
        await ApplyRequestAsync(prepared.Request);
        _statusMessage = string.IsNullOrWhiteSpace(prepared.WarningMessage)
            ? "Signature and original payload were moved into Verify. Matching locator metadata was also prepared for session-safe re-resolution."
            : $"Signature and original payload were moved into Verify. {prepared.WarningMessage}";
        _statusIsError = false;
    }

    private async Task PrepareDecryptFromHistoryAsync(LabHistoryItem item)
    {
        Pkcs11LabPreparedRequest prepared = Pkcs11LabRequestReuse.PrepareDecrypt(item.Request, item.Result);
        await ApplyRequestAsync(prepared.Request);
        _statusMessage = string.IsNullOrWhiteSpace(prepared.WarningMessage)
            ? "Ciphertext was moved into Decrypt. Matching locator metadata was prepared so the current session can re-resolve the decrypt key safely."
            : $"Ciphertext was moved into Decrypt. {prepared.WarningMessage}";
        _statusIsError = false;
    }

    private async Task PrepareUnwrapFromHistoryAsync(LabHistoryItem item)
    {
        Pkcs11LabPreparedRequest prepared = Pkcs11LabRequestReuse.PrepareUnwrap(item.Request, item.Result);
        await ApplyRequestAsync(prepared.Request);
        _statusMessage = "Wrapped blob was moved into Unwrap AES Key and the previous wrapping key locator was reused as the unwrapping key reference.";
        _statusIsError = false;
    }

    private async Task PrepareInspectCreatedHandleAsync(LabHistoryItem item)
    {
        Pkcs11LabPreparedRequest prepared = Pkcs11LabRequestReuse.PrepareInspectCreated(item.Request, item.Result);
        if (!string.IsNullOrWhiteSpace(prepared.WarningMessage))
        {
            _statusMessage = prepared.WarningMessage;
            _statusIsError = false;
            return;
        }

        await ApplyRequestAsync(prepared.Request);
        _statusMessage = "Prepared Inspect Object for the created object using session-safe locator metadata.";
        _statusIsError = false;
    }

    private async Task OpenInspectForCreatedHandleAsync()
    {
        if (_lastResult is null || string.IsNullOrWhiteSpace(_lastResult.CreatedHandleText))
        {
            return;
        }

        Pkcs11LabPreparedRequest prepared = Pkcs11LabRequestReuse.PrepareInspectCreated(_request, _lastResult);
        if (!string.IsNullOrWhiteSpace(prepared.WarningMessage))
        {
            _statusMessage = prepared.WarningMessage;
            _statusIsError = false;
            return;
        }

        await ApplyRequestAsync(prepared.Request);
        _statusMessage = "Prepared Inspect Object for the created object using session-safe locator metadata.";
        _statusIsError = false;
    }

    private async Task ApplyRequestAsync(Pkcs11LabRequest request)
    {
        if (request.DeviceId != Guid.Empty && _devices.Any(device => device.Id == request.DeviceId))
        {
            _selectedDeviceId = request.DeviceId.ToString();
        }
        else if (string.IsNullOrWhiteSpace(_selectedDeviceId))
        {
            _selectedDeviceId = _devices.FirstOrDefault()?.Id.ToString();
        }

        await LoadSlotsForSelectedDeviceAsync();

        if (request.SlotId is nuint slotId && _slots.Any(slot => slot.SlotId == slotId))
        {
            _selectedSlotId = slotId.ToString();
            await LoadProtectedPinAsync();
        }

        _request = CopyRequest(request);
        _request.UserPin = null;
        _operationPaletteCategory = Pkcs11LabView.GetCategory(_request.Operation);
        _lastResult = null;
    }

    private static Pkcs11LabRequest CopyRequest(Pkcs11LabRequest request)
        => Pkcs11LabRequestReuse.Copy(request);

    private static bool CanPrepareVerify(LabHistoryItem item)
        => item.Result.Success && item.Result.ArtifactKind == Pkcs11LabArtifactKind.Signature && !string.IsNullOrWhiteSpace(item.Result.ArtifactHex);

    private static bool CanPrepareDecrypt(LabHistoryItem item)
        => item.Result.Success && item.Result.ArtifactKind == Pkcs11LabArtifactKind.Ciphertext && !string.IsNullOrWhiteSpace(item.Result.ArtifactHex);

    private static bool CanPrepareUnwrap(LabHistoryItem item)
        => item.Result.Success && item.Result.ArtifactKind == Pkcs11LabArtifactKind.WrappedKey && !string.IsNullOrWhiteSpace(item.Result.ArtifactHex);

    private static bool CanInspectCreated(LabHistoryItem item)
        => Pkcs11LabRequestReuse.CanInspectCreated(item.Result);

    private static string? GetCreatedObjectLocatorSummary(Pkcs11LabExecutionResult result)
        => Pkcs11LabRequestReuse.DescribeLocator(result.CreatedLabel, result.CreatedIdHex, result.CreatedObjectClass, result.CreatedKeyType);

    private static string GetHistoryBadgeClass(Pkcs11LabExecutionResult result)
        => result.Success ? "text-bg-success" : "text-bg-danger";

    private static string GetHistoryBadgeText(Pkcs11LabExecutionResult result)
        => $"{result.DurationMilliseconds} ms";

    private static string GetCategoryLabel(Pkcs11LabOperationCategory category)
        => category switch
        {
            Pkcs11LabOperationCategory.Diagnostics => "Diagnostics",
            Pkcs11LabOperationCategory.Crypto => "Crypto",
            Pkcs11LabOperationCategory.Objects => "Objects",
            Pkcs11LabOperationCategory.Attributes => "Attributes",
            _ => category.ToString()
        };

    private sealed record LabTemplateViewRow(Pkcs11LabSavedTemplate Template, Pkcs11LabTemplateListItem View);
    private sealed record LabHistoryViewRow(LabHistoryItem Item, Pkcs11LabHistoryListItem View);
}
