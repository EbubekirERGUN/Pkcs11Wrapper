using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Rendering;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;
using Pkcs11Wrapper.Admin.Infrastructure;

namespace Pkcs11Wrapper.Admin.Web.Components.Pages;

public partial class Keys
{
    private IReadOnlyList<HsmDeviceProfile> _devices = [];
    private IReadOnlyList<HsmSlotSummary> _slots = [];
    private IReadOnlyList<HsmKeyObjectSummary> _keys = [];
    private HsmKeyObjectPage? _keyPage;
    private readonly List<string?> _previousPageCursors = [];
    private string? _currentCursor;
    private string? _selectedDeviceId;
    private string? _selectedSlotId;
    private string? _labelFilter;
    private string _searchText = string.Empty;
    private string _classFilter = "all";
    private string _capabilityFilter = "all";
    private string _sortMode = "handle";
    private int _pageSize = 25;
    private int _pageIndex = 1;
    private string? _userPin;
    private bool _rememberPin;
    private HsmObjectDetail? _selectedDetail;
    private nuint? _selectedDetailHandle;
    private HsmKeyObjectSummary? _destroyTarget;
    private DestroyObjectRequest _destroyRequest = new();
    private UpdateObjectAttributesRequest? _editRequest;
    private CopyObjectRequest? _copyRequest;
    private KeyManagementSlotCapabilities? _slotCapabilities;
    private GenerateAesKeyRequest _aesRequest = new() { Label = "aes-admin-" + Guid.NewGuid().ToString("N")[..10] };
    private ImportAesKeyRequest _importAesRequest = new() { Label = "aes-import-" + Guid.NewGuid().ToString("N")[..10] };
    private GenerateRsaKeyPairRequest _rsaRequest = new() { Label = "rsa-admin-" + Guid.NewGuid().ToString("N")[..10] };
    private string? _statusMessage;
    private bool _statusIsError;
    private bool _isOperator;

    private HsmDeviceProfile? SelectedDevice
        => Guid.TryParse(_selectedDeviceId, out Guid deviceId)
            ? _devices.FirstOrDefault(device => device.Id == deviceId)
            : null;
    private bool CanLoadKeys => Guid.TryParse(_selectedDeviceId, out _) && nuint.TryParse(_selectedSlotId, out _);
    private bool CanManageKeys => CanLoadKeys && !string.IsNullOrWhiteSpace(_userPin);
    private bool CanGenerateAes => CanManageKeys && _slotCapabilities?.SupportsAesKeyGeneration == true;
    private bool CanImportAes => CanManageKeys && _slotCapabilities?.SupportsAesObjectImport == true;
    private bool CanGenerateRsa => CanManageKeys && _slotCapabilities?.SupportsRsaKeyPairGeneration == true;
    private bool CanSaveEdit => CanManageKeys && _editRequest is not null && (_selectedDetail?.EditCapabilities.CanEditAnyAttributes ?? true);
    private bool CanCopyObject => CanManageKeys && _copyRequest is not null && _slotCapabilities?.TokenPresent == true;
    private bool HasLoadedPage => _keyPage is not null;
    private bool HasNextPage => _keyPage?.HasNextPage == true && !string.IsNullOrWhiteSpace(_keyPage.NextCursor);
    private bool HasPreviousPage => _previousPageCursors.Count != 0;
    private string DestroyConfirmationText => _destroyTarget is null ? string.Empty : HsmAdminService.BuildDestroyConfirmationText(_destroyTarget.Handle, _destroyTarget.Label);
    private IReadOnlyList<HsmKeyObjectSummary> CurrentPageKeys => _keys;
    private int CurrentPageIndex => _pageIndex;
    private int CurrentRangeStart => _keys.Count == 0 ? 0 : ((_pageIndex - 1) * _pageSize) + 1;
    private int CurrentRangeEnd => _keys.Count == 0 ? 0 : CurrentRangeStart + _keys.Count - 1;
    private string PageModeDescription => _keyPage?.UsedStreamingCursor == true
        ? "Streaming cursor mode"
        : "Server-side sorted page";

    protected override async Task OnInitializedAsync()
    {
        AuthenticationState state = await AuthenticationStateProvider.GetAuthenticationStateAsync();
        _isOperator = state.User.IsInRole(AdminRoles.Operator) || state.User.IsInRole(AdminRoles.Admin);
        _devices = await Admin.GetDevicesAsync();
        _selectedDeviceId = _devices.FirstOrDefault()?.Id.ToString();
        await ReloadSlotsAsync();
    }

    private async Task OnSelectedDeviceChangedAsync() => await ReloadSlotsAsync();
    private async Task OnSelectedSlotChangedAsync()
    {
        ResetPagedListState();
        await ReloadSlotCapabilitiesAsync();
    }

    private async Task ReloadSlotsAsync()
    {
        ResetPagedListState();
        _selectedDetail = null;
        _selectedDetailHandle = null;
        _destroyTarget = null;
        _destroyRequest = new();
        _editRequest = null;
        _copyRequest = null;
        _slotCapabilities = null;

        if (!Guid.TryParse(_selectedDeviceId, out Guid deviceId))
        {
            _slots = [];
            return;
        }

        _slots = await Admin.GetSlotsAsync(deviceId);
        _selectedSlotId = _slots.FirstOrDefault()?.SlotId.ToString();
        await LoadProtectedPinAsync();
        await ReloadSlotCapabilitiesAsync();
    }

    private async Task LoadProtectedPinAsync()
    {
        if (TryGetSelection(out Guid deviceId, out nuint slotId))
        {
            _userPin = await PinStore.TryGetAsync(deviceId, slotId, "keys");
            _rememberPin = !string.IsNullOrWhiteSpace(_userPin);
        }
    }

    private async Task ReloadSlotCapabilitiesAsync()
    {
        _slotCapabilities = null;
        if (!TryGetSelection(out Guid deviceId, out nuint slotId))
        {
            return;
        }

        try
        {
            _slotCapabilities = await Admin.GetKeyManagementCapabilitiesAsync(deviceId, slotId);
        }
        catch (Exception ex)
        {
            SetStatus(ex.Message, true);
        }
    }

    private async Task LoadKeysAsync()
    {
        await LoadKeysPageAsync(resetCursor: true);
    }

    private async Task LoadKeysPageAsync(bool resetCursor = false)
    {
        try
        {
            if (!TryGetSelection(out Guid deviceId, out nuint slotId))
            {
                return;
            }

            if (resetCursor)
            {
                ResetPagedListState();
            }

            KeyObjectPageRequest request = new()
            {
                LabelFilter = _labelFilter,
                SearchText = _searchText,
                ClassFilter = _classFilter,
                CapabilityFilter = _capabilityFilter,
                SortMode = _sortMode,
                PageSize = _pageSize,
                Cursor = _currentCursor
            };

            _keyPage = await Admin.GetKeyPageAsync(deviceId, slotId, request, _userPin);
            _keys = _keyPage.Items;
            await PersistPinAsync(deviceId, slotId);
            _destroyTarget = null;
            _destroyRequest = new();
            _selectedDetail = null;
            _selectedDetailHandle = null;
            _editRequest = null;
            _copyRequest = null;
            SetStatus($"Loaded {_keys.Count} object(s) on page {_pageIndex}.", false);
        }
        catch (Exception ex)
        {
            SetStatus(ex.Message, true);
        }
    }

    private async Task ShowDetailAsync(HsmKeyObjectSummary key)
    {
        try
        {
            if (!TryGetSelection(out Guid deviceId, out nuint slotId))
            {
                return;
            }

            _selectedDetail = await Admin.GetObjectDetailAsync(deviceId, slotId, key.Handle, _userPin);
            _selectedDetailHandle = key.Handle;
            _destroyTarget = null;
            _destroyRequest = new();
            _editRequest = null;
            _copyRequest = null;
            SetStatus($"Loaded detail for handle {key.Handle}.", false);
        }
        catch (Exception ex)
        {
            SetStatus(ex.Message, true);
        }
    }

    private void ClearDetail()
    {
        _selectedDetail = null;
        _selectedDetailHandle = null;
    }

    private void OpenLabInspect(HsmKeyObjectSummary key)
        => Navigation.NavigateTo(BuildLabUri(
            key.DeviceId,
            key.SlotId,
            Pkcs11LabOperation.InspectObject,
            primaryHandle: key.Handle,
            primaryLabel: key.Label,
            primaryIdHex: key.IdHex,
            primaryObjectClass: key.ObjectClass,
            primaryKeyType: key.KeyType));

    private void OpenLabInspect(HsmObjectDetail detail)
        => Navigation.NavigateTo(BuildLabUri(
            detail.DeviceId,
            detail.SlotId,
            Pkcs11LabOperation.InspectObject,
            primaryHandle: detail.Handle,
            primaryLabel: detail.Label,
            primaryIdHex: detail.IdHex,
            primaryObjectClass: detail.ObjectClass,
            primaryKeyType: detail.KeyType));

    private void OpenLabAttributePreset(HsmObjectDetail detail, string attributeType)
        => Navigation.NavigateTo(BuildLabUri(
            detail.DeviceId,
            detail.SlotId,
            Pkcs11LabOperation.ReadAttribute,
            primaryHandle: detail.Handle,
            primaryLabel: detail.Label,
            primaryIdHex: detail.IdHex,
            primaryObjectClass: detail.ObjectClass,
            primaryKeyType: detail.KeyType,
            attributeType: attributeType));

    private void OpenLabCryptoPreset(HsmObjectDetail detail, Pkcs11LabOperation operation, string mechanism)
        => Navigation.NavigateTo(BuildLabUri(
            detail.DeviceId,
            detail.SlotId,
            operation,
            primaryHandle: detail.Handle,
            primaryLabel: detail.Label,
            primaryIdHex: detail.IdHex,
            primaryObjectClass: detail.ObjectClass,
            primaryKeyType: detail.KeyType,
            mechanism: mechanism));

    private void OpenLabRsaPreset(HsmObjectDetail detail, Pkcs11LabOperation operation, string mechanism, Pkcs11LabMechanismParameterProfile parameterProfile, Pkcs11LabRsaHashProfile rsaHashProfile, int? pssSaltLength = null)
        => Navigation.NavigateTo(
            BuildLabUri(
                detail.DeviceId,
                detail.SlotId,
                operation,
                primaryHandle: detail.Handle,
                primaryLabel: detail.Label,
                primaryIdHex: detail.IdHex,
                primaryObjectClass: detail.ObjectClass,
                primaryKeyType: detail.KeyType,
                mechanism: mechanism,
                parameterProfile: parameterProfile,
                rsaHashProfile: rsaHashProfile,
                pssSaltLength: pssSaltLength));

    private void OpenLabWrapPreset(HsmObjectDetail detail, string mechanism)
        => Navigation.NavigateTo(
            BuildLabUri(
                detail.DeviceId,
                detail.SlotId,
                Pkcs11LabOperation.WrapKey,
                secondaryHandle: detail.Handle,
                secondaryLabel: detail.Label,
                secondaryIdHex: detail.IdHex,
                secondaryObjectClass: detail.ObjectClass,
                secondaryKeyType: detail.KeyType,
                mechanism: mechanism));

    private void OpenLabUnwrapPreset(HsmObjectDetail detail, string mechanism)
        => Navigation.NavigateTo(
            BuildLabUri(
                detail.DeviceId,
                detail.SlotId,
                Pkcs11LabOperation.UnwrapAesKey,
                primaryHandle: detail.Handle,
                primaryLabel: detail.Label,
                primaryIdHex: detail.IdHex,
                primaryObjectClass: detail.ObjectClass,
                primaryKeyType: detail.KeyType,
                mechanism: mechanism));

    private void BeginEdit(HsmKeyObjectSummary key)
    {
        _editRequest = new UpdateObjectAttributesRequest { Handle = key.Handle, CurrentLabel = key.Label, Label = key.Label ?? $"object-{key.Handle}", IdHex = key.IdHex };
        _copyRequest = null;
        _destroyTarget = null;
        _selectedDetail = null;
        _selectedDetailHandle = key.Handle;
    }

    private void BeginEditFromDetail(HsmObjectDetail detail)
    {
        _editRequest = new UpdateObjectAttributesRequest { Handle = detail.Handle, CurrentLabel = detail.Label, Label = detail.Label ?? $"object-{detail.Handle}", IdHex = detail.IdHex };
        _copyRequest = null;
        _destroyTarget = null;
    }

    private void BeginCopy(HsmKeyObjectSummary key)
    {
        _copyRequest = new CopyObjectRequest { SourceHandle = key.Handle, SourceLabel = key.Label, SourceObjectClass = key.ObjectClass, Label = $"{(key.Label ?? "object")}-copy", IdHex = key.IdHex };
        _editRequest = null;
        _destroyTarget = null;
        _selectedDetail = null;
        _selectedDetailHandle = key.Handle;
    }

    private void BeginCopyFromDetail(HsmObjectDetail detail)
    {
        _copyRequest = new CopyObjectRequest { SourceHandle = detail.Handle, SourceLabel = detail.Label, SourceObjectClass = detail.ObjectClass, Label = $"{(detail.Label ?? "object")}-copy", IdHex = detail.IdHex };
        _editRequest = null;
        _destroyTarget = null;
    }

    private void ResetEditBooleans()
    {
        if (_editRequest is null) return;
        _editRequest.Token = null;
        _editRequest.Private = null;
        _editRequest.Extractable = null;
        _editRequest.AllowEncrypt = null;
        _editRequest.AllowDecrypt = null;
        _editRequest.AllowSign = null;
        _editRequest.AllowVerify = null;
        _editRequest.AllowWrap = null;
        _editRequest.AllowUnwrap = null;
        _editRequest.AllowDerive = null;
    }

    private void ResetCopyBooleans()
    {
        if (_copyRequest is null) return;
        _copyRequest.Token = null;
        _copyRequest.Private = null;
        _copyRequest.Extractable = null;
        _copyRequest.AllowEncrypt = null;
        _copyRequest.AllowDecrypt = null;
        _copyRequest.AllowSign = null;
        _copyRequest.AllowVerify = null;
        _copyRequest.AllowWrap = null;
        _copyRequest.AllowUnwrap = null;
        _copyRequest.AllowDerive = null;
    }

    private void CancelEdit() => _editRequest = null;
    private void CancelCopy() => _copyRequest = null;

    private void BeginDestroy(HsmKeyObjectSummary key)
    {
        _destroyTarget = key;
        _selectedDetail = null;
        _selectedDetailHandle = null;
        _editRequest = null;
        _copyRequest = null;
        _destroyRequest = new DestroyObjectRequest { Handle = key.Handle, Label = key.Label, UserPin = _userPin ?? string.Empty };
    }

    private void CancelDestroy()
    {
        _destroyTarget = null;
        _destroyRequest = new();
    }

    private async Task SaveEditAsync()
    {
        try
        {
            if (_editRequest is null || !TryGetSelection(out Guid deviceId, out nuint slotId)) return;
            await PersistPinAsync(deviceId, slotId);
            KeyManagementResult result = await Admin.UpdateObjectAttributesAsync(deviceId, slotId, _editRequest, _userPin ?? string.Empty);
            SetStatus(result.Summary, false);
            _labelFilter = result.Label;
            _editRequest = null;
            await LoadKeysAsync();
        }
        catch (Exception ex)
        {
            SetStatus(ex.Message, true);
        }
    }

    private async Task CopyAsync()
    {
        try
        {
            if (_copyRequest is null || !TryGetSelection(out Guid deviceId, out nuint slotId)) return;
            await PersistPinAsync(deviceId, slotId);
            KeyManagementResult result = await Admin.CopyObjectAsync(deviceId, slotId, _copyRequest, _userPin ?? string.Empty);
            SetStatus(result.Summary, false);
            _labelFilter = result.Label;
            _copyRequest = null;
            await LoadKeysAsync();
        }
        catch (Exception ex)
        {
            SetStatus(ex.Message, true);
        }
    }

    private async Task DestroyAsync()
    {
        try
        {
            if (_destroyTarget is null || !TryGetSelection(out Guid deviceId, out nuint slotId)) return;
            await PersistPinAsync(deviceId, slotId);
            _destroyRequest.Handle = _destroyTarget.Handle;
            _destroyRequest.Label = _destroyTarget.Label;
            _destroyRequest.UserPin = _userPin ?? string.Empty;
            await Admin.DestroyObjectAsync(deviceId, slotId, _destroyRequest);
            SetStatus($"Destroyed object handle {_destroyTarget.Handle}.", false);
            _destroyTarget = null;
            _destroyRequest = new();
            await LoadKeysAsync();
        }
        catch (Exception ex)
        {
            SetStatus(ex.Message, true);
        }
    }

    private async Task GenerateAesAsync()
    {
        try
        {
            if (!CanGenerateAes || !TryGetSelection(out Guid deviceId, out nuint slotId))
            {
                SetStatus(string.Join(' ', GetAesWarnings()), true);
                return;
            }

            KeyManagementResult result = await Admin.GenerateAesKeyAsync(deviceId, slotId, _aesRequest, _userPin ?? string.Empty);
            await PersistPinAsync(deviceId, slotId);
            SetStatus(result.Summary, false);
            _labelFilter = result.Label;
            _aesRequest = new GenerateAesKeyRequest { Label = "aes-admin-" + Guid.NewGuid().ToString("N")[..10], SizeBytes = _aesRequest.SizeBytes };
            await LoadKeysAsync();
        }
        catch (Exception ex)
        {
            SetStatus(ex.Message, true);
        }
    }

    private async Task ImportAesAsync()
    {
        try
        {
            if (!CanImportAes || !TryGetSelection(out Guid deviceId, out nuint slotId))
            {
                SetStatus(string.Join(' ', GetImportWarnings()), true);
                return;
            }

            KeyManagementResult result = await Admin.ImportAesKeyAsync(deviceId, slotId, _importAesRequest, _userPin ?? string.Empty);
            await PersistPinAsync(deviceId, slotId);
            SetStatus(result.Summary, false);
            _labelFilter = result.Label;
            _importAesRequest = new ImportAesKeyRequest { Label = "aes-import-" + Guid.NewGuid().ToString("N")[..10] };
            await LoadKeysAsync();
        }
        catch (Exception ex)
        {
            SetStatus(ex.Message, true);
        }
    }

    private async Task GenerateRsaAsync()
    {
        try
        {
            if (!CanGenerateRsa || !TryGetSelection(out Guid deviceId, out nuint slotId))
            {
                SetStatus(string.Join(' ', GetRsaWarnings()), true);
                return;
            }

            KeyManagementResult result = await Admin.GenerateRsaKeyPairAsync(deviceId, slotId, _rsaRequest, _userPin ?? string.Empty);
            await PersistPinAsync(deviceId, slotId);
            SetStatus(result.Summary, false);
            _labelFilter = result.Label;
            _rsaRequest = new GenerateRsaKeyPairRequest { Label = "rsa-admin-" + Guid.NewGuid().ToString("N")[..10], ModulusBits = _rsaRequest.ModulusBits, PublicExponentHex = _rsaRequest.PublicExponentHex };
            await LoadKeysAsync();
        }
        catch (Exception ex)
        {
            SetStatus(ex.Message, true);
        }
    }

    private bool TryGetSelection(out Guid deviceId, out nuint slotId)
    {
        bool hasDevice = Guid.TryParse(_selectedDeviceId, out deviceId);
        bool hasSlot = nuint.TryParse(_selectedSlotId, out slotId);
        return hasDevice && hasSlot;
    }

    private bool CanEdit(Func<ObjectEditCapabilities, bool> selector) => _selectedDetail is not null && selector(_selectedDetail.EditCapabilities);

    private IReadOnlyList<string> GetAesWarnings()
    {
        List<string> warnings = [];
        if (!CanLoadKeys) warnings.Add("Select a device and slot first.");
        if (string.IsNullOrWhiteSpace(_userPin)) warnings.Add("User PIN is required for key-management operations.");
        if (_slotCapabilities?.SupportsAesKeyGeneration == false) warnings.Add("Selected slot does not expose CKM_AES_KEY_GEN with generate support.");
        if (_slotCapabilities?.TokenPresent == false) warnings.Add("No token is present in the selected slot.");
        return warnings;
    }

    private IReadOnlyList<string> GetImportWarnings()
    {
        List<string> warnings = [];
        if (!CanLoadKeys) warnings.Add("Select a device and slot first.");
        if (string.IsNullOrWhiteSpace(_userPin)) warnings.Add("User PIN is required for key-management operations.");
        if (_slotCapabilities?.SupportsAesObjectImport == false) warnings.Add("Import is gated because the selected slot has no token present.");
        return warnings;
    }

    private IReadOnlyList<string> GetRsaWarnings()
    {
        List<string> warnings = [];
        if (!CanLoadKeys) warnings.Add("Select a device and slot first.");
        if (string.IsNullOrWhiteSpace(_userPin)) warnings.Add("User PIN is required for key-management operations.");
        if (_slotCapabilities?.SupportsRsaKeyPairGeneration == false) warnings.Add("Selected slot does not expose CKM_RSA_PKCS_KEY_PAIR_GEN with generate-key-pair support.");
        if (_slotCapabilities?.TokenPresent == false) warnings.Add("No token is present in the selected slot.");
        return warnings;
    }

    private IReadOnlyList<string> GetEditWarnings()
    {
        List<string> warnings = [];
        if (_selectedDetail?.EditCapabilities.CanEditAnyAttributes == false) warnings.Add("The selected object does not currently look modifiable, so SetAttributeValue is likely to fail.");
        if (string.IsNullOrWhiteSpace(_userPin)) warnings.Add("User PIN is required for write operations.");
        return warnings;
    }

    private IReadOnlyList<string> GetCopyWarnings()
    {
        List<string> warnings = [];
        if (string.IsNullOrWhiteSpace(_userPin)) warnings.Add("User PIN is required for write operations.");
        if (_slotCapabilities?.TokenPresent == false) warnings.Add("No token is present in the selected slot.");
        warnings.Add("Some tokens reject copy-time overrides for sensitive or policy-controlled attributes; unchanged fields can be left as 'keep existing'.");
        return warnings;
    }

    private RenderFragment RenderOperationWarnings(IReadOnlyList<string> warnings) => builder =>
    {
        if (warnings.Count == 0) return;
        builder.OpenElement(0, "div");
        builder.AddAttribute(1, "class", "col-12");
        builder.OpenElement(2, "div");
        builder.AddAttribute(3, "class", "alert alert-warning small mb-0");
        builder.OpenElement(4, "ul");
        builder.AddAttribute(5, "class", "mb-0 ps-3");
        foreach (string warning in warnings)
        {
            string capturedWarning = warning;
            builder.AddContent(6, (RenderFragment)(itemBuilder =>
            {
                itemBuilder.OpenElement(0, "li");
                itemBuilder.AddContent(1, capturedWarning);
                itemBuilder.CloseElement();
            }));
        }
        builder.CloseElement();
        builder.CloseElement();
        builder.CloseElement();
    };

    private void SetStatus(string message, bool isError)
    {
        _statusMessage = message;
        _statusIsError = isError;
    }

    private async Task PersistPinAsync(Guid deviceId, nuint slotId)
    {
        if (_rememberPin && !string.IsNullOrWhiteSpace(_userPin))
        {
            await PinStore.SaveAsync(deviceId, slotId, "keys", _userPin);
        }
        else
        {
            await PinStore.DeleteAsync(deviceId, slotId, "keys");
        }
    }

    private static IEnumerable<string> GetFlags(HsmObjectDetail detail)
    {
        if (detail.Token == true) yield return "token";
        if (detail.Private == true) yield return "private";
        if (detail.Modifiable == true) yield return "modifiable";
        if (detail.Sensitive == true) yield return "sensitive";
        if (detail.Extractable == true) yield return "extractable";
        if (detail.CanEncrypt == true) yield return "encrypt";
        if (detail.CanDecrypt == true) yield return "decrypt";
        if (detail.CanSign == true) yield return "sign";
        if (detail.CanVerify == true) yield return "verify";
        if (detail.CanWrap == true) yield return "wrap";
        if (detail.CanUnwrap == true) yield return "unwrap";
        if (detail.CanDerive == true) yield return "derive";
    }

    private static string FormatNullable(nuint? value) => value?.ToString() ?? "n/a";

    private static string CapabilitySummary(HsmKeyObjectSummary key)
    {
        List<string> flags = [];
        if (key.CanEncrypt == true) flags.Add("enc");
        if (key.CanDecrypt == true) flags.Add("dec");
        if (key.CanSign == true) flags.Add("sign");
        if (key.CanVerify == true) flags.Add("verify");
        if (key.CanWrap == true) flags.Add("wrap");
        if (key.CanUnwrap == true) flags.Add("unwrap");
        return flags.Count == 0 ? "n/a" : string.Join(", ", flags);
    }

    private int CountByClass(string normalizedClass)
        => _keys.Count(key => string.Equals(KeyObjectListView.Normalize(key.ObjectClass), normalizedClass, StringComparison.OrdinalIgnoreCase));

    private async Task OnKeyViewChangedAsync()
    {
        bool shouldReload = HasLoadedPage;
        ResetPagedListState();
        if (shouldReload)
        {
            await LoadKeysPageAsync();
        }
    }

    private async Task OnPageSizeChangedAsync()
    {
        bool shouldReload = HasLoadedPage;
        ResetPagedListState();
        if (shouldReload)
        {
            await LoadKeysPageAsync();
        }
    }

    private async Task PreviousPageAsync()
    {
        if (!HasPreviousPage)
        {
            return;
        }

        _currentCursor = _previousPageCursors[^1];
        _previousPageCursors.RemoveAt(_previousPageCursors.Count - 1);
        _pageIndex = Math.Max(1, _pageIndex - 1);
        await LoadKeysPageAsync();
    }

    private async Task NextPageAsync()
    {
        if (!HasNextPage || string.IsNullOrWhiteSpace(_keyPage?.NextCursor))
        {
            return;
        }

        _previousPageCursors.Add(_currentCursor);
        _currentCursor = _keyPage.NextCursor;
        _pageIndex++;
        await LoadKeysPageAsync();
    }

    private void ResetPagedListState()
    {
        _keys = [];
        _keyPage = null;
        _currentCursor = null;
        _previousPageCursors.Clear();
        _pageIndex = 1;
    }

    private static bool TryGetSignPreset(HsmObjectDetail detail, out string? mechanism)
    {
        mechanism = detail.CanSign == true && string.Equals(detail.KeyType, "RSA", StringComparison.OrdinalIgnoreCase)
            ? "0x1"
            : null;
        return mechanism is not null;
    }

    private static bool TryGetVerifyPreset(HsmObjectDetail detail, out string? mechanism)
    {
        mechanism = detail.CanVerify == true && string.Equals(detail.KeyType, "RSA", StringComparison.OrdinalIgnoreCase)
            ? "0x1"
            : null;
        return mechanism is not null;
    }

    private static bool TryGetEncryptPreset(HsmObjectDetail detail, out string? mechanism)
    {
        mechanism = detail.CanEncrypt == true
            ? detail.KeyType switch
            {
                "RSA" => "0x1",
                "AES" => "0x1081",
                _ => null
            }
            : null;
        return mechanism is not null;
    }

    private static bool TryGetEncryptOaepPreset(HsmObjectDetail detail, out string? mechanism)
    {
        mechanism = detail.CanEncrypt == true && string.Equals(detail.KeyType, "RSA", StringComparison.OrdinalIgnoreCase)
            ? "0x9"
            : null;
        return mechanism is not null;
    }

    private static bool TryGetDecryptPreset(HsmObjectDetail detail, out string? mechanism)
    {
        mechanism = detail.CanDecrypt == true
            ? detail.KeyType switch
            {
                "RSA" => "0x1",
                "AES" => "0x1081",
                _ => null
            }
            : null;
        return mechanism is not null;
    }

    private static bool TryGetDecryptOaepPreset(HsmObjectDetail detail, out string? mechanism)
    {
        mechanism = detail.CanDecrypt == true && string.Equals(detail.KeyType, "RSA", StringComparison.OrdinalIgnoreCase)
            ? "0x9"
            : null;
        return mechanism is not null;
    }

    private static bool TryGetSignPssPreset(HsmObjectDetail detail, out string? mechanism)
    {
        mechanism = detail.CanSign == true && string.Equals(detail.KeyType, "RSA", StringComparison.OrdinalIgnoreCase)
            ? "0x43"
            : null;
        return mechanism is not null;
    }

    private static bool TryGetVerifyPssPreset(HsmObjectDetail detail, out string? mechanism)
    {
        mechanism = detail.CanVerify == true && string.Equals(detail.KeyType, "RSA", StringComparison.OrdinalIgnoreCase)
            ? "0x43"
            : null;
        return mechanism is not null;
    }

    private static bool TryGetWrapPreset(HsmObjectDetail detail, out string? mechanism)
    {
        mechanism = detail.CanWrap == true && string.Equals(detail.KeyType, "AES", StringComparison.OrdinalIgnoreCase)
            ? "0x2109"
            : null;
        return mechanism is not null;
    }

    private static bool TryGetUnwrapPreset(HsmObjectDetail detail, out string? mechanism)
    {
        mechanism = detail.CanUnwrap == true && string.Equals(detail.KeyType, "AES", StringComparison.OrdinalIgnoreCase)
            ? "0x2109"
            : null;
        return mechanism is not null;
    }

    private static string BuildLabUri(
        Guid deviceId,
        nuint slotId,
        Pkcs11LabOperation operation,
        nuint? primaryHandle = null,
        string? primaryLabel = null,
        string? primaryIdHex = null,
        string? primaryObjectClass = null,
        string? primaryKeyType = null,
        string? mechanism = null,
        nuint? secondaryHandle = null,
        string? secondaryLabel = null,
        string? secondaryIdHex = null,
        string? secondaryObjectClass = null,
        string? secondaryKeyType = null,
        string? attributeType = null,
        Pkcs11LabMechanismParameterProfile? parameterProfile = null,
        Pkcs11LabRsaHashProfile? rsaHashProfile = null,
        int? pssSaltLength = null)
    {
        List<string> query =
        [
            $"device={Uri.EscapeDataString(deviceId.ToString())}",
            $"slot={Uri.EscapeDataString(slotId.ToString())}",
            $"op={Uri.EscapeDataString(operation.ToString())}"
        ];

        AddLocatorQuery(query, string.Empty, primaryHandle, primaryLabel, primaryIdHex, primaryObjectClass, primaryKeyType);
        AddLocatorQuery(query, "wrap", secondaryHandle, secondaryLabel, secondaryIdHex, secondaryObjectClass, secondaryKeyType);

        if (!string.IsNullOrWhiteSpace(mechanism))
        {
            query.Add($"mechanism={Uri.EscapeDataString(mechanism)}");
        }

        if (!string.IsNullOrWhiteSpace(attributeType))
        {
            query.Add($"attr={Uri.EscapeDataString(attributeType)}");
        }

        if (parameterProfile is not null)
        {
            query.Add($"profile={Uri.EscapeDataString(parameterProfile.Value.ToString())}");
        }

        if (rsaHashProfile is not null)
        {
            query.Add($"rsaHash={Uri.EscapeDataString(rsaHashProfile.Value.ToString())}");
        }

        if (pssSaltLength is not null)
        {
            query.Add($"pssSalt={pssSaltLength.Value}");
        }

        return $"/lab?{string.Join("&", query)}";
    }

    private static void AddLocatorQuery(List<string> query, string prefix, nuint? handle, string? label, string? idHex, string? objectClass, string? keyType)
    {
        string handleKey = string.IsNullOrEmpty(prefix) ? "handle" : $"{prefix}Handle";
        string labelKey = string.IsNullOrEmpty(prefix) ? "label" : $"{prefix}Label";
        string idKey = string.IsNullOrEmpty(prefix) ? "id" : $"{prefix}Id";
        string classKey = string.IsNullOrEmpty(prefix) ? "class" : $"{prefix}Class";
        string keyTypeKey = string.IsNullOrEmpty(prefix) ? "keyType" : $"{prefix}KeyType";

        if (handle is not null)
        {
            query.Add($"{handleKey}={handle.Value}");
        }

        if (!string.IsNullOrWhiteSpace(label))
        {
            query.Add($"{labelKey}={Uri.EscapeDataString(label)}");
        }

        if (!string.IsNullOrWhiteSpace(idHex))
        {
            query.Add($"{idKey}={Uri.EscapeDataString(idHex)}");
        }

        if (!string.IsNullOrWhiteSpace(objectClass))
        {
            query.Add($"{classKey}={Uri.EscapeDataString(objectClass)}");
        }

        if (!string.IsNullOrWhiteSpace(keyType))
        {
            query.Add($"{keyTypeKey}={Uri.EscapeDataString(keyType)}");
        }
    }

    private RenderFragment CapabilityCheckbox(Func<bool> getValue, Action<bool> setValue, string label) => builder =>
    {
        builder.OpenElement(0, "div");
        builder.AddAttribute(1, "class", "form-check");
        builder.OpenElement(2, "input");
        builder.AddAttribute(3, "class", "form-check-input");
        builder.AddAttribute(4, "type", "checkbox");
        builder.AddAttribute(5, "checked", getValue());
        builder.AddAttribute(6, "onchange", EventCallback.Factory.CreateBinder<bool>(this, setValue, getValue()));
        builder.CloseElement();
        builder.OpenElement(7, "label");
        builder.AddAttribute(8, "class", "form-check-label");
        builder.AddContent(9, label);
        builder.CloseElement();
        builder.CloseElement();
    };

    private RenderFragment NullableCheckbox(Func<bool?> getValue, Action<bool?> setValue, string label, bool enabled) => builder =>
    {
        bool current = getValue() == true;
        builder.OpenElement(0, "div");
        builder.AddAttribute(1, "class", "form-check form-switch");
        builder.OpenElement(2, "input");
        builder.AddAttribute(3, "class", "form-check-input");
        builder.AddAttribute(4, "type", "checkbox");
        builder.AddAttribute(5, "checked", current);
        builder.AddAttribute(6, "disabled", !enabled);
        builder.AddAttribute(7, "onchange", EventCallback.Factory.CreateBinder<bool>(this, value => setValue(value), current));
        builder.CloseElement();
        builder.OpenElement(8, "label");
        builder.AddAttribute(9, "class", "form-check-label");
        builder.AddContent(10, !enabled ? $"{label} (unsupported here)" : getValue() is null ? $"{label} (keep existing)" : label);
        builder.CloseElement();
        builder.CloseElement();
    };
}
