using System.Diagnostics;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper.Native;

public enum Pkcs11OperationTelemetryStatus
{
    Succeeded = 0,
    ReturnedFalse = 1,
    Failed = 2,
}

public enum Pkcs11TelemetryFieldClassification
{
    SafeMetadata = 0,
    LengthOnly = 1,
    Masked = 2,
    Hashed = 3,
    NeverLog = 4,
}

public readonly record struct Pkcs11OperationTelemetryField(
    string Name,
    Pkcs11TelemetryFieldClassification Classification,
    string? Value);

public readonly record struct Pkcs11OperationTelemetryEvent(
    string OperationName,
    string? NativeOperationName,
    Pkcs11OperationTelemetryStatus Status,
    TimeSpan Duration,
    CK_RV? ReturnValue,
    nuint? SlotId,
    nuint? SessionHandle,
    nuint? MechanismType,
    Exception? Exception)
{
    public IReadOnlyList<Pkcs11OperationTelemetryField> Fields { get; init; } = Array.Empty<Pkcs11OperationTelemetryField>();

    public bool IsSuccess => Status == Pkcs11OperationTelemetryStatus.Succeeded;
}

public interface IPkcs11OperationTelemetryListener
{
    void OnOperationCompleted(in Pkcs11OperationTelemetryEvent operationEvent);
}

internal ref struct Pkcs11OperationTelemetryScope
{
    private readonly IPkcs11OperationTelemetryListener? _listener;
    private readonly string _operationName;
    private readonly string? _nativeOperationName;
    private readonly nuint? _slotId;
    private readonly nuint? _sessionHandle;
    private readonly nuint? _mechanismType;
    private readonly long _startTimestamp;
    private List<Pkcs11OperationTelemetryField>? _fields;

    public Pkcs11OperationTelemetryScope(
        IPkcs11OperationTelemetryListener? listener,
        string operationName,
        string? nativeOperationName,
        CK_SLOT_ID? slotId = null,
        CK_SESSION_HANDLE? sessionHandle = null,
        CK_MECHANISM_TYPE? mechanismType = null)
    {
        _listener = listener;
        _operationName = operationName;
        _nativeOperationName = nativeOperationName;
        _slotId = slotId?.Value;
        _sessionHandle = sessionHandle?.Value;
        _mechanismType = mechanismType?.Value;
        _startTimestamp = listener is null ? 0 : Stopwatch.GetTimestamp();
        _fields = null;
    }

    public bool IsEnabled => _listener is not null;

    public void AddField(Pkcs11OperationTelemetryField field)
    {
        if (_listener is null)
        {
            return;
        }

        (_fields ??= []).Add(field);
    }

    public void AddFields(IEnumerable<Pkcs11OperationTelemetryField> fields)
    {
        if (_listener is null)
        {
            return;
        }

        _fields ??= [];
        _fields.AddRange(fields);
    }

    public void Succeeded(CK_RV returnValue)
        => Emit(Pkcs11OperationTelemetryStatus.Succeeded, returnValue, null);

    public void ReturnedFalse(CK_RV returnValue)
        => Emit(Pkcs11OperationTelemetryStatus.ReturnedFalse, returnValue, null);

    public void Failed(Exception exception)
        => Emit(
            Pkcs11OperationTelemetryStatus.Failed,
            exception is Pkcs11Exception pkcs11Exception ? pkcs11Exception.Result : null,
            exception);

    private void Emit(Pkcs11OperationTelemetryStatus status, CK_RV? returnValue, Exception? exception)
    {
        if (_listener is null)
        {
            return;
        }

        Pkcs11OperationTelemetryEvent operationEvent = new(
            _operationName,
            _nativeOperationName,
            status,
            Stopwatch.GetElapsedTime(_startTimestamp),
            returnValue,
            _slotId,
            _sessionHandle,
            _mechanismType,
            exception)
        {
            Fields = _fields is { Count: > 0 }
                ? _fields.ToArray()
                : Array.Empty<Pkcs11OperationTelemetryField>()
        };

        try
        {
            _listener.OnOperationCompleted(in operationEvent);
        }
        catch
        {
        }
    }
}
