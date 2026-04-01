using System.Diagnostics;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper.Native;

public enum Pkcs11OperationTelemetryStatus
{
    Succeeded = 0,
    ReturnedFalse = 1,
    Failed = 2,
}

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
    public bool IsSuccess => Status == Pkcs11OperationTelemetryStatus.Succeeded;
}

public interface IPkcs11OperationTelemetryListener
{
    void OnOperationCompleted(in Pkcs11OperationTelemetryEvent operationEvent);
}

internal readonly ref struct Pkcs11OperationTelemetryScope
{
    private readonly IPkcs11OperationTelemetryListener? _listener;
    private readonly string _operationName;
    private readonly string? _nativeOperationName;
    private readonly nuint? _slotId;
    private readonly nuint? _sessionHandle;
    private readonly nuint? _mechanismType;
    private readonly long _startTimestamp;

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
            exception);

        try
        {
            _listener.OnOperationCompleted(in operationEvent);
        }
        catch
        {
        }
    }
}
