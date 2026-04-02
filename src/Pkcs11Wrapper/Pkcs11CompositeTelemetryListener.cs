using Pkcs11Wrapper.Native;

namespace Pkcs11Wrapper;

public sealed class Pkcs11CompositeTelemetryListener : IPkcs11OperationTelemetryListener
{
    private readonly IPkcs11OperationTelemetryListener[] _listeners;

    public Pkcs11CompositeTelemetryListener(params IPkcs11OperationTelemetryListener?[] listeners)
    {
        ArgumentNullException.ThrowIfNull(listeners);
        _listeners = listeners.Where(static listener => listener is not null).Cast<IPkcs11OperationTelemetryListener>().ToArray();
    }

    public void OnOperationCompleted(in Pkcs11OperationTelemetryEvent operationEvent)
    {
        for (int i = 0; i < _listeners.Length; i++)
        {
            try
            {
                _listeners[i].OnOperationCompleted(in operationEvent);
            }
            catch
            {
            }
        }
    }
}
