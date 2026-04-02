using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Pkcs11Wrapper.Native;

namespace Pkcs11Wrapper;

public static class Pkcs11TelemetryListeners
{
    public static IPkcs11OperationTelemetryListener? Combine(params IPkcs11OperationTelemetryListener?[] listeners)
    {
        ArgumentNullException.ThrowIfNull(listeners);

        IPkcs11OperationTelemetryListener[] materialized = listeners.Where(static listener => listener is not null).Cast<IPkcs11OperationTelemetryListener>().ToArray();
        return materialized.Length switch
        {
            0 => null,
            1 => materialized[0],
            _ => new Pkcs11CompositeTelemetryListener(materialized),
        };
    }

    public static IPkcs11OperationTelemetryListener? Create(
        ILogger? logger = null,
        ActivitySource? activitySource = null,
        Pkcs11LoggerTelemetryOptions? loggerOptions = null,
        Pkcs11ActivityTelemetryOptions? activityOptions = null)
        => Combine(
            logger is null ? null : new Pkcs11LoggerTelemetryListener(logger, loggerOptions),
            activitySource is null ? null : new Pkcs11ActivityTelemetryListener(activitySource, activityOptions));
}
