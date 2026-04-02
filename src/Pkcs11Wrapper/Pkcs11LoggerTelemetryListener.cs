using Microsoft.Extensions.Logging;
using Pkcs11Wrapper.Native;

namespace Pkcs11Wrapper;

public sealed record Pkcs11LoggerTelemetryOptions
{
    public LogLevel SuccessLevel { get; init; } = LogLevel.Information;

    public LogLevel ReturnedFalseLevel { get; init; } = LogLevel.Warning;

    public LogLevel FailureLevel { get; init; } = LogLevel.Error;

    public bool IncludeStructuredScope { get; init; } = true;

    public bool IncludeFieldClassifications { get; init; } = true;
}

public sealed class Pkcs11LoggerTelemetryListener : IPkcs11OperationTelemetryListener
{
    private readonly ILogger _logger;
    private readonly Pkcs11LoggerTelemetryOptions _options;

    public Pkcs11LoggerTelemetryListener(ILogger logger)
        : this(logger, options: null)
    {
    }

    public Pkcs11LoggerTelemetryListener(ILogger logger, Pkcs11LoggerTelemetryOptions? options)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _options = options ?? new Pkcs11LoggerTelemetryOptions();
    }

    public void OnOperationCompleted(in Pkcs11OperationTelemetryEvent operationEvent)
    {
        LogLevel level = operationEvent.Status switch
        {
            Pkcs11OperationTelemetryStatus.Succeeded => _options.SuccessLevel,
            Pkcs11OperationTelemetryStatus.ReturnedFalse => _options.ReturnedFalseLevel,
            Pkcs11OperationTelemetryStatus.Failed => _options.FailureLevel,
            _ => _options.FailureLevel,
        };

        if (!_logger.IsEnabled(level))
        {
            return;
        }

        IDisposable? scope = null;
        if (_options.IncludeStructuredScope)
        {
            scope = _logger.BeginScope(Pkcs11TelemetryScopeState.Create(operationEvent, _options.IncludeFieldClassifications));
        }

        try
        {
            _logger.Log(
                level,
                operationEvent.Exception,
                "PKCS#11 {OperationName} ({NativeOperationName}) completed with {Status} in {DurationMs} ms.",
                operationEvent.OperationName,
                operationEvent.NativeOperationName ?? string.Empty,
                operationEvent.Status,
                operationEvent.Duration.TotalMilliseconds);
        }
        finally
        {
            scope?.Dispose();
        }
    }
}

internal static class Pkcs11TelemetryScopeState
{
    public static IReadOnlyList<KeyValuePair<string, object?>> Create(in Pkcs11OperationTelemetryEvent operationEvent, bool includeFieldClassifications)
    {
        List<KeyValuePair<string, object?>> scope =
        [
            new("pkcs11.operation.name", operationEvent.OperationName),
            new("pkcs11.status", operationEvent.Status.ToString()),
            new("pkcs11.duration_ms", operationEvent.Duration.TotalMilliseconds),
        ];

        if (!string.IsNullOrWhiteSpace(operationEvent.NativeOperationName))
        {
            scope.Add(new KeyValuePair<string, object?>("pkcs11.native.operation", operationEvent.NativeOperationName));
        }

        if (operationEvent.ReturnValue is { } returnValue)
        {
            scope.Add(new KeyValuePair<string, object?>("pkcs11.return_value", returnValue.ToString()));
        }

        if (operationEvent.SlotId is { } slotId)
        {
            scope.Add(new KeyValuePair<string, object?>("pkcs11.slot_id", slotId));
        }

        if (operationEvent.SessionHandle is { } sessionHandle)
        {
            scope.Add(new KeyValuePair<string, object?>("pkcs11.session_handle", sessionHandle));
        }

        if (operationEvent.MechanismType is { } mechanismType)
        {
            scope.Add(new KeyValuePair<string, object?>("pkcs11.mechanism_type", $"0x{mechanismType:x}"));
        }

        for (int i = 0; i < operationEvent.Fields.Count; i++)
        {
            Pkcs11OperationTelemetryField field = operationEvent.Fields[i];
            scope.Add(new KeyValuePair<string, object?>($"pkcs11.field.{field.Name}", field.Value));

            if (includeFieldClassifications)
            {
                scope.Add(new KeyValuePair<string, object?>($"pkcs11.field_classification.{field.Name}", field.Classification.ToString()));
            }
        }

        return scope;
    }
}
