using System.Diagnostics;
using Pkcs11Wrapper.Native;

namespace Pkcs11Wrapper;

public sealed record Pkcs11ActivityTelemetryOptions
{
    public string ActivityNamePrefix { get; init; } = "pkcs11.";

    public ActivityKind Kind { get; init; } = ActivityKind.Internal;

    public bool IncludeFieldsAsTags { get; init; } = true;

    public bool IncludeFieldClassifications { get; init; } = true;

    public bool IncludeExceptionEvent { get; init; } = true;
}

public sealed class Pkcs11ActivityTelemetryListener : IPkcs11OperationTelemetryListener
{
    private readonly ActivitySource _activitySource;
    private readonly Pkcs11ActivityTelemetryOptions _options;

    public Pkcs11ActivityTelemetryListener(ActivitySource activitySource)
        : this(activitySource, options: null)
    {
    }

    public Pkcs11ActivityTelemetryListener(ActivitySource activitySource, Pkcs11ActivityTelemetryOptions? options)
    {
        _activitySource = activitySource ?? throw new ArgumentNullException(nameof(activitySource));
        _options = options ?? new Pkcs11ActivityTelemetryOptions();
    }

    public void OnOperationCompleted(in Pkcs11OperationTelemetryEvent operationEvent)
    {
        Activity? activity = _activitySource.CreateActivity(_options.ActivityNamePrefix + operationEvent.OperationName, _options.Kind);
        if (activity is null)
        {
            return;
        }

        DateTime startTimeUtc = DateTime.UtcNow - operationEvent.Duration;
        DateTime endTimeUtc = startTimeUtc + operationEvent.Duration;

        activity.SetStartTime(startTimeUtc);
        activity.SetTag("pkcs11.operation.name", operationEvent.OperationName);
        activity.SetTag("pkcs11.status", operationEvent.Status.ToString());
        activity.SetTag("pkcs11.duration_ms", operationEvent.Duration.TotalMilliseconds);

        if (!string.IsNullOrWhiteSpace(operationEvent.NativeOperationName))
        {
            activity.SetTag("pkcs11.native.operation", operationEvent.NativeOperationName);
        }

        if (operationEvent.ReturnValue is { } returnValue)
        {
            activity.SetTag("pkcs11.return_value", returnValue.ToString());
        }

        if (operationEvent.SlotId is { } slotId)
        {
            activity.SetTag("pkcs11.slot_id", slotId);
        }

        if (operationEvent.SessionHandle is { } sessionHandle)
        {
            activity.SetTag("pkcs11.session_handle", sessionHandle);
        }

        if (operationEvent.MechanismType is { } mechanismType)
        {
            activity.SetTag("pkcs11.mechanism_type", $"0x{mechanismType:x}");
        }

        if (_options.IncludeFieldsAsTags)
        {
            for (int i = 0; i < operationEvent.Fields.Count; i++)
            {
                Pkcs11OperationTelemetryField field = operationEvent.Fields[i];
                activity.SetTag($"pkcs11.field.{field.Name}", field.Value);

                if (_options.IncludeFieldClassifications)
                {
                    activity.SetTag($"pkcs11.field_classification.{field.Name}", field.Classification.ToString());
                }
            }
        }

        activity.Start();

        if (operationEvent.Status == Pkcs11OperationTelemetryStatus.Succeeded)
        {
            activity.SetStatus(ActivityStatusCode.Ok);
        }
        else if (operationEvent.Status == Pkcs11OperationTelemetryStatus.ReturnedFalse)
        {
            activity.SetStatus(ActivityStatusCode.Error, "returned_false");
        }
        else
        {
            activity.SetStatus(ActivityStatusCode.Error, operationEvent.Exception?.Message ?? operationEvent.ReturnValue?.ToString());
        }

        if (_options.IncludeExceptionEvent && operationEvent.Exception is not null)
        {
            ActivityTagsCollection tags =
            [
                new KeyValuePair<string, object?>("exception.type", operationEvent.Exception.GetType().FullName),
                new KeyValuePair<string, object?>("exception.message", operationEvent.Exception.Message),
            ];

            if (!string.IsNullOrWhiteSpace(operationEvent.Exception.StackTrace))
            {
                tags.Add("exception.stacktrace", operationEvent.Exception.StackTrace);
            }

            activity.AddEvent(new ActivityEvent("exception", endTimeUtc, tags));
        }

        activity.SetEndTime(endTimeUtc);
        activity.Stop();
    }
}
