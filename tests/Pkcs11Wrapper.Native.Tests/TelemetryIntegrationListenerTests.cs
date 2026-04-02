using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Pkcs11Wrapper;
using Pkcs11Wrapper.Native;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper.Native.Tests;

public sealed class TelemetryIntegrationListenerTests
{
    [Fact]
    public void LoggerListenerWritesStructuredScopeWithRedactedFields()
    {
        RecordingLogger logger = new();
        Pkcs11LoggerTelemetryListener listener = new(logger);

        listener.OnOperationCompleted(CreateOperationEvent());

        LogEntry entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Information, entry.Level);
        Assert.Contains("PKCS#11 Load (C_GetFunctionList) completed with Succeeded", entry.Message, StringComparison.Ordinal);

        IReadOnlyList<KeyValuePair<string, object?>> scope = Assert.Single(logger.Scopes);
        Assert.Contains(scope, kvp => kvp.Key == "pkcs11.operation.name" && Equals(kvp.Value, "Load"));
        Assert.Contains(scope, kvp => kvp.Key == "pkcs11.native.operation" && Equals(kvp.Value, "C_GetFunctionList"));
        Assert.Contains(scope, kvp => kvp.Key == "pkcs11.return_value" && Equals(kvp.Value, CK_RV.Ok.ToString()));
        Assert.Contains(scope, kvp => kvp.Key == "pkcs11.slot_id" && Equals(kvp.Value, (nuint)7));
        Assert.Contains(scope, kvp => kvp.Key == "pkcs11.mechanism_type" && Equals(kvp.Value, $"0x{Pkcs11MechanismTypes.Sha256.Value:x}"));
        Assert.Contains(scope, kvp => kvp.Key == "pkcs11.field.credential.pin" && Equals(kvp.Value, "set(len=6)"));
        Assert.Contains(scope, kvp => kvp.Key == "pkcs11.field_classification.credential.pin" && Equals(kvp.Value, nameof(Pkcs11TelemetryFieldClassification.Masked)));
    }

    [Fact]
    public void ActivityListenerCreatesTraceableActivityWithTagsAndExceptionEvent()
    {
        using ActivitySource activitySource = new("Pkcs11Wrapper.Tests.Telemetry");
        Activity? stoppedActivity = null;

        using ActivityListener listener = new()
        {
            ShouldListenTo = source => source.Name == activitySource.Name,
            Sample = static (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => stoppedActivity = activity,
        };

        ActivitySource.AddActivityListener(listener);

        Pkcs11ActivityTelemetryListener telemetryListener = new(activitySource);
        telemetryListener.OnOperationCompleted(CreateOperationEvent(
            status: Pkcs11OperationTelemetryStatus.Failed,
            exception: new InvalidOperationException("boom"),
            duration: TimeSpan.FromMilliseconds(12)));

        Assert.NotNull(stoppedActivity);
        Activity activity = stoppedActivity!;
        Assert.Equal("pkcs11.Load", activity.OperationName);
        Assert.Equal(ActivityStatusCode.Error, activity.Status);
        Assert.Equal("boom", activity.StatusDescription);
        Assert.Equal(TimeSpan.FromMilliseconds(12), activity.Duration);
        Assert.Equal("Load", activity.GetTagItem("pkcs11.operation.name"));
        Assert.Equal("C_GetFunctionList", activity.GetTagItem("pkcs11.native.operation"));
        Assert.Equal("Failed", activity.GetTagItem("pkcs11.status"));
        Assert.Equal("set(len=6)", activity.GetTagItem("pkcs11.field.credential.pin"));
        Assert.Equal(nameof(Pkcs11TelemetryFieldClassification.Masked), activity.GetTagItem("pkcs11.field_classification.credential.pin"));

        ActivityEvent exceptionEvent = Assert.Single(activity.Events, evt => evt.Name == "exception");
        Assert.Contains(exceptionEvent.Tags, kvp => kvp.Key == "exception.type" && Equals(kvp.Value, typeof(InvalidOperationException).FullName));
        Assert.Contains(exceptionEvent.Tags, kvp => kvp.Key == "exception.message" && Equals(kvp.Value, "boom"));
    }

    [Fact]
    public void CompositeListenerSwallowsChildFailuresAndFactoryBuildsExpectedShape()
    {
        RecordingForwardingListener recordingListener = new();
        Pkcs11CompositeTelemetryListener composite = new(new ThrowingListener(), recordingListener);

        composite.OnOperationCompleted(CreateOperationEvent());

        Assert.Single(recordingListener.Events);
        Assert.Null(Pkcs11TelemetryListeners.Create());
        Assert.Same(recordingListener, Pkcs11TelemetryListeners.Combine(recordingListener));

        RecordingLogger logger = new();
        using ActivitySource activitySource = new("Pkcs11Wrapper.Tests.Factory");
        IPkcs11OperationTelemetryListener? created = Pkcs11TelemetryListeners.Create(logger, activitySource);
        Assert.IsType<Pkcs11CompositeTelemetryListener>(created);
    }

    private static Pkcs11OperationTelemetryEvent CreateOperationEvent(
        Pkcs11OperationTelemetryStatus status = Pkcs11OperationTelemetryStatus.Succeeded,
        Exception? exception = null,
        TimeSpan? duration = null)
        => new(
            OperationName: "Load",
            NativeOperationName: "C_GetFunctionList",
            Status: status,
            Duration: duration ?? TimeSpan.FromMilliseconds(5),
            ReturnValue: exception is null ? CK_RV.Ok : new CK_RV(0x00000005u),
            SlotId: 7,
            SessionHandle: 11,
            MechanismType: Pkcs11MechanismTypes.Sha256.Value,
            Exception: exception)
        {
            Fields =
            [
                new Pkcs11OperationTelemetryField("credential.pin", Pkcs11TelemetryFieldClassification.Masked, "set(len=6)"),
                new Pkcs11OperationTelemetryField("input", Pkcs11TelemetryFieldClassification.LengthOnly, "len=32"),
            ]
        };

    private sealed class ThrowingListener : IPkcs11OperationTelemetryListener
    {
        public void OnOperationCompleted(in Pkcs11OperationTelemetryEvent operationEvent)
            => throw new InvalidOperationException("listener failure");
    }

    private sealed class RecordingForwardingListener : IPkcs11OperationTelemetryListener
    {
        public List<Pkcs11OperationTelemetryEvent> Events { get; } = [];

        public void OnOperationCompleted(in Pkcs11OperationTelemetryEvent operationEvent)
            => Events.Add(operationEvent);
    }

    private sealed class RecordingLogger : ILogger
    {
        public List<LogEntry> Entries { get; } = [];

        public List<IReadOnlyList<KeyValuePair<string, object?>>> Scopes { get; } = [];

        public IDisposable BeginScope<TState>(TState state) where TState : notnull
        {
            if (state is IReadOnlyList<KeyValuePair<string, object?>> scope)
            {
                Scopes.Add(scope);
            }
            else if (state is IEnumerable<KeyValuePair<string, object?>> enumerable)
            {
                Scopes.Add(enumerable.ToList());
            }
            else
            {
                Scopes.Add([new KeyValuePair<string, object?>("state", state)]);
            }

            return NoopDisposable.Instance;
        }

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => Entries.Add(new LogEntry(logLevel, formatter(state, exception), exception));
    }

    private sealed record LogEntry(LogLevel Level, string Message, Exception? Exception);

    private sealed class NoopDisposable : IDisposable
    {
        public static NoopDisposable Instance { get; } = new();

        public void Dispose()
        {
        }
    }
}
