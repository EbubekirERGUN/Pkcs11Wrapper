using System.Text;
using Pkcs11Wrapper;
using Pkcs11Wrapper.Native;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper.Native.Tests;

[Collection(Pkcs11RuntimeCollection.Name)]
public sealed class TelemetryRegressionTests
{
    [Fact]
    public void ModuleAndSessionOperationsEmitStructuredTelemetry()
    {
        string? modulePath = Environment.GetEnvironmentVariable("PKCS11_MODULE_PATH");
        string? tokenLabel = Environment.GetEnvironmentVariable("PKCS11_TOKEN_LABEL");
        string? userPin = Environment.GetEnvironmentVariable("PKCS11_USER_PIN");

        if (string.IsNullOrWhiteSpace(modulePath) || string.IsNullOrWhiteSpace(tokenLabel) || string.IsNullOrWhiteSpace(userPin))
        {
            return;
        }

        RecordingTelemetryListener listener = new();

        using (Pkcs11Module module = Pkcs11Module.Load(modulePath, listener))
        {
            Assert.Same(listener, module.TelemetryListener);

            module.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));

            Pkcs11SlotId slotId = FindSlotByTokenLabel(module, tokenLabel);
            using Pkcs11Session session = module.OpenSession(slotId);
            session.Login(Pkcs11UserType.User, Encoding.UTF8.GetBytes(userPin));

            byte[] digest = new byte[32];
            bool digested = session.TryDigest(new Pkcs11Mechanism(Pkcs11MechanismTypes.Sha256), "telemetry-payload"u8, digest, out int written);
            Assert.True(digested);
            Assert.Equal(32, written);

            byte[] random = new byte[16];
            session.GenerateRandom(random);
            session.Logout();
        }

        Pkcs11OperationTelemetryEvent[] events = listener.Events.ToArray();
        Assert.Contains(events, e => e.OperationName == nameof(Pkcs11NativeModule.Load) && e.NativeOperationName == "C_GetFunctionList" && e.Status == Pkcs11OperationTelemetryStatus.Succeeded);
        Assert.Contains(events, e => e.OperationName == nameof(Pkcs11NativeModule.Initialize) && e.NativeOperationName == "C_Initialize" && e.Status == Pkcs11OperationTelemetryStatus.Succeeded);
        Assert.Contains(events, e => e.OperationName == nameof(Pkcs11NativeModule.OpenSession) && e.NativeOperationName == "C_OpenSession" && e.SlotId.HasValue && e.Status == Pkcs11OperationTelemetryStatus.Succeeded);
        Assert.Contains(events, e => e.OperationName == nameof(Pkcs11NativeModule.Login) && e.NativeOperationName == "C_Login" && e.SessionHandle.HasValue && e.Status == Pkcs11OperationTelemetryStatus.Succeeded);
        Assert.Contains(events, e => e.OperationName == "C_Digest" && e.NativeOperationName == "C_Digest" && e.SessionHandle.HasValue && e.MechanismType == Pkcs11MechanismTypes.Sha256.Value && e.Status == Pkcs11OperationTelemetryStatus.Succeeded && e.Duration >= TimeSpan.Zero);
        Assert.Contains(events, e => e.OperationName == nameof(Pkcs11NativeModule.GenerateRandom) && e.NativeOperationName == "C_GenerateRandom" && e.SessionHandle.HasValue && e.Status == Pkcs11OperationTelemetryStatus.Succeeded);
        Assert.Contains(events, e => e.OperationName == nameof(Pkcs11NativeModule.CloseSession) && e.NativeOperationName == "C_CloseSession" && e.SessionHandle.HasValue && e.Status == Pkcs11OperationTelemetryStatus.Succeeded);

        Pkcs11OperationTelemetryEvent loginEvent = Assert.Single(events, e => e.OperationName == nameof(Pkcs11NativeModule.Login) && e.NativeOperationName == "C_Login");
        Pkcs11OperationTelemetryField loginPin = Assert.Single(loginEvent.Fields, f => f.Name == "credential.pin");
        Assert.Equal(Pkcs11TelemetryFieldClassification.Masked, loginPin.Classification);
        Assert.Equal($"set(len={Encoding.UTF8.GetByteCount(userPin)})", loginPin.Value);

        Pkcs11OperationTelemetryEvent digestEvent = Assert.Single(events, e => e.OperationName == "C_Digest" && e.NativeOperationName == "C_Digest");
        Assert.Contains(digestEvent.Fields, f => f.Name == "input" && f.Classification == Pkcs11TelemetryFieldClassification.LengthOnly && f.Value == "len=17");
        Assert.Contains(digestEvent.Fields, f => f.Name == "output" && f.Classification == Pkcs11TelemetryFieldClassification.LengthOnly && f.Value == "len=32");

        Pkcs11OperationTelemetryEvent randomEvent = Assert.Single(events, e => e.OperationName == nameof(Pkcs11NativeModule.GenerateRandom) && e.NativeOperationName == "C_GenerateRandom");
        Assert.Contains(randomEvent.Fields, f => f.Name == "random.output" && f.Classification == Pkcs11TelemetryFieldClassification.LengthOnly && f.Value == "len=16");

        Assert.DoesNotContain(events.SelectMany(e => e.Fields), f => (f.Value ?? string.Empty).Contains(userPin, StringComparison.Ordinal));
        Assert.DoesNotContain(events.SelectMany(e => e.Fields), f => (f.Value ?? string.Empty).Contains("telemetry-payload", StringComparison.Ordinal));
    }

    [Fact]
    public void ListenerFailuresDoNotBreakObservedOperations()
    {
        string? modulePath = Environment.GetEnvironmentVariable("PKCS11_MODULE_PATH");
        if (string.IsNullOrWhiteSpace(modulePath))
        {
            return;
        }

        using Pkcs11Module module = Pkcs11Module.Load(modulePath, new ThrowingTelemetryListener());
        module.Initialize(new Pkcs11InitializeOptions(Pkcs11InitializeFlags.UseOperatingSystemLocking));

        CK_VERSION version = module.GetInfo().LibraryVersion;
        Assert.True(version.Major > 0 || version.Minor >= 0);

        module.FinalizeModule();
    }

    private static Pkcs11SlotId FindSlotByTokenLabel(Pkcs11Module module, string tokenLabel)
    {
        int slotCount = module.GetSlotCount(tokenPresentOnly: true);
        Pkcs11SlotId[] slots = new Pkcs11SlotId[slotCount];
        Assert.True(module.TryGetSlots(slots, out int written, tokenPresentOnly: true));
        Assert.Equal(slotCount, written);

        for (int i = 0; i < written; i++)
        {
            if (module.TryGetTokenInfo(slots[i], out Pkcs11TokenInfo tokenInfo) && string.Equals(tokenInfo.Label, tokenLabel, StringComparison.Ordinal))
            {
                return slots[i];
            }
        }

        throw new InvalidOperationException($"Token '{tokenLabel}' was not found in the configured PKCS#11 fixture.");
    }

    private sealed class RecordingTelemetryListener : IPkcs11OperationTelemetryListener
    {
        public List<Pkcs11OperationTelemetryEvent> Events { get; } = [];

        public void OnOperationCompleted(in Pkcs11OperationTelemetryEvent operationEvent)
            => Events.Add(operationEvent);
    }

    private sealed class ThrowingTelemetryListener : IPkcs11OperationTelemetryListener
    {
        public void OnOperationCompleted(in Pkcs11OperationTelemetryEvent operationEvent)
            => throw new InvalidOperationException($"Telemetry listener failure for {operationEvent.OperationName}");
    }
}
