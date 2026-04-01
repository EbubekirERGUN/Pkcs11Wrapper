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
