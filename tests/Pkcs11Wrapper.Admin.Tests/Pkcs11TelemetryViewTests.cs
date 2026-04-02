using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Web.Components.Pages;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class Pkcs11TelemetryViewTests
{
    [Fact]
    public void ApplyFiltersByDeviceSlotOperationMechanismStatusAndTimeRange()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        AdminPkcs11TelemetryEntry[] items =
        [
            CreateEntry("Primary", "OpenSession", "Succeeded", now.AddMinutes(-40), slotId: 1, mechanismType: null),
            CreateEntry("Primary", "SignData", "Failed", now.AddMinutes(-10), slotId: 2, mechanismType: 0x00000040, returnValue: "CKR_GENERAL_ERROR"),
            CreateEntry("Backup", "SignData", "ReturnedFalse", now.AddDays(-2), slotId: 2, mechanismType: 0x00000040)
        ];

        IReadOnlyList<AdminPkcs11TelemetryEntry> filtered = Pkcs11TelemetryView.Apply(
            items,
            searchText: null,
            deviceFilter: "Primary",
            slotFilter: "2",
            operationFilter: "SignData",
            mechanismFilter: "0x40",
            statusFilter: "failed",
            timeRangeFilter: "24h",
            nowUtc: now);

        AdminPkcs11TelemetryEntry match = Assert.Single(filtered);
        Assert.Equal("Primary", match.DeviceName);
        Assert.Equal("SignData", match.OperationName);
        Assert.Equal("Failed", match.Status);
    }

    [Fact]
    public void ApplySearchesReturnValuesRedactedFieldsAndCorrelationFields()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        AdminPkcs11TelemetryEntry[] items =
        [
            CreateEntry(
                "Primary",
                "Login",
                "Failed",
                now.AddMinutes(-2),
                slotId: 3,
                mechanismType: null,
                returnValue: "CKR_PIN_INCORRECT",
                actor: "alice",
                sessionId: "trace-1",
                fields:
                [
                    new AdminPkcs11TelemetryField("credential.pin", "Masked", "set(len=8)")
                ]),
            CreateEntry("Primary", "OpenSession", "Succeeded", now.AddMinutes(-1), slotId: 3, mechanismType: null)
        ];

        IReadOnlyList<AdminPkcs11TelemetryEntry> byReturnValue = Pkcs11TelemetryView.Apply(items, "pin_incorrect", null, null, null, null, "all", "all", now);
        IReadOnlyList<AdminPkcs11TelemetryEntry> byFieldName = Pkcs11TelemetryView.Apply(items, "credential.pin", null, null, null, null, "all", "all", now);
        IReadOnlyList<AdminPkcs11TelemetryEntry> byActor = Pkcs11TelemetryView.Apply(items, "alice", null, null, null, null, "all", "all", now);
        IReadOnlyList<AdminPkcs11TelemetryEntry> byTrace = Pkcs11TelemetryView.Apply(items, "trace-1", null, null, null, null, "all", "all", now);

        Assert.Single(byReturnValue);
        Assert.Single(byFieldName);
        Assert.Single(byActor);
        Assert.Single(byTrace);
        Assert.Equal("Login", byReturnValue[0].OperationName);
        Assert.Equal("Login", byFieldName[0].OperationName);
        Assert.Equal("Login", byActor[0].OperationName);
        Assert.Equal("Login", byTrace[0].OperationName);
    }

    [Fact]
    public void NonSuccessFilterIncludesReturnedFalseAndFailed()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        AdminPkcs11TelemetryEntry[] items =
        [
            CreateEntry("Primary", "OpenSession", "Succeeded", now.AddMinutes(-3), slotId: 1, mechanismType: null),
            CreateEntry("Primary", "FindObjects", "ReturnedFalse", now.AddMinutes(-2), slotId: 1, mechanismType: null),
            CreateEntry("Primary", "SignData", "Failed", now.AddMinutes(-1), slotId: 1, mechanismType: 0x40)
        ];

        IReadOnlyList<AdminPkcs11TelemetryEntry> filtered = Pkcs11TelemetryView.Apply(items, null, null, null, null, null, "non-success", "all", now);

        Assert.Equal(2, filtered.Count);
        Assert.DoesNotContain(filtered, item => item.Status == "Succeeded");
    }

    [Fact]
    public void BuildAuditHrefUsesSessionIdWhenAvailable()
    {
        string href = Pkcs11TelemetryView.BuildAuditHref(CreateEntry("Primary", "OpenSession", "Succeeded", DateTimeOffset.UtcNow, 1, null, actor: "alice", sessionId: "trace-88", correlationId: "corr-1"));

        Assert.Contains("/audit", href, StringComparison.Ordinal);
        Assert.Contains("trace-88", href, StringComparison.Ordinal);
    }

    private static AdminPkcs11TelemetryEntry CreateEntry(
        string deviceName,
        string operationName,
        string status,
        DateTimeOffset timestampUtc,
        ulong? slotId,
        ulong? mechanismType,
        string? returnValue = null,
        string? actor = null,
        string? sessionId = null,
        string? correlationId = null,
        AdminPkcs11TelemetryField[]? fields = null)
        => new(
            Guid.NewGuid(),
            timestampUtc,
            Guid.NewGuid(),
            deviceName,
            operationName,
            $"C_{operationName}",
            status,
            4.2,
            returnValue,
            slotId,
            99,
            mechanismType,
            status == "Failed" ? "Pkcs11Exception" : null,
            actor,
            actor is null ? null : "cookie",
            sessionId,
            correlationId,
            fields ?? []);
}
