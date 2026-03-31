namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record DashboardSummary(
    int DeviceCount,
    int EnabledDeviceCount,
    int DisabledDeviceCount,
    int ActiveSessionCount,
    int HealthySessionCount,
    int InvalidatedSessionCount,
    int RecentAuditCount,
    int RecentAuditFailureCount,
    bool AuditIntegrityValid,
    string AuditIntegritySummary);
