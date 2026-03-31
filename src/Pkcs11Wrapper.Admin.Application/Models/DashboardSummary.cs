namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record DashboardSummary(
    int DeviceCount,
    int EnabledDeviceCount,
    int ActiveSessionCount,
    int RecentAuditCount);
