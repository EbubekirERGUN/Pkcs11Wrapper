namespace Pkcs11Wrapper.Admin.Application.Models;

public sealed record DeviceDependencyCleanupSummary(
    int InvalidatedTrackedSessions,
    int RemovedProtectedPinEntries,
    int RemovedLabTemplates)
{
    public bool HasChanges => InvalidatedTrackedSessions > 0 || RemovedProtectedPinEntries > 0 || RemovedLabTemplates > 0;

    public string ToAuditSuffix()
        => HasChanges
            ? $" Reconciled dependencies: {InvalidatedTrackedSessions} tracked session(s), {RemovedProtectedPinEntries} protected PIN entr{(RemovedProtectedPinEntries == 1 ? "y" : "ies")}, {RemovedLabTemplates} lab template(s)."
            : " No dependent tracked sessions, protected PIN entries, or lab templates required cleanup.";
}
