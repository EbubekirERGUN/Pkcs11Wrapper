namespace Pkcs11Wrapper.Admin.Tests;

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
internal sealed class HostedWindowsSoftHsmRuntimeFactAttribute : FactAttribute
{
    internal const string SkipReason = "GitHub-hosted Windows SoftHSM runtime coverage is disabled because SoftHSM-for-Windows can still crash native C_Initialize in admin runtime integration paths. Re-enable with WINDOWS_CI_SOFTHSM_RUNTIME_ENABLED=true once hosted Windows is stable enough.";

    public HostedWindowsSoftHsmRuntimeFactAttribute()
    {
        if (HostedWindowsSoftHsmRuntimeGuard.ShouldSkip())
        {
            Skip = SkipReason;
        }
    }
}

internal static class HostedWindowsSoftHsmRuntimeGuard
{
    public static bool ShouldSkip()
        => ShouldSkip(
            OperatingSystem.IsWindows(),
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS"),
            Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT"),
            Environment.GetEnvironmentVariable("WINDOWS_CI_SOFTHSM_RUNTIME_ENABLED"));

    internal static bool ShouldSkip(bool isWindows, string? githubActions, string? runnerEnvironment, string? runtimeEnabled)
        => isWindows
            && IsTrue(githubActions)
            && !string.Equals(runnerEnvironment, "self-hosted", StringComparison.OrdinalIgnoreCase)
            && !IsTrue(runtimeEnabled);

    private static bool IsTrue(string? value)
        => string.Equals(value, "true", StringComparison.OrdinalIgnoreCase);
}
