namespace Pkcs11Wrapper.Admin.Tests;

public sealed class HostedWindowsSoftHsmRuntimeGuardTests
{
    [Theory]
    [InlineData(true, "true", "github-hosted", null, true)]
    [InlineData(true, "true", "github-hosted", "false", true)]
    [InlineData(true, "true", "github-hosted", "true", false)]
    [InlineData(true, "true", "self-hosted", "false", false)]
    [InlineData(true, "false", "github-hosted", "false", false)]
    [InlineData(false, "true", "github-hosted", "false", false)]
    [InlineData(true, null, "github-hosted", "false", false)]
    [InlineData(true, "true", null, "false", true)]
    public void ShouldSkipOnlyForDisabledGitHubHostedWindowsSoftHsmRuntime(bool isWindows, string? githubActions, string? runnerEnvironment, string? runtimeEnabled, bool expected)
    {
        bool shouldSkip = HostedWindowsSoftHsmRuntimeGuard.ShouldSkip(isWindows, githubActions, runnerEnvironment, runtimeEnabled);

        Assert.Equal(expected, shouldSkip);
    }
}
