using Microsoft.Extensions.Options;
using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;
using Pkcs11Wrapper.Admin.Infrastructure;
using Pkcs11Wrapper.Admin.Web.Security;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class LocalAdminLoginServiceTests
{
    [Fact]
    public async Task AttemptLoginAsyncAuditsFailuresAndLocksOutAfterThreshold()
    {
        await using TestContext context = await TestContext.CreateAsync(maxFailures: 2, lockoutMinutes: 5);

        LocalAdminLoginResult first = await context.Service.AttemptLoginAsync("admin", "wrong-1", "127.0.0.1");
        LocalAdminLoginResult second = await context.Service.AttemptLoginAsync("admin", "wrong-2", "127.0.0.1");
        LocalAdminLoginResult third = await context.Service.AttemptLoginAsync("admin", "BootstrapWillStillBeBlocked", "127.0.0.1");

        Assert.False(first.Success);
        Assert.Equal("invalid", first.RedirectErrorCode);
        Assert.False(second.Success);
        Assert.True(second.IsThrottled);
        Assert.Equal("locked", second.RedirectErrorCode);
        Assert.False(third.Success);
        Assert.True(third.IsThrottled);

        Assert.Equal(["Failure", "Throttled", "Throttled"], context.AuditEntries.Select(entry => entry.Outcome).ToArray());
    }

    [Fact]
    public async Task AttemptLoginAsyncSuccessResetsThrottleAndWritesSuccessAudit()
    {
        await using TestContext context = await TestContext.CreateAsync(maxFailures: 2, lockoutMinutes: 5);
        string bootstrapPassword = context.ReadBootstrapPassword();

        await context.Service.AttemptLoginAsync("admin", "wrong-1", "127.0.0.1");
        LocalAdminLoginResult success = await context.Service.AttemptLoginAsync("admin", bootstrapPassword, "127.0.0.1");
        LocalAdminLoginResult nextFailure = await context.Service.AttemptLoginAsync("admin", "wrong-2", "127.0.0.1");

        Assert.True(success.Success);
        Assert.False(success.IsThrottled);
        Assert.False(nextFailure.IsThrottled);
        Assert.Equal(["Failure", "Success", "Failure"], context.AuditEntries.Select(entry => entry.Outcome).ToArray());
    }

    [Fact]
    public async Task AttemptLoginAsyncRestartResetsInMemoryThrottleState()
    {
        await using TestContext first = await TestContext.CreateAsync(maxFailures: 2, lockoutMinutes: 5);
        Assert.False((await first.Service.AttemptLoginAsync("admin", "wrong-1", "127.0.0.1")).IsThrottled);
        Assert.True((await first.Service.AttemptLoginAsync("admin", "wrong-2", "127.0.0.1")).IsThrottled);

        await using TestContext second = await TestContext.CreateAsync(maxFailures: 2, lockoutMinutes: 5);
        LocalAdminLoginResult afterRestart = await second.Service.AttemptLoginAsync("admin", "wrong-1", "127.0.0.1");
        Assert.False(afterRestart.IsThrottled);
        Assert.Single(second.AuditEntries);
        Assert.Equal("Failure", second.AuditEntries[0].Outcome);
    }

    [Fact]
    public async Task WriteLogoutAsyncAddsAuthenticationAuditEntry()
    {
        await using TestContext context = await TestContext.CreateAsync();

        await context.Service.WriteLogoutAsync("admin");

        AdminAuditLogEntry entry = Assert.Single(context.AuditEntries);
        Assert.Equal("Authentication", entry.Category);
        Assert.Equal("Logout", entry.Action);
        Assert.Equal("Success", entry.Outcome);
    }

    private sealed class TestContext : IAsyncDisposable
    {
        private readonly string _rootPath;

        private TestContext(string rootPath, LocalAdminLoginService service, LocalAdminUserStore store, InMemoryAuditLogStore auditStore)
        {
            _rootPath = rootPath;
            Service = service;
            Store = store;
            AuditStore = auditStore;
        }

        public LocalAdminLoginService Service { get; }

        public LocalAdminUserStore Store { get; }

        public InMemoryAuditLogStore AuditStore { get; }

        public IReadOnlyList<AdminAuditLogEntry> AuditEntries => AuditStore.Entries;

        public static async Task<TestContext> CreateAsync(int maxFailures = 5, int lockoutMinutes = 15)
        {
            string rootPath = Path.Combine(Path.GetTempPath(), "pkcs11wrapper-login-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(rootPath);

            LocalAdminUserStore userStore = new(Options.Create(new AdminStorageOptions { DataRoot = rootPath }));
            await userStore.EnsureSeedDataAsync();
            InMemoryAuditLogStore auditStore = new();
            AuditLogService auditLog = new(auditStore, new AnonymousActorContext());
            LocalAdminLoginThrottleService throttle = new(new LocalAdminLoginThrottleOptions
            {
                MaxFailuresPerKey = maxFailures,
                LockoutDuration = TimeSpan.FromMinutes(lockoutMinutes),
                FailureWindow = TimeSpan.FromMinutes(10)
            });
            LocalAdminLoginService service = new(userStore, auditLog, throttle);
            return new(rootPath, service, userStore, auditStore);
        }

        public string ReadBootstrapPassword()
        {
            string bootstrapPath = Path.Combine(_rootPath, "bootstrap-admin.txt");
            string line = File.ReadAllLines(bootstrapPath).Single(x => x.StartsWith("password:", StringComparison.OrdinalIgnoreCase));
            return line["password:".Length..].Trim();
        }

        public ValueTask DisposeAsync()
        {
            if (Directory.Exists(_rootPath))
            {
                Directory.Delete(_rootPath, recursive: true);
            }

            return ValueTask.CompletedTask;
        }
    }

    private sealed class InMemoryAuditLogStore : IAuditLogStore
    {
        private readonly List<AdminAuditLogEntry> _entries = [];

        public IReadOnlyList<AdminAuditLogEntry> Entries => _entries;

        public Task AppendAsync(AdminAuditLogEntry entry, CancellationToken cancellationToken = default)
        {
            _entries.Add(entry);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AdminAuditLogEntry>> ReadRecentAsync(int take, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<AdminAuditLogEntry>>(_entries.TakeLast(take).Reverse().ToArray());

        public Task<AuditIntegrityStatus> VerifyIntegrityAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new AuditIntegrityStatus(true, _entries.Count, _entries.LastOrDefault()?.Sequence.ToString(), "ok", null));
    }

    private sealed class AnonymousActorContext : IAdminActorContext
    {
        public AdminActorInfo GetCurrent()
            => new("anonymous", "none", false, [], "127.0.0.1", "login-tests", "tests");
    }
}
