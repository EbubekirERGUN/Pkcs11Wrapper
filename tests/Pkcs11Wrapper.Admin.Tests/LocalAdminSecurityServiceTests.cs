using Microsoft.Extensions.Options;
using Pkcs11Wrapper.Admin.Application.Abstractions;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Application.Services;
using Pkcs11Wrapper.Admin.Infrastructure;
using Pkcs11Wrapper.Admin.Web.Security;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class LocalAdminSecurityServiceTests
{
    [Fact]
    public async Task GetSnapshotAsyncSeedsBootstrapAdminAndNotice()
    {
        await using TestContext context = await TestContext.CreateAsync();

        LocalAdminSecuritySnapshot snapshot = await context.Service.GetSnapshotAsync();

        Assert.Contains(snapshot.Users, user => string.Equals(user.Username, "admin", StringComparison.OrdinalIgnoreCase));
        Assert.True(snapshot.BootstrapStatus.NoticeExists);
        Assert.Equal("admin", snapshot.BootstrapStatus.UserName);
        Assert.True(File.Exists(snapshot.BootstrapStatus.NoticePath));
    }

    [Fact]
    public async Task CreateUserAndRotatePasswordAsyncUpdatesCredentials()
    {
        await using TestContext context = await TestContext.CreateAsync();

        await context.Service.CreateUserAsync(new CreateLocalAdminUserRequest
        {
            UserName = "operator1",
            Password = "OperatorPassword!1",
            Roles = [AdminRoles.Viewer, AdminRoles.Operator]
        });

        (bool successBefore, AdminWebUserRecord? userBefore) = await context.Store.ValidateCredentialsAsync("operator1", "OperatorPassword!1");
        Assert.True(successBefore);
        Assert.NotNull(userBefore);

        await context.Service.RotatePasswordAsync(new RotateLocalAdminPasswordRequest
        {
            UserName = "operator1",
            NewPassword = "OperatorPassword!2"
        });

        (bool successOld, _) = await context.Store.ValidateCredentialsAsync("operator1", "OperatorPassword!1");
        (bool successNew, AdminWebUserRecord? userAfter) = await context.Store.ValidateCredentialsAsync("operator1", "OperatorPassword!2");

        Assert.False(successOld);
        Assert.True(successNew);
        Assert.NotNull(userAfter);
        Assert.Contains(AdminRoles.Operator, userAfter.Roles);
    }

    [Fact]
    public async Task UpdateRolesAsyncRejectsSelfRoleChange()
    {
        await using TestContext context = await TestContext.CreateAsync(currentUserName: "admin");

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() => context.Service.UpdateRolesAsync(new UpdateLocalAdminUserRolesRequest
        {
            UserName = "admin",
            Roles = [AdminRoles.Viewer]
        }));

        Assert.Contains("cannot change their own roles", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DeleteUserAsyncRejectsDeletingLastAdmin()
    {
        await using TestContext context = await TestContext.CreateAsync(currentUserName: "security-admin");

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() => context.Service.DeleteUserAsync("admin"));

        Assert.Contains("at least one local admin", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RetireBootstrapNoticeAsyncDeletesBootstrapFile()
    {
        await using TestContext context = await TestContext.CreateAsync();
        LocalAdminSecuritySnapshot before = await context.Service.GetSnapshotAsync();
        Assert.True(before.BootstrapStatus.NoticeExists);

        await context.Service.RetireBootstrapNoticeAsync();

        LocalAdminSecuritySnapshot after = await context.Service.GetSnapshotAsync();
        Assert.False(after.BootstrapStatus.NoticeExists);
        Assert.False(File.Exists(before.BootstrapStatus.NoticePath));
    }

    private sealed class TestContext : IAsyncDisposable
    {
        private TestContext(string rootPath, LocalAdminUserStore store, LocalAdminSecurityService service)
        {
            RootPath = rootPath;
            Store = store;
            Service = service;
        }

        public string RootPath { get; }

        public LocalAdminUserStore Store { get; }

        public LocalAdminSecurityService Service { get; }

        public static async Task<TestContext> CreateAsync(string currentUserName = "security-admin")
        {
            string rootPath = Path.Combine(Path.GetTempPath(), "pkcs11wrapper-admin-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(rootPath);

            LocalAdminUserStore store = new(Options.Create(new AdminStorageOptions { RootPath = rootPath }));
            AuditLogService auditLog = new(new InMemoryAuditLogStore(), new TestActorContext(currentUserName));
            LocalAdminSecurityService service = new(store, auditLog, new AllowAllAuthorizationService(), new TestActorContext(currentUserName));
            await store.EnsureSeedDataAsync();
            return new(rootPath, store, service);
        }

        public ValueTask DisposeAsync()
        {
            if (Directory.Exists(RootPath))
            {
                Directory.Delete(RootPath, recursive: true);
            }

            return ValueTask.CompletedTask;
        }
    }

    private sealed class InMemoryAuditLogStore : IAuditLogStore
    {
        private readonly List<AdminAuditLogEntry> _entries = [];

        public Task AppendAsync(AdminAuditLogEntry entry, CancellationToken cancellationToken = default)
        {
            _entries.Add(entry);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<AdminAuditLogEntry>> ReadRecentAsync(int take, CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<AdminAuditLogEntry>>(_entries.TakeLast(take).Reverse().ToArray());

        public Task<AuditIntegrityStatus> VerifyIntegrityAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(new AuditIntegrityStatus(true, _entries.Count, null, "ok", null));
    }

    private sealed class TestActorContext(string userName) : IAdminActorContext
    {
        public AdminActorInfo GetCurrent()
            => new(userName, "cookie", true, [AdminRoles.Admin], "127.0.0.1", "session-1", "tests");
    }

    private sealed class AllowAllAuthorizationService : IAdminAuthorizationService
    {
        public void DemandAdmin()
        {
        }

        public void DemandOperator()
        {
        }

        public void DemandViewer()
        {
        }
    }
}
