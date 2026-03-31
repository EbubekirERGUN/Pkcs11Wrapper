using Microsoft.Extensions.Options;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Infrastructure;
using Pkcs11Wrapper.Admin.Web.Lab;

namespace Pkcs11Wrapper.Admin.Tests;

public sealed class Pkcs11LabTemplateStoreTests : IDisposable
{
    private readonly string _rootPath = Path.Combine(Path.GetTempPath(), $"pkcs11wrapper-lab-templates-{Guid.NewGuid():N}");

    [Fact]
    public async Task SaveAsyncStripsUserPinAndPersistsTemplate()
    {
        Pkcs11LabTemplateStore store = CreateStore();
        Pkcs11LabRequest request = new()
        {
            DeviceId = Guid.NewGuid(),
            SlotId = 7,
            Operation = Pkcs11LabOperation.SignData,
            UserPin = "123456",
            MechanismTypeText = "0x40",
            KeyHandleText = "77",
            TextInput = "hello"
        };

        Pkcs11LabSavedTemplate saved = await store.SaveAsync("sign-demo", "demo template", request);
        IReadOnlyList<Pkcs11LabSavedTemplate> all = await store.GetAllAsync();

        Assert.Single(all);
        Assert.Equal(saved.Id, all[0].Id);
        Assert.Equal("sign-demo", all[0].Name);
        Assert.Null(all[0].Request.UserPin);
        Assert.Equal("hello", all[0].Request.TextInput);
    }

    [Fact]
    public async Task SaveAsyncUpdatesExistingTemplateByName()
    {
        Pkcs11LabTemplateStore store = CreateStore();

        Pkcs11LabSavedTemplate first = await store.SaveAsync("crypto-flow", null, new Pkcs11LabRequest
        {
            Operation = Pkcs11LabOperation.SignData,
            MechanismTypeText = "0x40"
        });

        Pkcs11LabSavedTemplate updated = await store.SaveAsync("crypto-flow", "updated", new Pkcs11LabRequest
        {
            Operation = Pkcs11LabOperation.EncryptData,
            MechanismTypeText = "0x1082"
        });

        IReadOnlyList<Pkcs11LabSavedTemplate> all = await store.GetAllAsync();

        Assert.Single(all);
        Assert.Equal(first.Id, updated.Id);
        Assert.Equal(Pkcs11LabOperation.EncryptData, all[0].Request.Operation);
        Assert.Equal("updated", all[0].Notes);
    }

    [Fact]
    public async Task DeleteAsyncRemovesTemplate()
    {
        Pkcs11LabTemplateStore store = CreateStore();
        Pkcs11LabSavedTemplate saved = await store.SaveAsync("temp", null, new Pkcs11LabRequest
        {
            Operation = Pkcs11LabOperation.ModuleInfo
        });

        await store.DeleteAsync(saved.Id);

        Assert.Empty(await store.GetAllAsync());
    }

    public void Dispose()
    {
        if (Directory.Exists(_rootPath))
        {
            Directory.Delete(_rootPath, recursive: true);
        }
    }

    private Pkcs11LabTemplateStore CreateStore()
        => new(Options.Create(new AdminStorageOptions { DataRoot = _rootPath }));
}
