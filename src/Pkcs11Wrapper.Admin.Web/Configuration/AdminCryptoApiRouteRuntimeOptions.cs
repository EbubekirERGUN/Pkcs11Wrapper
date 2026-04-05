namespace Pkcs11Wrapper.Admin.Web.Configuration;

public sealed class AdminCryptoApiRouteRuntimeOptions
{
    public const string SectionName = "CryptoApiRuntime";

    public string? ModulePath { get; set; }

    public List<AdminCryptoApiRuntimeBackendOptions> Backends { get; set; } = [];

    public List<AdminCryptoApiRuntimeRouteGroupOptions> RouteGroups { get; set; } = [];
}

public sealed class AdminCryptoApiRuntimeBackendOptions
{
    public string? Name { get; set; }

    public bool Enabled { get; set; } = true;
}

public sealed class AdminCryptoApiRuntimeRouteGroupOptions
{
    public string? Name { get; set; }

    public List<AdminCryptoApiRuntimeRouteBackendOptions> Backends { get; set; } = [];
}

public sealed class AdminCryptoApiRuntimeRouteBackendOptions
{
    public string? BackendName { get; set; }

    public ulong SlotId { get; set; }

    public int Priority { get; set; }

    public bool Enabled { get; set; } = true;
}
