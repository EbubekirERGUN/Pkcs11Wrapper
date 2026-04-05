namespace Pkcs11Wrapper.CryptoApi.Configuration;

public sealed class CryptoApiRuntimeOptions
{
    public const string SectionName = "CryptoApiRuntime";

    public string? ModulePath { get; set; }

    public string? UserPin { get; set; }

    public int MaxRetainedSessionsPerSlot { get; set; } = 16;

    public int RouteFailureCooldownSeconds { get; set; } = 30;

    public List<CryptoApiRuntimeBackendOptions> Backends { get; set; } = [];

    public List<CryptoApiRuntimeRouteGroupOptions> RouteGroups { get; set; } = [];

    public bool DisableHttpsRedirection { get; set; }
}

public sealed class CryptoApiRuntimeBackendOptions
{
    public string? Name { get; set; }

    public string? ModulePath { get; set; }

    public string? UserPin { get; set; }

    public int? MaxRetainedSessionsPerSlot { get; set; }

    public bool Enabled { get; set; } = true;
}

public sealed class CryptoApiRuntimeRouteGroupOptions
{
    public string? Name { get; set; }

    public string SelectionMode { get; set; } = "priority";

    public List<CryptoApiRuntimeRouteBackendOptions> Backends { get; set; } = [];
}

public sealed class CryptoApiRuntimeRouteBackendOptions
{
    public string? BackendName { get; set; }

    public ulong SlotId { get; set; }

    public int Priority { get; set; }

    public bool Enabled { get; set; } = true;
}
