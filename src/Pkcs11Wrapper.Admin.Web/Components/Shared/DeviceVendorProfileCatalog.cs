using Pkcs11Wrapper.Admin.Application.Models;

namespace Pkcs11Wrapper.Admin.Web.Components.Shared;

internal static class DeviceVendorProfileCatalog
{
    public const string VendorNeutralSelectionId = "vendor-neutral";
    public const string CustomSelectionId = "custom";

    public static IReadOnlyList<DeviceVendorProfileDefinition> Profiles { get; } =
    [
        new(
            "thales-luna-standard",
            "Thales Luna / standard PKCS#11",
            "thales",
            "Thales",
            "luna-standard",
            "Luna / standard PKCS#11",
            "Use this when the admin host already has the Luna client/runtime installed and you want vendor-aware reminders while staying inside the repo's current standard PKCS#11 scope.",
            [
                new DeviceVendorHint(
                    "Client/runtime must already exist on this host",
                    "Point the profile at the exact Luna PKCS#11 library path visible to the running admin host or container. If your environment intentionally uses cklog or ckshim wrappers, point at that wrapper explicitly and validate the underlying Luna client configuration outside the app first.",
                    DeviceVendorHintTone.Info),
                new DeviceVendorHint(
                    "Treat Luna capability differences as runtime reality",
                    "Use the built-in Test action plus Slots/Keys inspection before assuming every standard call, mechanism, or PKCS#11 v3 path is available. Some Luna behavior is token/policy dependent and some v3 paths remain capability-gated or unverified in current repo guidance.",
                    DeviceVendorHintTone.Warning),
                new DeviceVendorHint(
                    "Luna-only CA_* admin flows stay out of scope here",
                    "The admin UI remains focused on standard PKCS#11 device, slot, object, and lab workflows. HA control, cloning, PED/MofN, policy-admin, and other Luna-only extension families are intentionally not implemented on this surface.",
                    DeviceVendorHintTone.Boundary)
            ]),
        new(
            "entrust-nshield-standard",
            "Entrust nShield / standard PKCS#11",
            "entrust",
            "Entrust",
            "nshield-standard",
            "nShield / standard PKCS#11",
            "Use this when a device profile targets the standard PKCS#11 face of an Entrust nShield environment and you want the UI to keep vendor setup caveats visible without introducing vendor-specific operations.",
            [
                new DeviceVendorHint(
                    "Run the admin app where the vendor client/world is already configured",
                    "This UI does not bootstrap Security World or client runtime prerequisites for you. Use the exact module path that the running host/container can resolve and verify vendor prerequisites before relying on the profile operationally.",
                    DeviceVendorHintTone.Info),
                new DeviceVendorHint(
                    "Confirm policy and mechanism exposure with live slot inspection",
                    "Mechanism availability, object policy, and slot behavior can vary with the prepared world/HSM configuration. Use Test, Slots, and Keys pages to confirm what the module actually exposes instead of assuming a generic baseline.",
                    DeviceVendorHintTone.Warning),
                new DeviceVendorHint(
                    "Keep vendor administration outside this UI",
                    "This profile is for standard PKCS#11 interaction only. Vendor-native provisioning, operational control, or lifecycle tooling should remain in vendor-specific operational paths rather than being inferred from the generic admin panel.",
                    DeviceVendorHintTone.Boundary)
            ]),
        new(
            "utimaco-standard",
            "Utimaco / standard PKCS#11",
            "utimaco",
            "Utimaco",
            "standard",
            "Standard PKCS#11",
            "Use this when the profile points at a Utimaco PKCS#11 module and you want the admin UI to keep standard-vs-vendor boundaries explicit while still guiding operators toward the right validation steps.",
            [
                new DeviceVendorHint(
                    "Module path + runtime prerequisites are explicit",
                    "The admin panel only uses the module path you configure. Make sure the vendor runtime, libraries, and any required host/container configuration are already present on the same machine that runs this app.",
                    DeviceVendorHintTone.Info),
                new DeviceVendorHint(
                    "Validate token behavior from the live module",
                    "Use connection testing, slot inventory, and the PKCS#11 Lab to confirm token presence, mechanism exposure, and object behavior in the actual environment. Vendor policy differences should be discovered from the runtime rather than assumed from generic docs.",
                    DeviceVendorHintTone.Warning),
                new DeviceVendorHint(
                    "Stay on the vendor-neutral operational surface",
                    "This UI intentionally covers standard PKCS#11 workflows. Vendor-specific appliance or security-administration tasks remain out of scope and should stay in dedicated vendor tooling/processes.",
                    DeviceVendorHintTone.Boundary)
            ]),
        new(
            "aws-cloudhsm-standard",
            "AWS CloudHSM / standard PKCS#11",
            "aws",
            "AWS",
            "cloudhsm-standard",
            "CloudHSM / Client SDK 5",
            "Use this when the profile targets the PKCS#11 library from AWS CloudHSM Client SDK 5 and you want the admin UI to keep the CloudHSM bootstrap/auth/session caveats visible while staying inside standard PKCS#11 flows.",
            [
                new DeviceVendorHint(
                    "Client SDK 5 must already be installed and bootstrapped on this host",
                    "Point the profile at the exact AWS CloudHSM PKCS#11 module path that the running host/container can resolve, and make sure the host already has the Client SDK 5 runtime, cluster certificate, and cluster bootstrap/configuration in place first.",
                    DeviceVendorHintTone.Info),
                new DeviceVendorHint(
                    "CloudHSM uses RW sessions and CU-style login semantics",
                    "AWS documents that SDK 5 rejects read-only C_OpenSession calls and expects C_Login PINs in the form username:password for a crypto user (CU). The admin layer will retry a failed read-only open as read-write for compatibility, but operators should still expect CloudHSM sessions to behave as RW by default.",
                    DeviceVendorHintTone.Warning),
                new DeviceVendorHint(
                    "Cluster/user administration stays outside this UI",
                    "This profile is for standard PKCS#11 device, slot, object, and lab workflows only. Cluster bootstrap, CloudHSM CLI/CMU user management, trust-anchor/TLS bootstrap, and other AWS control-plane operations remain out of scope here.",
                    DeviceVendorHintTone.Boundary)
            ]),
        new(
            "google-cloud-kms-kmsp11",
            "Google Cloud KMS / Cloud HSM via kmsp11",
            "google",
            "Google Cloud",
            "cloud-kms-kmsp11",
            "Cloud KMS / Cloud HSM via kmsp11",
            "Use this when the device profile points at Google's kmsp11 PKCS#11 adapter for Cloud KMS-backed keys. The practical fit is indirect PKCS#11 through Cloud KMS, not a direct network-HSM client SDK.",
            [
                new DeviceVendorHint(
                    "Config + Google auth must already exist on the admin host",
                    "Point the profile at the exact kmsp11 library path visible to the running host/container and make sure the host already has a valid kmsp11 config file plus Google authentication/IAM in place. In the current repo slice, the admin host should provide KMS_PKCS11_CONFIG before starting the app because the wrapper does not yet pass kmsp11 config through C_Initialize pReserved.",
                    DeviceVendorHintTone.Info),
                new DeviceVendorHint(
                    "Expect a narrower PKCS#11 surface than a classic token",
                    "kmsp11 maps Cloud KMS into PKCS#11, so login is optional and any supplied PIN is ignored, but object import/copy/edit, wrap/unwrap, derive, PIN-admin, and several other classic token flows are not available. The current admin UI therefore treats Google support primarily as browse/test/destroy plus wrapper-level integration guidance rather than full generic key-management parity.",
                    DeviceVendorHintTone.Warning),
                new DeviceVendorHint(
                    "Cloud KMS provisioning and policy remain outside this UI",
                    "Key rings, IAM, service accounts, protection-level choices, and broader Cloud KMS lifecycle/control-plane tasks stay in Google Cloud tooling and APIs. This profile only helps the repo/admin surface stay honest when consuming kmsp11 as a PKCS#11 module.",
                    DeviceVendorHintTone.Boundary)
            ])
    ];

    public static DeviceVendorGuidance GetGuidance(HsmDeviceVendorMetadata? vendor)
    {
        if (vendor is null)
        {
            return CreateGenericGuidance();
        }

        DeviceVendorProfileDefinition? knownProfile = Profiles.FirstOrDefault(profile => profile.Matches(vendor));
        return knownProfile is not null
            ? CreateKnownProfileGuidance(knownProfile)
            : CreateCustomVendorGuidance(vendor);
    }

    public static string GetSelectionId(HsmDeviceVendorMetadata? vendor)
    {
        if (vendor is null)
        {
            return VendorNeutralSelectionId;
        }

        DeviceVendorProfileDefinition? knownProfile = Profiles.FirstOrDefault(profile => profile.Matches(vendor));
        return knownProfile?.SelectionId ?? CustomSelectionId;
    }

    public static DeviceVendorProfileDefinition? FindBySelectionId(string? selectionId)
        => Profiles.FirstOrDefault(profile => string.Equals(profile.SelectionId, selectionId, StringComparison.Ordinal));

    private static DeviceVendorGuidance CreateGenericGuidance()
        => new(
            "Vendor-neutral profile",
            null,
            "Use the generic path when you only need an explicit module path plus the normal standard PKCS#11 inventory/test workflows. You can still attach a vendor profile later without changing the rest of the device shape.",
            [
                new DeviceVendorHint(
                    "Treat the module path as host-specific runtime configuration",
                    "The admin app loads exactly the library path you store here. Keep that path accurate for the host/container that runs the panel and use the built-in Test action after changes.",
                    DeviceVendorHintTone.Info),
                new DeviceVendorHint(
                    "Use device notes for environment breadcrumbs",
                    "Record token labels, host-specific wrapper choices, client versions, or operator caveats in the Notes field so the profile remains understandable when someone revisits it later.",
                    DeviceVendorHintTone.Info),
                new DeviceVendorHint(
                    "Vendor-specific operations still belong elsewhere",
                    "This UI focuses on standard PKCS#11 management and diagnostics. If a scenario needs vendor-native control planes or extension APIs, keep that work out of the generic device workflow and document the boundary clearly.",
                    DeviceVendorHintTone.Boundary)
            ],
            IsKnownProfile: false,
            IsVendorNeutral: true);

    private static DeviceVendorGuidance CreateKnownProfileGuidance(DeviceVendorProfileDefinition profile)
        => new(
            profile.VendorName,
            profile.ProfileName ?? profile.DisplayName,
            profile.Summary,
            profile.Hints,
            IsKnownProfile: true,
            IsVendorNeutral: false);

    private static DeviceVendorGuidance CreateCustomVendorGuidance(HsmDeviceVendorMetadata vendor)
    {
        string title = string.IsNullOrWhiteSpace(vendor.VendorName) ? "Custom vendor profile" : vendor.VendorName;
        string? profileName = string.IsNullOrWhiteSpace(vendor.ProfileName) ? null : vendor.ProfileName;

        return new(
            title,
            profileName,
            "This device carries explicit vendor metadata even though it does not match one of the built-in profiles. The admin UI keeps the identity visible and falls back to generic vendor-aware guidance.",
            [
                new DeviceVendorHint(
                    "Keep runtime prerequisites explicit",
                    "Make sure the vendor client/runtime and any host-specific configuration already exist on the machine that runs the admin panel. Store the exact module path that this host resolves.",
                    DeviceVendorHintTone.Info),
                new DeviceVendorHint(
                    "Validate behavior from the real module",
                    "Use Test, Slots, Keys, and the PKCS#11 Lab to confirm what this vendor/module combination actually exposes. Capability differences should come from the live runtime, not assumption.",
                    DeviceVendorHintTone.Warning),
                new DeviceVendorHint(
                    "Use metadata for identity, not for hidden automation",
                    "Vendor metadata is intended to improve operator context and future extensibility. It should not imply that vendor-native operational APIs are available through the current admin surface.",
                    DeviceVendorHintTone.Boundary)
            ],
            IsKnownProfile: false,
            IsVendorNeutral: false);
    }
}

internal sealed record DeviceVendorProfileDefinition(
    string SelectionId,
    string DisplayName,
    string VendorId,
    string VendorName,
    string? ProfileId,
    string? ProfileName,
    string Summary,
    IReadOnlyList<DeviceVendorHint> Hints)
{
    public bool Matches(HsmDeviceVendorMetadata vendor)
        => string.Equals(VendorId, vendor.VendorId, StringComparison.Ordinal)
            && string.Equals(ProfileId, vendor.ProfileId, StringComparison.Ordinal);
}

internal sealed record DeviceVendorGuidance(
    string Title,
    string? ProfileName,
    string Summary,
    IReadOnlyList<DeviceVendorHint> Hints,
    bool IsKnownProfile,
    bool IsVendorNeutral);

internal sealed record DeviceVendorHint(string Title, string Body, DeviceVendorHintTone Tone);

internal enum DeviceVendorHintTone
{
    Info,
    Warning,
    Boundary
}
