using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper.Native.Tests;

public sealed class NativeTypeLayoutTests
{
    [Fact]
    public void PhaseZeroInteropTypesAreBlittable()
    {
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_FLAGS>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_BBOOL>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_RV>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_ULONG>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_SLOT_ID>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_SESSION_HANDLE>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_STATE>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_USER_TYPE>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_MECHANISM_TYPE>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_OBJECT_HANDLE>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_MECHANISM>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_RSA_PKCS_MGF_TYPE>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_RSA_PKCS_OAEP_SOURCE_TYPE>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_AES_CTR_PARAMS>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_CCM_PARAMS>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_GCM_PARAMS>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_RSA_PKCS_OAEP_PARAMS>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_RSA_PKCS_PSS_PARAMS>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_EC_KDF_TYPE>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_ECDH1_DERIVE_PARAMS>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_MECHANISM_INFO>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_VERSION>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_INTERFACE>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_INFO>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_SLOT_INFO>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_TOKEN_INFO>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_SESSION_INFO>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_FUNCTION_LIST>());
        Assert.True(Pkcs11NativeTypeValidation.IsBlittable<CK_C_INITIALIZE_ARGS>());
    }

    [Fact]
    public void PlatformSizedTypesMatchPointerSize()
    {
        Assert.Equal(IntPtr.Size, Unsafe.SizeOf<CK_RV>());
        Assert.Equal(IntPtr.Size, Unsafe.SizeOf<CK_ULONG>());
        Assert.Equal(IntPtr.Size, Unsafe.SizeOf<CK_FLAGS>());
        Assert.Equal(IntPtr.Size, Unsafe.SizeOf<CK_SLOT_ID>());
        Assert.Equal(IntPtr.Size, Unsafe.SizeOf<CK_SESSION_HANDLE>());
        Assert.Equal(IntPtr.Size, Unsafe.SizeOf<CK_STATE>());
        Assert.Equal(IntPtr.Size, Unsafe.SizeOf<CK_USER_TYPE>());
        Assert.Equal(IntPtr.Size, Unsafe.SizeOf<CK_MECHANISM_TYPE>());
        Assert.Equal(IntPtr.Size, Unsafe.SizeOf<CK_OBJECT_HANDLE>());
        Assert.Equal(IntPtr.Size, Unsafe.SizeOf<CK_RSA_PKCS_MGF_TYPE>());
        Assert.Equal(IntPtr.Size, Unsafe.SizeOf<CK_RSA_PKCS_OAEP_SOURCE_TYPE>());
        Assert.Equal(IntPtr.Size, Unsafe.SizeOf<CK_EC_KDF_TYPE>());
        Assert.Equal(3 * IntPtr.Size, Unsafe.SizeOf<CK_MECHANISM>());
        Assert.Equal(IntPtr.Size + 16, Unsafe.SizeOf<CK_AES_CTR_PARAMS>());
        Assert.Equal(6 * IntPtr.Size, Unsafe.SizeOf<CK_CCM_PARAMS>());
        Assert.Equal(6 * IntPtr.Size, Unsafe.SizeOf<CK_GCM_PARAMS>());
        Assert.Equal(5 * IntPtr.Size, Unsafe.SizeOf<CK_RSA_PKCS_OAEP_PARAMS>());
        Assert.Equal(3 * IntPtr.Size, Unsafe.SizeOf<CK_RSA_PKCS_PSS_PARAMS>());
        Assert.Equal(5 * IntPtr.Size, Unsafe.SizeOf<CK_ECDH1_DERIVE_PARAMS>());
        Assert.Equal(3 * IntPtr.Size, Unsafe.SizeOf<CK_MECHANISM_INFO>());
        Assert.Equal(6 * IntPtr.Size, Unsafe.SizeOf<CK_C_INITIALIZE_ARGS>());
        Assert.Equal(1, Unsafe.SizeOf<CK_BBOOL>());
    }

    [Fact]
    public void CkMechanismLayoutMatchesPlatformAbi()
    {
        Assert.Equal(0, Marshal.OffsetOf<CK_MECHANISM>(nameof(CK_MECHANISM.Mechanism)).ToInt32());
        Assert.Equal(IntPtr.Size, Marshal.OffsetOf<CK_MECHANISM>(nameof(CK_MECHANISM.Parameter)).ToInt32());
        Assert.Equal(2 * IntPtr.Size, Marshal.OffsetOf<CK_MECHANISM>(nameof(CK_MECHANISM.ParameterLength)).ToInt32());
    }

    [Fact]
    public void CkMechanismInfoLayoutMatchesPlatformAbi()
    {
        Assert.Equal(0, Marshal.OffsetOf<CK_MECHANISM_INFO>(nameof(CK_MECHANISM_INFO.MinKeySize)).ToInt32());
        Assert.Equal(IntPtr.Size, Marshal.OffsetOf<CK_MECHANISM_INFO>(nameof(CK_MECHANISM_INFO.MaxKeySize)).ToInt32());
        Assert.Equal(2 * IntPtr.Size, Marshal.OffsetOf<CK_MECHANISM_INFO>(nameof(CK_MECHANISM_INFO.Flags)).ToInt32());
    }

    [Fact]
    public void CkSessionInfoLayoutMatchesPlatformAbi()
    {
        Assert.Equal(0, Marshal.OffsetOf<CK_SESSION_INFO>(nameof(CK_SESSION_INFO.SlotId)).ToInt32());
        Assert.Equal(IntPtr.Size, Marshal.OffsetOf<CK_SESSION_INFO>(nameof(CK_SESSION_INFO.State)).ToInt32());
        Assert.Equal(2 * IntPtr.Size, Marshal.OffsetOf<CK_SESSION_INFO>(nameof(CK_SESSION_INFO.Flags)).ToInt32());
        Assert.Equal(3 * IntPtr.Size, Marshal.OffsetOf<CK_SESSION_INFO>(nameof(CK_SESSION_INFO.DeviceError)).ToInt32());
        Assert.Equal(4 * IntPtr.Size, Unsafe.SizeOf<CK_SESSION_INFO>());
    }

    [Fact]
    public void CkVersionLayoutMatchesSpecification()
    {
        Assert.Equal(2, Unsafe.SizeOf<CK_VERSION>());
        Assert.Equal(0, Marshal.OffsetOf<CK_VERSION>(nameof(CK_VERSION.Major)).ToInt32());
        Assert.Equal(1, Marshal.OffsetOf<CK_VERSION>(nameof(CK_VERSION.Minor)).ToInt32());
    }

    [Fact]
    public void CkInfoLayoutMatchesPlatformAbi()
    {
        int expectedFlagsOffset = IntPtr.Size == 8 ? 40 : 36;
        int expectedLibraryDescriptionOffset = IntPtr.Size == 8 ? 48 : 40;
        int expectedLibraryVersionOffset = IntPtr.Size == 8 ? 80 : 72;
        int expectedSize = IntPtr.Size == 8 ? 88 : 76;

        Assert.Equal(0, Marshal.OffsetOf<CK_INFO>(nameof(CK_INFO.CryptokiVersion)).ToInt32());
        Assert.Equal(2, Marshal.OffsetOf<CK_INFO>(nameof(CK_INFO.ManufacturerId)).ToInt32());
        Assert.Equal(expectedFlagsOffset, Marshal.OffsetOf<CK_INFO>(nameof(CK_INFO.Flags)).ToInt32());
        Assert.Equal(expectedLibraryDescriptionOffset, Marshal.OffsetOf<CK_INFO>(nameof(CK_INFO.LibraryDescription)).ToInt32());
        Assert.Equal(expectedLibraryVersionOffset, Marshal.OffsetOf<CK_INFO>(nameof(CK_INFO.LibraryVersion)).ToInt32());
        Assert.Equal(expectedSize, Unsafe.SizeOf<CK_INFO>());
    }

    [Fact]
    public void CkSlotInfoLayoutMatchesPlatformAbi()
    {
        int expectedFlagsOffset = 96;
        int expectedHardwareVersionOffset = IntPtr.Size == 8 ? 104 : 100;
        int expectedFirmwareVersionOffset = IntPtr.Size == 8 ? 106 : 102;
        int expectedSize = IntPtr.Size == 8 ? 112 : 104;

        Assert.Equal(0, Marshal.OffsetOf<CK_SLOT_INFO>(nameof(CK_SLOT_INFO.SlotDescription)).ToInt32());
        Assert.Equal(64, Marshal.OffsetOf<CK_SLOT_INFO>(nameof(CK_SLOT_INFO.ManufacturerId)).ToInt32());
        Assert.Equal(expectedFlagsOffset, Marshal.OffsetOf<CK_SLOT_INFO>(nameof(CK_SLOT_INFO.Flags)).ToInt32());
        Assert.Equal(expectedHardwareVersionOffset, Marshal.OffsetOf<CK_SLOT_INFO>(nameof(CK_SLOT_INFO.HardwareVersion)).ToInt32());
        Assert.Equal(expectedFirmwareVersionOffset, Marshal.OffsetOf<CK_SLOT_INFO>(nameof(CK_SLOT_INFO.FirmwareVersion)).ToInt32());
        Assert.Equal(expectedSize, Unsafe.SizeOf<CK_SLOT_INFO>());
    }

    [Fact]
    public void CkTokenInfoLayoutMatchesPlatformAbi()
    {
        int expectedFlagsOffset = 96;
        int pointerSize = IntPtr.Size;
        int expectedHardwareVersionOffset = 96 + (11 * pointerSize);
        int expectedFirmwareVersionOffset = expectedHardwareVersionOffset + 2;
        int expectedUtcTimeOffset = expectedFirmwareVersionOffset + 2;
        int expectedSize = IntPtr.Size == 8 ? 208 : 160;

        Assert.Equal(0, Marshal.OffsetOf<CK_TOKEN_INFO>(nameof(CK_TOKEN_INFO.Label)).ToInt32());
        Assert.Equal(32, Marshal.OffsetOf<CK_TOKEN_INFO>(nameof(CK_TOKEN_INFO.ManufacturerId)).ToInt32());
        Assert.Equal(64, Marshal.OffsetOf<CK_TOKEN_INFO>(nameof(CK_TOKEN_INFO.Model)).ToInt32());
        Assert.Equal(80, Marshal.OffsetOf<CK_TOKEN_INFO>(nameof(CK_TOKEN_INFO.SerialNumber)).ToInt32());
        Assert.Equal(expectedFlagsOffset, Marshal.OffsetOf<CK_TOKEN_INFO>(nameof(CK_TOKEN_INFO.Flags)).ToInt32());
        Assert.Equal(expectedHardwareVersionOffset, Marshal.OffsetOf<CK_TOKEN_INFO>(nameof(CK_TOKEN_INFO.HardwareVersion)).ToInt32());
        Assert.Equal(expectedFirmwareVersionOffset, Marshal.OffsetOf<CK_TOKEN_INFO>(nameof(CK_TOKEN_INFO.FirmwareVersion)).ToInt32());
        Assert.Equal(expectedUtcTimeOffset, Marshal.OffsetOf<CK_TOKEN_INFO>(nameof(CK_TOKEN_INFO.UtcTime)).ToInt32());
        Assert.Equal(expectedSize, Unsafe.SizeOf<CK_TOKEN_INFO>());
    }

    [Fact]
    public void CkInitializeArgsLayoutMatchesPlatformAbi()
    {
        Assert.Equal(0, Marshal.OffsetOf<CK_C_INITIALIZE_ARGS>(nameof(CK_C_INITIALIZE_ARGS.CreateMutex)).ToInt32());
        Assert.Equal(IntPtr.Size, Marshal.OffsetOf<CK_C_INITIALIZE_ARGS>(nameof(CK_C_INITIALIZE_ARGS.DestroyMutex)).ToInt32());
        Assert.Equal(2 * IntPtr.Size, Marshal.OffsetOf<CK_C_INITIALIZE_ARGS>(nameof(CK_C_INITIALIZE_ARGS.LockMutex)).ToInt32());
        Assert.Equal(3 * IntPtr.Size, Marshal.OffsetOf<CK_C_INITIALIZE_ARGS>(nameof(CK_C_INITIALIZE_ARGS.UnlockMutex)).ToInt32());
        Assert.Equal(4 * IntPtr.Size, Marshal.OffsetOf<CK_C_INITIALIZE_ARGS>(nameof(CK_C_INITIALIZE_ARGS.Flags)).ToInt32());
        Assert.Equal(5 * IntPtr.Size, Marshal.OffsetOf<CK_C_INITIALIZE_ARGS>(nameof(CK_C_INITIALIZE_ARGS.Reserved)).ToInt32());
    }

    [Fact]
    public void FunctionListPrefixMatchesExpectedOrder()
    {
        int pointerSize = IntPtr.Size;
        int expectedInitializeOffset = IntPtr.Size == 8 ? 8 : 4;

        Assert.Equal(0, Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.Version)).ToInt32());
        Assert.Equal(expectedInitializeOffset, Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_Initialize)).ToInt32());
        Assert.Equal(expectedInitializeOffset + pointerSize, Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_Finalize)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (2 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_GetInfo)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (3 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_GetFunctionList)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (4 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_GetSlotList)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (5 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_GetSlotInfo)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (6 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_GetTokenInfo)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (7 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_GetMechanismList)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (8 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_GetMechanismInfo)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (9 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_InitToken)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (10 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_InitPIN)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (11 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_SetPIN)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (12 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_OpenSession)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (13 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_CloseSession)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (14 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_CloseAllSessions)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (15 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_GetSessionInfo)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (16 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_GetOperationState)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (17 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_SetOperationState)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (18 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_Login)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (19 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_Logout)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (20 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_CreateObject)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (28 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_FindObjectsFinal)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (29 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_EncryptInit)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (30 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_Encrypt)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (33 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_DecryptInit)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (34 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_Decrypt)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (37 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_DigestInit)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (38 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_Digest)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (41 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_DigestFinal)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (42 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_SignInit)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (43 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_Sign)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (44 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_SignUpdate)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (45 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_SignFinal)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (48 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_VerifyInit)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (49 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_Verify)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (50 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_VerifyUpdate)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (51 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_VerifyFinal)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (58 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_GenerateKey)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (59 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_GenerateKeyPair)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (60 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_WrapKey)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (61 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_UnwrapKey)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (62 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_DeriveKey)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (63 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_SeedRandom)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (64 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_GenerateRandom)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (65 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_GetFunctionStatus)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (66 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_CancelFunction)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (67 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_WaitForSlotEvent)).ToInt32());
    }

    [Fact]
    public void InterfaceAndFunctionList30LayoutMatchesExpectedOrder()
    {
        int pointerSize = IntPtr.Size;
        int expectedInitializeOffset = IntPtr.Size == 8 ? 8 : 4;
        int baseSize = Marshal.SizeOf<CK_FUNCTION_LIST>();

        Assert.Equal(0, Marshal.OffsetOf<CK_INTERFACE>(nameof(CK_INTERFACE.InterfaceName)).ToInt32());
        Assert.Equal(pointerSize, Marshal.OffsetOf<CK_INTERFACE>(nameof(CK_INTERFACE.FunctionList)).ToInt32());
        Assert.Equal(2 * pointerSize, Marshal.OffsetOf<CK_INTERFACE>(nameof(CK_INTERFACE.Flags)).ToInt32());

        Assert.Equal(0, Marshal.OffsetOf<CK_FUNCTION_LIST_3_0>(nameof(CK_FUNCTION_LIST_3_0.Base)).ToInt32());
        Assert.Equal(baseSize, Marshal.OffsetOf<CK_FUNCTION_LIST_3_0>(nameof(CK_FUNCTION_LIST_3_0.C_GetInterfaceList)).ToInt32());
        Assert.Equal(baseSize + pointerSize, Marshal.OffsetOf<CK_FUNCTION_LIST_3_0>(nameof(CK_FUNCTION_LIST_3_0.C_GetInterface)).ToInt32());
        Assert.Equal(baseSize + (2 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST_3_0>(nameof(CK_FUNCTION_LIST_3_0.C_LoginUser)).ToInt32());
        Assert.Equal(baseSize + (3 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST_3_0>(nameof(CK_FUNCTION_LIST_3_0.C_SessionCancel)).ToInt32());
        Assert.Equal(baseSize + (4 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST_3_0>(nameof(CK_FUNCTION_LIST_3_0.C_MessageEncryptInit)).ToInt32());
        Assert.Equal(baseSize + (8 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST_3_0>(nameof(CK_FUNCTION_LIST_3_0.C_MessageEncryptFinal)).ToInt32());
        Assert.Equal(baseSize + (9 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST_3_0>(nameof(CK_FUNCTION_LIST_3_0.C_MessageDecryptInit)).ToInt32());
        Assert.Equal(baseSize + (13 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST_3_0>(nameof(CK_FUNCTION_LIST_3_0.C_MessageDecryptFinal)).ToInt32());
        Assert.Equal(baseSize + (14 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST_3_0>(nameof(CK_FUNCTION_LIST_3_0.C_MessageSignInit)).ToInt32());
        Assert.Equal(baseSize + (18 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST_3_0>(nameof(CK_FUNCTION_LIST_3_0.C_MessageSignFinal)).ToInt32());
        Assert.Equal(baseSize + (19 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST_3_0>(nameof(CK_FUNCTION_LIST_3_0.C_MessageVerifyInit)).ToInt32());
        Assert.Equal(baseSize + (23 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST_3_0>(nameof(CK_FUNCTION_LIST_3_0.C_MessageVerifyFinal)).ToInt32());
        Assert.Equal(expectedInitializeOffset + (67 * pointerSize), Marshal.OffsetOf<CK_FUNCTION_LIST>(nameof(CK_FUNCTION_LIST.C_WaitForSlotEvent)).ToInt32());
    }
}
