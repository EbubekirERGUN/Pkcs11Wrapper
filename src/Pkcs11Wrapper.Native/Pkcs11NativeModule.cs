using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper.Native;

public sealed unsafe class Pkcs11NativeModule : IDisposable
{
    private const nuint Pkcs11Ecdh1DeriveMechanism = 0x00001050u;
    private const nuint Pkcs11AesCtrMechanism = 0x00001086u;
    private const nuint Pkcs11AesGcmMechanism = 0x00001087u;
    private const nuint Pkcs11AesCcmMechanism = 0x00001088u;
    private const nuint Pkcs11RsaPkcsOaepMechanism = 0x00000009u;
    private const nuint Pkcs11RsaPkcsPssMechanism = 0x0000000du;
    private const nuint Pkcs11Sha1RsaPkcsPssMechanism = 0x0000000eu;
    private const nuint Pkcs11Sha224RsaPkcsPssMechanism = 0x00000047u;
    private const nuint Pkcs11Sha256RsaPkcsPssMechanism = 0x00000043u;
    private const nuint Pkcs11Sha384RsaPkcsPssMechanism = 0x00000044u;
    private const nuint Pkcs11Sha512RsaPkcsPssMechanism = 0x00000045u;
    private readonly nint _handle;
    private readonly CK_FUNCTION_LIST* _functionList;
    private readonly nint _getInterfaceListExport;
    private readonly nint _getInterfaceExport;
    private readonly object _lifecycleSync = new();
    private volatile bool _disposed;
    private volatile bool _isInitialized;
    private volatile IPkcs11OperationTelemetryListener? _telemetryListener;
    private bool _ownsInitialization;

    private Pkcs11NativeModule(
        nint handle,
        CK_FUNCTION_LIST* functionList,
        nint getInterfaceListExport,
        nint getInterfaceExport,
        IPkcs11OperationTelemetryListener? telemetryListener)
    {
        _handle = handle;
        _functionList = functionList;
        _getInterfaceListExport = getInterfaceListExport;
        _getInterfaceExport = getInterfaceExport;
        _telemetryListener = telemetryListener;
    }

    public CK_FUNCTION_LIST* FunctionList
    {
        get
        {
            EnsureNotDisposed();
            return _functionList;
        }
    }

    public CK_VERSION CryptokiVersion => FunctionList->Version;

    public CK_VERSION FunctionListVersion => GetFunctionListVersion();

    public bool IsDisposed => _disposed;

    public bool IsInitialized => _isInitialized;

    public IPkcs11OperationTelemetryListener? TelemetryListener
    {
        get => _telemetryListener;
        set => _telemetryListener = value;
    }

    public static Pkcs11NativeModule Load(string libraryPath) => Load(libraryPath, null);

    public static Pkcs11NativeModule Load(string libraryPath, IPkcs11OperationTelemetryListener? telemetryListener)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(libraryPath);

        nint handle = NativeLibrary.Load(libraryPath);

        try
        {
            Pkcs11OperationTelemetryScope telemetry = new(telemetryListener, nameof(Load), "C_GetFunctionList");
            try
            {
                nint exportAddress = NativeLibrary.GetExport(handle, "C_GetFunctionList");
                delegate* unmanaged[Cdecl]<CK_FUNCTION_LIST**, CK_RV> getFunctionList = (delegate* unmanaged[Cdecl]<CK_FUNCTION_LIST**, CK_RV>)exportAddress;

                CK_FUNCTION_LIST* functionList = null;
                CK_RV result = getFunctionList(&functionList);
                ThrowIfFailed(result, "C_GetFunctionList");

                if (functionList is null)
                {
                    throw new InvalidOperationException("C_GetFunctionList returned a null function list pointer.");
                }

                nint getInterfaceList = 0;
                nint getInterface = 0;

                if (NativeLibrary.TryGetExport(handle, "C_GetInterfaceList", out nint getInterfaceListAddress))
                {
                    getInterfaceList = getInterfaceListAddress;
                }

                if (NativeLibrary.TryGetExport(handle, "C_GetInterface", out nint getInterfaceAddress))
                {
                    getInterface = getInterfaceAddress;
                }

                telemetry.Succeeded(result);
                return new Pkcs11NativeModule(handle, functionList, getInterfaceList, getInterface, telemetryListener);
            }
            catch (Exception ex)
            {
                telemetry.Failed(ex);
                throw;
            }
        }
        catch
        {
            NativeLibrary.Free(handle);
            throw;
        }
    }

    public void Initialize() => Initialize(null);

    public void Initialize(CK_C_INITIALIZE_ARGS* initializeArgs)
    {
        lock (_lifecycleSync)
        {
            Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(Initialize), "C_Initialize");
            try
            {
                EnsureNotDisposed();

                if (_isInitialized)
                {
                    telemetry.Succeeded(CK_RV.Ok);
                    return;
                }

                EnsureFunctionAvailable((void*)FunctionList->C_Initialize, "C_Initialize");

                CK_RV result = FunctionList->C_Initialize(initializeArgs);
                if (result == Pkcs11ReturnValues.CryptokiAlreadyInitialized)
                {
                    _isInitialized = true;
                    _ownsInitialization = false;
                    telemetry.Succeeded(result);
                    return;
                }

                ThrowIfFailed(result, "C_Initialize");
                _isInitialized = true;
                _ownsInitialization = true;
                telemetry.Succeeded(result);
            }
            catch (Exception ex)
            {
                telemetry.Failed(ex);
                throw;
            }
        }
    }

    public void FinalizeModule()
    {
        lock (_lifecycleSync)
        {
            Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(FinalizeModule), "C_Finalize");
            try
            {
                EnsureNotDisposed();

                if (!_isInitialized)
                {
                    telemetry.Succeeded(CK_RV.Ok);
                    return;
                }

                if (_ownsInitialization)
                {
                    InvokeFinalize();
                }

                _isInitialized = false;
                _ownsInitialization = false;
                telemetry.Succeeded(CK_RV.Ok);
            }
            catch (Exception ex)
            {
                telemetry.Failed(ex);
                throw;
            }
        }
    }

    public CK_INFO GetInfo()
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(GetInfo), "C_GetInfo");
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_GetInfo, "C_GetInfo");

            var info = default(CK_INFO);
            CK_RV result = FunctionList->C_GetInfo(&info);
            ThrowIfFailed(result, "C_GetInfo");
            telemetry.Succeeded(result);
            return info;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public CK_VERSION GetFunctionListVersion()
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(GetFunctionListVersion), "C_GetFunctionList");
        try
        {
            EnsureNotDisposed();

            EnsureFunctionAvailable((void*)FunctionList->C_GetFunctionList, "C_GetFunctionList");

            CK_FUNCTION_LIST* functionList = null;
            CK_RV result = FunctionList->C_GetFunctionList(&functionList);
            ThrowIfFailed(result, "C_GetFunctionList");

            if (functionList is null)
            {
                throw new InvalidOperationException("C_GetFunctionList returned a null function list pointer.");
            }

            telemetry.Succeeded(result);
            return functionList->Version;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool SupportsInterfaceDiscovery => _getInterfaceListExport != 0 && _getInterfaceExport != 0;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private Pkcs11OperationTelemetryScope BeginTelemetry(
        string operationName,
        string? nativeOperationName,
        CK_SLOT_ID? slotId = null,
        CK_SESSION_HANDLE? sessionHandle = null,
        CK_MECHANISM_TYPE? mechanismType = null)
        => new(_telemetryListener, operationName, nativeOperationName, slotId, sessionHandle, mechanismType);

    public int GetInterfaceCount()
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(GetInterfaceCount), "C_GetInterfaceList");
        try
        {
            EnsureNotDisposed();

            if (_getInterfaceListExport == 0)
            {
                telemetry.Succeeded(CK_RV.Ok);
                return 0;
            }

            delegate* unmanaged[Cdecl]<CK_INTERFACE*, CK_ULONG*, CK_RV> getInterfaceList = (delegate* unmanaged[Cdecl]<CK_INTERFACE*, CK_ULONG*, CK_RV>)_getInterfaceListExport;

            CK_ULONG count = default;
            CK_RV result = getInterfaceList(null, &count);
            ThrowIfFailed(result, "C_GetInterfaceList");
            telemetry.Succeeded(result);
            return ToInt32Checked(count, "interface count");
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool TryGetInterfaces(Span<CK_INTERFACE> destination, out int written)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(TryGetInterfaces), "C_GetInterfaceList");
        try
        {
            EnsureNotDisposed();

            if (_getInterfaceListExport == 0)
            {
                written = 0;
                telemetry.Succeeded(CK_RV.Ok);
                return true;
            }

            delegate* unmanaged[Cdecl]<CK_INTERFACE*, CK_ULONG*, CK_RV> getInterfaceList = (delegate* unmanaged[Cdecl]<CK_INTERFACE*, CK_ULONG*, CK_RV>)_getInterfaceListExport;

            CK_ULONG count = default;
            CK_RV result = getInterfaceList(null, &count);
            ThrowIfFailed(result, "C_GetInterfaceList");

            int required = ToInt32Checked(count, "interface count");
            if (destination.Length < required)
            {
                written = required;
                telemetry.ReturnedFalse(Pkcs11ReturnValues.BufferTooSmall);
                return false;
            }

            if (required == 0)
            {
                written = 0;
                telemetry.Succeeded(result);
                return true;
            }

            count = (CK_ULONG)(nuint)required;
            fixed (CK_INTERFACE* destinationPointer = destination)
            {
                result = getInterfaceList(destinationPointer, &count);
            }

            if (result == Pkcs11ReturnValues.BufferTooSmall)
            {
                written = ToInt32Checked(count, "interface count");
                telemetry.ReturnedFalse(result);
                return false;
            }

            ThrowIfFailed(result, "C_GetInterfaceList");
            written = ToInt32Checked(count, "interface count");
            telemetry.Succeeded(result);
            return true;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool TryGetInterface(ReadOnlySpan<byte> nameUtf8, CK_VERSION? version, CK_FLAGS flags, out CK_INTERFACE nativeInterface)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(TryGetInterface), "C_GetInterface");
        try
        {
            EnsureNotDisposed();

            if (_getInterfaceExport == 0)
            {
                nativeInterface = default;
                telemetry.ReturnedFalse(Pkcs11ReturnValues.FunctionNotSupported);
                return false;
            }

            delegate* unmanaged[Cdecl]<byte*, CK_VERSION*, CK_INTERFACE**, CK_FLAGS, CK_RV> getInterface = (delegate* unmanaged[Cdecl]<byte*, CK_VERSION*, CK_INTERFACE**, CK_FLAGS, CK_RV>)_getInterfaceExport;

            CK_INTERFACE* interfacePointer = null;
            CK_VERSION requestedVersion = version ?? default;
            CK_VERSION* requestedVersionPointer = version is null ? null : &requestedVersion;

            CK_RV result;
            if (nameUtf8.IsEmpty)
            {
                result = getInterface(null, requestedVersionPointer, &interfacePointer, flags);
            }
            else
            {
                fixed (byte* namePointer = nameUtf8)
                {
                    result = getInterface(namePointer, requestedVersionPointer, &interfacePointer, flags);
                }
            }

            if (result == Pkcs11ReturnValues.FunctionNotSupported)
            {
                nativeInterface = default;
                telemetry.ReturnedFalse(result);
                return false;
            }

            ThrowIfFailed(result, "C_GetInterface");

            if (interfacePointer is null)
            {
                throw new InvalidOperationException("C_GetInterface returned a null interface pointer.");
            }

            nativeInterface = *interfacePointer;
            telemetry.Succeeded(result);
            return true;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public int GetSlotCount(bool tokenPresentOnly)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(GetSlotCount), "C_GetSlotList");
        try
        {
            EnsureInitialized();

            CK_ULONG count = default;
            CK_RV result = GetSlotList(tokenPresentOnly, null, &count);
            ThrowIfFailed(result, "C_GetSlotList");
            telemetry.Succeeded(result);
            return ToInt32Checked(count, "slot count");
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool TryGetSlots(Span<CK_SLOT_ID> destination, out int written, bool tokenPresentOnly)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(TryGetSlots), "C_GetSlotList");
        try
        {
            EnsureInitialized();

            CK_ULONG count = default;
            CK_RV result = GetSlotList(tokenPresentOnly, null, &count);
            ThrowIfFailed(result, "C_GetSlotList");

            int required = ToInt32Checked(count, "slot count");
            if (destination.Length < required)
            {
                written = required;
                telemetry.ReturnedFalse(Pkcs11ReturnValues.BufferTooSmall);
                return false;
            }

            if (required == 0)
            {
                written = 0;
                telemetry.Succeeded(result);
                return true;
            }

            count = (CK_ULONG)(nuint)required;
            fixed (CK_SLOT_ID* destinationPointer = destination)
            {
                result = GetSlotList(tokenPresentOnly, destinationPointer, &count);
            }

            if (result == Pkcs11ReturnValues.BufferTooSmall)
            {
                written = ToInt32Checked(count, "slot count");
                telemetry.ReturnedFalse(result);
                return false;
            }

            ThrowIfFailed(result, "C_GetSlotList");
            written = ToInt32Checked(count, "slot count");
            telemetry.Succeeded(result);
            return true;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public CK_SLOT_INFO GetSlotInfo(CK_SLOT_ID slotId)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(GetSlotInfo), "C_GetSlotInfo", slotId: slotId);
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_GetSlotInfo, "C_GetSlotInfo");

            var slotInfo = default(CK_SLOT_INFO);
            CK_RV result = FunctionList->C_GetSlotInfo(slotId, &slotInfo);
            ThrowIfFailed(result, "C_GetSlotInfo");
            telemetry.Succeeded(result);
            return slotInfo;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool TryGetTokenInfo(CK_SLOT_ID slotId, out CK_TOKEN_INFO tokenInfo)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(TryGetTokenInfo), "C_GetTokenInfo", slotId: slotId);
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_GetTokenInfo, "C_GetTokenInfo");

            CK_TOKEN_INFO nativeTokenInfo = default;
            CK_RV result = FunctionList->C_GetTokenInfo(slotId, &nativeTokenInfo);
            if (result == Pkcs11ReturnValues.TokenNotPresent)
            {
                tokenInfo = default;
                telemetry.ReturnedFalse(result);
                return false;
            }

            ThrowIfFailed(result, "C_GetTokenInfo");
            tokenInfo = nativeTokenInfo;
            telemetry.Succeeded(result);
            return true;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public void InitToken(CK_SLOT_ID slotId, ReadOnlySpan<byte> soPinUtf8, ReadOnlySpan<byte> label)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(InitToken), "C_InitToken", slotId: slotId);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.InitToken(soPinUtf8, label));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_InitToken, "C_InitToken");

            if (label.Length != 32)
            {
                throw new ArgumentException("The PKCS#11 token label must already be blank-padded to exactly 32 bytes.", nameof(label));
            }

            CK_ULONG soPinLength = (CK_ULONG)(nuint)soPinUtf8.Length;
            CK_RV result;

            if (soPinUtf8.IsEmpty)
            {
                fixed (byte* labelPointer = label)
                {
                    result = FunctionList->C_InitToken(slotId, null, soPinLength, labelPointer);
                }
            }
            else
            {
                fixed (byte* soPinPointer = soPinUtf8)
                fixed (byte* labelPointer = label)
                {
                    result = FunctionList->C_InitToken(slotId, soPinPointer, soPinLength, labelPointer);
                }
            }

            ThrowIfFailed(result, "C_InitToken");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public int GetMechanismCount(CK_SLOT_ID slotId)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(GetMechanismCount), "C_GetMechanismList", slotId: slotId);
        try
        {
            EnsureInitialized();

            CK_ULONG count = default;
            CK_RV result = GetMechanismList(slotId, null, &count);
            ThrowIfFailed(result, "C_GetMechanismList");
            telemetry.Succeeded(result);
            return ToInt32Checked(count, "mechanism count");
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool TryGetMechanisms(CK_SLOT_ID slotId, Span<CK_MECHANISM_TYPE> destination, out int written)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(TryGetMechanisms), "C_GetMechanismList", slotId: slotId);
        try
        {
            EnsureInitialized();

            CK_ULONG count = default;
            CK_RV result = GetMechanismList(slotId, null, &count);
            ThrowIfFailed(result, "C_GetMechanismList");

            int required = ToInt32Checked(count, "mechanism count");
            if (destination.Length < required)
            {
                written = required;
                telemetry.ReturnedFalse(Pkcs11ReturnValues.BufferTooSmall);
                return false;
            }

            if (required == 0)
            {
                written = 0;
                telemetry.Succeeded(result);
                return true;
            }

            count = (CK_ULONG)(nuint)required;
            fixed (CK_MECHANISM_TYPE* destinationPointer = destination)
            {
                result = GetMechanismList(slotId, destinationPointer, &count);
            }

            if (result == Pkcs11ReturnValues.BufferTooSmall)
            {
                written = ToInt32Checked(count, "mechanism count");
                telemetry.ReturnedFalse(result);
                return false;
            }

            ThrowIfFailed(result, "C_GetMechanismList");
            written = ToInt32Checked(count, "mechanism count");
            telemetry.Succeeded(result);
            return true;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public CK_MECHANISM_INFO GetMechanismInfo(CK_SLOT_ID slotId, CK_MECHANISM_TYPE mechanismType)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(GetMechanismInfo), "C_GetMechanismInfo", slotId: slotId, mechanismType: mechanismType);
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_GetMechanismInfo, "C_GetMechanismInfo");

            CK_MECHANISM_INFO info = default;
            CK_RV result = FunctionList->C_GetMechanismInfo(slotId, mechanismType, &info);
            ThrowIfFailed(result, "C_GetMechanismInfo");
            telemetry.Succeeded(result);
            return info;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public CK_SESSION_HANDLE OpenSession(CK_SLOT_ID slotId, bool readWrite)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(OpenSession), "C_OpenSession", slotId: slotId);
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_OpenSession, "C_OpenSession");

            CK_SESSION_HANDLE sessionHandle = default;
            nuint flagsValue = Pkcs11SessionFlags.SerialSession;
            if (readWrite)
            {
                flagsValue |= Pkcs11SessionFlags.ReadWriteSession;
            }

            CK_FLAGS flags = new(flagsValue);
            CK_RV result = FunctionList->C_OpenSession(slotId, flags, null, null, &sessionHandle);
            ThrowIfFailed(result, "C_OpenSession");
            telemetry.Succeeded(result);
            return sessionHandle;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public void CloseSession(CK_SESSION_HANDLE sessionHandle)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(CloseSession), "C_CloseSession", sessionHandle: sessionHandle);
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_CloseSession, "C_CloseSession");

            CK_RV result = FunctionList->C_CloseSession(sessionHandle);
            ThrowIfFailed(result, "C_CloseSession");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public void CloseAllSessions(CK_SLOT_ID slotId)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(CloseAllSessions), "C_CloseAllSessions", slotId: slotId);
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_CloseAllSessions, "C_CloseAllSessions");

            CK_RV result = FunctionList->C_CloseAllSessions(slotId);
            ThrowIfFailed(result, "C_CloseAllSessions");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public CK_SESSION_INFO GetSessionInfo(CK_SESSION_HANDLE sessionHandle)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(GetSessionInfo), "C_GetSessionInfo", sessionHandle: sessionHandle);
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_GetSessionInfo, "C_GetSessionInfo");

            CK_SESSION_INFO sessionInfo = default;
            CK_RV result = FunctionList->C_GetSessionInfo(sessionHandle, &sessionInfo);
            ThrowIfFailed(result, "C_GetSessionInfo");
            telemetry.Succeeded(result);
            return sessionInfo;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public void Login(CK_SESSION_HANDLE sessionHandle, CK_USER_TYPE userType, ReadOnlySpan<byte> pinUtf8)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(Login), "C_Login", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.Credentials(userType, pinUtf8));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_Login, "C_Login");

            CK_ULONG pinLength = (CK_ULONG)(nuint)pinUtf8.Length;
            CK_RV result;

            if (pinUtf8.IsEmpty)
            {
                result = FunctionList->C_Login(sessionHandle, userType, null, pinLength);
            }
            else
            {
                fixed (byte* pinPointer = pinUtf8)
                {
                    result = FunctionList->C_Login(sessionHandle, userType, pinPointer, pinLength);
                }
            }

            ThrowIfFailed(result, "C_Login");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public void Logout(CK_SESSION_HANDLE sessionHandle)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(Logout), "C_Logout", sessionHandle: sessionHandle);
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_Logout, "C_Logout");

            CK_RV result = FunctionList->C_Logout(sessionHandle);
            ThrowIfFailed(result, "C_Logout");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public void InitPin(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> pinUtf8)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(InitPin), "C_InitPIN", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.MaskedSecret("credential.pin", pinUtf8));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_InitPIN, "C_InitPIN");

            CK_ULONG pinLength = (CK_ULONG)(nuint)pinUtf8.Length;
            CK_RV result;

            if (pinUtf8.IsEmpty)
            {
                result = FunctionList->C_InitPIN(sessionHandle, null, pinLength);
            }
            else
            {
                fixed (byte* pinPointer = pinUtf8)
                {
                    result = FunctionList->C_InitPIN(sessionHandle, pinPointer, pinLength);
                }
            }

            ThrowIfFailed(result, "C_InitPIN");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public void SetPin(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> oldPinUtf8, ReadOnlySpan<byte> newPinUtf8)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(SetPin), "C_SetPIN", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.PinChange(oldPinUtf8, newPinUtf8));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_SetPIN, "C_SetPIN");

            CK_ULONG oldPinLength = (CK_ULONG)(nuint)oldPinUtf8.Length;
            CK_ULONG newPinLength = (CK_ULONG)(nuint)newPinUtf8.Length;
            CK_RV result;

            if (oldPinUtf8.IsEmpty && newPinUtf8.IsEmpty)
            {
                result = FunctionList->C_SetPIN(sessionHandle, null, oldPinLength, null, newPinLength);
            }
            else if (oldPinUtf8.IsEmpty)
            {
                fixed (byte* newPinPointer = newPinUtf8)
                {
                    result = FunctionList->C_SetPIN(sessionHandle, null, oldPinLength, newPinPointer, newPinLength);
                }
            }
            else if (newPinUtf8.IsEmpty)
            {
                fixed (byte* oldPinPointer = oldPinUtf8)
                {
                    result = FunctionList->C_SetPIN(sessionHandle, oldPinPointer, oldPinLength, null, newPinLength);
                }
            }
            else
            {
                fixed (byte* oldPinPointer = oldPinUtf8)
                fixed (byte* newPinPointer = newPinUtf8)
                {
                    result = FunctionList->C_SetPIN(sessionHandle, oldPinPointer, oldPinLength, newPinPointer, newPinLength);
                }
            }

            ThrowIfFailed(result, "C_SetPIN");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool TryFindObjects(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<CK_ATTRIBUTE> template, Span<CK_OBJECT_HANDLE> destination, out int written, out bool hasMore)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(TryFindObjects), "C_FindObjects", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.Template("searchTemplate", template));
            telemetry.AddField(Pkcs11TelemetryRedaction.Safe("search.destinationCapacity", destination.Length));
        }

        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_FindObjectsInit, "C_FindObjectsInit");
        EnsureFunctionAvailable((void*)FunctionList->C_FindObjects, "C_FindObjects");
        EnsureFunctionAvailable((void*)FunctionList->C_FindObjectsFinal, "C_FindObjectsFinal");

        bool searchInitialized = false;

        try
        {
            fixed (CK_ATTRIBUTE* templatePointer = template)
            {
                CK_RV initResult = FunctionList->C_FindObjectsInit(sessionHandle, templatePointer, (CK_ULONG)(nuint)template.Length);
                ThrowIfFailed(initResult, "C_FindObjectsInit");
            }

            searchInitialized = true;

            CK_ULONG objectCount = (CK_ULONG)(nuint)destination.Length;
            if (destination.IsEmpty)
            {
                objectCount = 0;
                CK_OBJECT_HANDLE ignored = default;
                CK_ULONG extraCount = default;
                CK_RV extraResult = FunctionList->C_FindObjects(sessionHandle, &ignored, 1, &extraCount);
                ThrowIfFailed(extraResult, "C_FindObjects");
                written = 0;
                hasMore = extraCount.Value != 0;
                if (hasMore)
                {
                    telemetry.ReturnedFalse(extraResult);
                }
                else
                {
                    telemetry.Succeeded(extraResult);
                }

                return !hasMore;
            }

            CK_RV result;
            fixed (CK_OBJECT_HANDLE* destinationPointer = destination)
            {
                result = FunctionList->C_FindObjects(sessionHandle, destinationPointer, objectCount, &objectCount);
            }

            ThrowIfFailed(result, "C_FindObjects");
            written = ToInt32Checked(objectCount, "object count");

            if (written < destination.Length)
            {
                hasMore = false;
                telemetry.Succeeded(result);
                return true;
            }

            CK_OBJECT_HANDLE extraObject = default;
            CK_ULONG extraFound = default;
            CK_RV extraFindResult = FunctionList->C_FindObjects(sessionHandle, &extraObject, 1, &extraFound);
            ThrowIfFailed(extraFindResult, "C_FindObjects");

            hasMore = extraFound.Value != 0;
            if (hasMore)
            {
                telemetry.ReturnedFalse(extraFindResult);
            }
            else
            {
                telemetry.Succeeded(extraFindResult);
            }

            return !hasMore;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
        finally
        {
            if (searchInitialized)
            {
                CK_RV finalResult = FunctionList->C_FindObjectsFinal(sessionHandle);
                ThrowIfFailed(finalResult, "C_FindObjectsFinal");
            }
        }
    }

    public Pkcs11NativeAttributeQuery QueryAttributeValue(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE objectHandle, CK_ATTRIBUTE_TYPE attributeType)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(QueryAttributeValue), "C_GetAttributeValue", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.AttributeType("attribute.type", attributeType));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_GetAttributeValue, "C_GetAttributeValue");

            CK_ATTRIBUTE attribute = new()
            {
                Type = attributeType,
                Value = null,
                ValueLength = 0,
            };

            CK_RV result = FunctionList->C_GetAttributeValue(sessionHandle, objectHandle, &attribute, 1);
            ThrowIfAttributeQueryFailed(result, "C_GetAttributeValue");
            telemetry.Succeeded(result);
            return new Pkcs11NativeAttributeQuery(result, (nuint)attribute.ValueLength);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool TryGetAttributeValue(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE objectHandle, CK_ATTRIBUTE_TYPE attributeType, Span<byte> destination, out int written, out Pkcs11NativeAttributeQuery query)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(TryGetAttributeValue), "C_GetAttributeValue", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.AttributeType("attribute.type", attributeType));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("attribute.destination", destination.Length));
        }

        try
        {
            query = QueryAttributeValue(sessionHandle, objectHandle, attributeType);
            if (!query.IsReadable)
            {
                written = 0;
                telemetry.ReturnedFalse(query.Result);
                return false;
            }

            if (query.IsUnavailableInformation)
            {
                written = 0;
                telemetry.ReturnedFalse(query.Result);
                return false;
            }

            int requiredLength = ToInt32Checked(new CK_ULONG(query.Length), "attribute length");
            if (destination.Length < requiredLength)
            {
                written = requiredLength;
                telemetry.ReturnedFalse(Pkcs11ReturnValues.BufferTooSmall);
                return false;
            }

            CK_ATTRIBUTE attribute = new()
            {
                Type = attributeType,
                ValueLength = (CK_ULONG)(nuint)destination.Length,
            };

            CK_RV result;
            if (destination.IsEmpty)
            {
                attribute.Value = null;
                result = FunctionList->C_GetAttributeValue(sessionHandle, objectHandle, &attribute, 1);
            }
            else
            {
                fixed (byte* destinationPointer = destination)
                {
                    attribute.Value = destinationPointer;
                    result = FunctionList->C_GetAttributeValue(sessionHandle, objectHandle, &attribute, 1);
                }
            }

            if (result == Pkcs11ReturnValues.BufferTooSmall)
            {
                written = ToInt32Checked(attribute.ValueLength, "attribute length");
                query = new Pkcs11NativeAttributeQuery(result, (nuint)attribute.ValueLength);
                telemetry.ReturnedFalse(result);
                return false;
            }

            ThrowIfAttributeQueryFailed(result, "C_GetAttributeValue");
            written = ToInt32Checked(attribute.ValueLength, "attribute length");
            query = new Pkcs11NativeAttributeQuery(result, (nuint)attribute.ValueLength);
            telemetry.Succeeded(result);
            return true;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public unsafe Pkcs11NativeAttributeValue[] GetAttributeValues(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE objectHandle, ReadOnlySpan<CK_ATTRIBUTE_TYPE> attributeTypes)
    {
        EnsureInitialized();
        EnsureFunctionAvailable((void*)FunctionList->C_GetAttributeValue, "C_GetAttributeValue");

        if (attributeTypes.IsEmpty)
        {
            return [];
        }

        CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[attributeTypes.Length];
        for (int i = 0; i < attributeTypes.Length; i++)
        {
            template[i] = new CK_ATTRIBUTE
            {
                Type = attributeTypes[i],
                Value = null,
                ValueLength = 0,
            };
        }

        CK_RV queryResult;
        fixed (CK_ATTRIBUTE* templatePointer = template)
        {
            queryResult = FunctionList->C_GetAttributeValue(sessionHandle, objectHandle, templatePointer, (CK_ULONG)(nuint)template.Length);
        }

        ThrowIfBatchedAttributeQueryFailed(queryResult, "C_GetAttributeValue");

        int[] lengths = new int[template.Length];
        int[] offsets = new int[template.Length];
        int totalLength = 0;
        for (int i = 0; i < template.Length; i++)
        {
            if (!IsReadableAttributeLength(template[i].ValueLength))
            {
                continue;
            }

            int length = ToInt32Checked(template[i].ValueLength, "attribute length");
            lengths[i] = length;
            offsets[i] = totalLength;
            totalLength = checked(totalLength + length);
        }

        byte[] buffer = new byte[totalLength];
        CK_ATTRIBUTE[] readTemplate = new CK_ATTRIBUTE[template.Length];
        for (int i = 0; i < template.Length; i++)
        {
            readTemplate[i] = new CK_ATTRIBUTE
            {
                Type = template[i].Type,
                Value = null,
                ValueLength = template[i].ValueLength,
            };
        }

        CK_RV readResult;
        fixed (CK_ATTRIBUTE* templatePointer = readTemplate)
        fixed (byte* bufferPointer = buffer)
        {
            for (int i = 0; i < readTemplate.Length; i++)
            {
                if (!IsReadableAttributeLength(readTemplate[i].ValueLength))
                {
                    continue;
                }

                if (lengths[i] == 0)
                {
                    readTemplate[i].Value = buffer.Length == 0 ? null : bufferPointer;
                    readTemplate[i].ValueLength = 0;
                    continue;
                }

                readTemplate[i].Value = bufferPointer + offsets[i];
                readTemplate[i].ValueLength = (CK_ULONG)(nuint)lengths[i];
            }

            readResult = FunctionList->C_GetAttributeValue(sessionHandle, objectHandle, templatePointer, (CK_ULONG)(nuint)readTemplate.Length);
        }

        ThrowIfBatchedAttributeQueryFailed(readResult, "C_GetAttributeValue");

        Pkcs11NativeAttributeValue[] values = new Pkcs11NativeAttributeValue[readTemplate.Length];
        for (int i = 0; i < readTemplate.Length; i++)
        {
            Pkcs11NativeAttributeQuery valueQuery = CreateBatchedAttributeQuery(queryResult, readResult, template[i].ValueLength, readTemplate[i].ValueLength, lengths[i]);
            byte[]? value = null;
            if (valueQuery.IsReadable)
            {
                int written = ToInt32Checked(readTemplate[i].ValueLength, "attribute length");
                value = new byte[written];
                if (written != 0)
                {
                    Buffer.BlockCopy(buffer, offsets[i], value, 0, written);
                }
            }

            values[i] = new Pkcs11NativeAttributeValue(readTemplate[i].Type, valueQuery, value);
        }

        return values;
    }

    public CK_OBJECT_HANDLE CreateObject(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(CreateObject), "C_CreateObject", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.Template("template", template));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_CreateObject, "C_CreateObject");

            CK_OBJECT_HANDLE objectHandle = default;
            CK_RV result;

            if (template.IsEmpty)
            {
                result = FunctionList->C_CreateObject(sessionHandle, null, 0, &objectHandle);
            }
            else
            {
                fixed (CK_ATTRIBUTE* templatePointer = template)
                {
                    result = FunctionList->C_CreateObject(sessionHandle, templatePointer, (CK_ULONG)(nuint)template.Length, &objectHandle);
                }
            }

            ThrowIfFailed(result, "C_CreateObject");
            telemetry.Succeeded(result);
            return objectHandle;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public CK_OBJECT_HANDLE CopyObject(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE sourceObjectHandle, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(CopyObject), "C_CopyObject", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.Safe("sourceObjectHandle", sourceObjectHandle.Value));
            telemetry.AddFields(Pkcs11TelemetryRedaction.Template("template", template));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_CopyObject, "C_CopyObject");

            CK_OBJECT_HANDLE objectHandle = default;
            CK_RV result;

            if (template.IsEmpty)
            {
                result = FunctionList->C_CopyObject(sessionHandle, sourceObjectHandle, null, 0, &objectHandle);
            }
            else
            {
                fixed (CK_ATTRIBUTE* templatePointer = template)
                {
                    result = FunctionList->C_CopyObject(sessionHandle, sourceObjectHandle, templatePointer, (CK_ULONG)(nuint)template.Length, &objectHandle);
                }
            }

            ThrowIfFailed(result, "C_CopyObject");
            telemetry.Succeeded(result);
            return objectHandle;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public void SetAttributeValue(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE objectHandle, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(SetAttributeValue), "C_SetAttributeValue", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.Safe("objectHandle", objectHandle.Value));
            telemetry.AddFields(Pkcs11TelemetryRedaction.Template("template", template));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_SetAttributeValue, "C_SetAttributeValue");

            CK_RV result;

            if (template.IsEmpty)
            {
                result = FunctionList->C_SetAttributeValue(sessionHandle, objectHandle, null, 0);
            }
            else
            {
                fixed (CK_ATTRIBUTE* templatePointer = template)
                {
                    result = FunctionList->C_SetAttributeValue(sessionHandle, objectHandle, templatePointer, (CK_ULONG)(nuint)template.Length);
                }
            }

            ThrowIfFailed(result, "C_SetAttributeValue");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public void DestroyObject(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE objectHandle)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(DestroyObject), "C_DestroyObject", sessionHandle: sessionHandle);
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_DestroyObject, "C_DestroyObject");

            CK_RV result = FunctionList->C_DestroyObject(sessionHandle, objectHandle);
            ThrowIfFailed(result, "C_DestroyObject");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public CK_OBJECT_HANDLE GenerateKey(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(GenerateKey), "C_GenerateKey", sessionHandle: sessionHandle, mechanismType: mechanismType);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.MechanismParameters(mechanismType, mechanismParameter));
            telemetry.AddFields(Pkcs11TelemetryRedaction.Template("template", template));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_GenerateKey, "C_GenerateKey");

            CK_OBJECT_HANDLE keyHandle = default;
            fixed (byte* mechanismParameterPointer = mechanismParameter)
            {
                CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length, out MarshalledMechanismParameters marshalledMechanismParameters);
                CK_RV result;

                if (template.IsEmpty)
                {
                    result = FunctionList->C_GenerateKey(sessionHandle, &mechanism, null, 0, &keyHandle);
                }
                else
                {
                    fixed (CK_ATTRIBUTE* templatePointer = template)
                    {
                        result = FunctionList->C_GenerateKey(sessionHandle, &mechanism, templatePointer, (CK_ULONG)(nuint)template.Length, &keyHandle);
                    }
                }

                ThrowIfFailed(result, "C_GenerateKey");
                telemetry.Succeeded(result);
            }

            return keyHandle;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public (CK_OBJECT_HANDLE PublicKeyHandle, CK_OBJECT_HANDLE PrivateKeyHandle) GenerateKeyPair(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<CK_ATTRIBUTE> publicKeyTemplate, ReadOnlySpan<CK_ATTRIBUTE> privateKeyTemplate)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(GenerateKeyPair), "C_GenerateKeyPair", sessionHandle: sessionHandle, mechanismType: mechanismType);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.MechanismParameters(mechanismType, mechanismParameter));
            telemetry.AddFields(Pkcs11TelemetryRedaction.Template("publicTemplate", publicKeyTemplate));
            telemetry.AddFields(Pkcs11TelemetryRedaction.Template("privateTemplate", privateKeyTemplate));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_GenerateKeyPair, "C_GenerateKeyPair");

            CK_OBJECT_HANDLE publicKeyHandle = default;
            CK_OBJECT_HANDLE privateKeyHandle = default;
            fixed (byte* mechanismParameterPointer = mechanismParameter)
            {
                CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length, out MarshalledMechanismParameters marshalledMechanismParameters);
                fixed (CK_ATTRIBUTE* publicTemplatePointer = publicKeyTemplate)
                fixed (CK_ATTRIBUTE* privateTemplatePointer = privateKeyTemplate)
                {
                    CK_RV result = FunctionList->C_GenerateKeyPair(
                        sessionHandle,
                        &mechanism,
                        publicKeyTemplate.IsEmpty ? null : publicTemplatePointer,
                        (CK_ULONG)(nuint)publicKeyTemplate.Length,
                        privateKeyTemplate.IsEmpty ? null : privateTemplatePointer,
                        (CK_ULONG)(nuint)privateKeyTemplate.Length,
                        &publicKeyHandle,
                        &privateKeyHandle);

                    ThrowIfFailed(result, "C_GenerateKeyPair");
                    telemetry.Succeeded(result);
                }
            }

            return (publicKeyHandle, privateKeyHandle);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public int GetWrapKeyOutputLength(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE wrappingKeyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, CK_OBJECT_HANDLE keyHandle)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(GetWrapKeyOutputLength), "C_WrapKey", sessionHandle: sessionHandle, mechanismType: mechanismType);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.MechanismParameters(mechanismType, mechanismParameter));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_WrapKey, "C_WrapKey");

            CK_ULONG wrappedKeyLength = default;
            fixed (byte* mechanismParameterPointer = mechanismParameter)
            {
                CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length, out MarshalledMechanismParameters marshalledMechanismParameters);
                CK_RV result = FunctionList->C_WrapKey(sessionHandle, &mechanism, wrappingKeyHandle, keyHandle, null, &wrappedKeyLength);
                ThrowIfFailed(result, "C_WrapKey");
                telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("wrappedKey", ToInt32Checked(wrappedKeyLength, "wrapped key length")));
                telemetry.Succeeded(result);
            }

            return ToInt32Checked(wrappedKeyLength, "wrapped key length");
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool TryWrapKey(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE wrappingKeyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, CK_OBJECT_HANDLE keyHandle, Span<byte> wrappedKey, out int written)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(TryWrapKey), "C_WrapKey", sessionHandle: sessionHandle, mechanismType: mechanismType);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.MechanismParameters(mechanismType, mechanismParameter));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("wrappedKey.destination", wrappedKey.Length));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_WrapKey, "C_WrapKey");

            CK_ULONG wrappedKeyLength = (CK_ULONG)(nuint)wrappedKey.Length;

            fixed (byte* mechanismParameterPointer = mechanismParameter)
            fixed (byte* wrappedKeyPointer = wrappedKey)
            {
                CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length, out MarshalledMechanismParameters marshalledMechanismParameters);
                CK_RV result = FunctionList->C_WrapKey(sessionHandle, &mechanism, wrappingKeyHandle, keyHandle, wrappedKey.IsEmpty ? null : wrappedKeyPointer, &wrappedKeyLength);
                if (result == Pkcs11ReturnValues.BufferTooSmall)
                {
                    written = ToInt32Checked(wrappedKeyLength, "wrapped key length");
                    telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("wrappedKey", written));
                    telemetry.ReturnedFalse(result);
                    return false;
                }

                ThrowIfFailed(result, "C_WrapKey");
                telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("wrappedKey", ToInt32Checked(wrappedKeyLength, "wrapped key length")));
                telemetry.Succeeded(result);
            }

            written = ToInt32Checked(wrappedKeyLength, "wrapped key length");
            return true;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public CK_OBJECT_HANDLE UnwrapKey(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE unwrappingKeyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<byte> wrappedKey, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(UnwrapKey), "C_UnwrapKey", sessionHandle: sessionHandle, mechanismType: mechanismType);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.MechanismParameters(mechanismType, mechanismParameter));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("wrappedKey", wrappedKey));
            telemetry.AddFields(Pkcs11TelemetryRedaction.Template("template", template));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_UnwrapKey, "C_UnwrapKey");

            CK_OBJECT_HANDLE keyHandle = default;
            fixed (byte* mechanismParameterPointer = mechanismParameter)
            fixed (byte* wrappedKeyPointer = wrappedKey)
            fixed (CK_ATTRIBUTE* templatePointer = template)
            {
                CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length, out MarshalledMechanismParameters marshalledMechanismParameters);
                CK_RV result = FunctionList->C_UnwrapKey(
                    sessionHandle,
                    &mechanism,
                    unwrappingKeyHandle,
                    wrappedKey.IsEmpty ? null : wrappedKeyPointer,
                    (CK_ULONG)(nuint)wrappedKey.Length,
                    template.IsEmpty ? null : templatePointer,
                    (CK_ULONG)(nuint)template.Length,
                    &keyHandle);

                ThrowIfFailed(result, "C_UnwrapKey");
                telemetry.Succeeded(result);
            }

            return keyHandle;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public CK_OBJECT_HANDLE DeriveKey(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE baseKeyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(DeriveKey), "C_DeriveKey", sessionHandle: sessionHandle, mechanismType: mechanismType);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.MechanismParameters(mechanismType, mechanismParameter));
            telemetry.AddFields(Pkcs11TelemetryRedaction.Template("template", template));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_DeriveKey, "C_DeriveKey");

            CK_OBJECT_HANDLE keyHandle = default;
            fixed (byte* mechanismParameterPointer = mechanismParameter)
            fixed (CK_ATTRIBUTE* templatePointer = template)
            {
                CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length, out MarshalledMechanismParameters marshalledMechanismParameters);
                CK_RV result = FunctionList->C_DeriveKey(
                    sessionHandle,
                    &mechanism,
                    baseKeyHandle,
                    template.IsEmpty ? null : templatePointer,
                    (CK_ULONG)(nuint)template.Length,
                    &keyHandle);

                ThrowIfFailed(result, "C_DeriveKey");
                telemetry.Succeeded(result);
            }

            return keyHandle;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private static CK_MECHANISM CreateMechanism(CK_MECHANISM_TYPE mechanismType, byte* mechanismParameterPointer, int mechanismParameterLength, out MarshalledMechanismParameters marshalledMechanismParameters)
    {
        marshalledMechanismParameters = default;
        nuint mechanismValue = (nuint)mechanismType.Value;

        if (mechanismValue == Pkcs11Ecdh1DeriveMechanism)
        {
            marshalledMechanismParameters.Ecdh1DeriveParams = CreateEcdh1DeriveParams(mechanismParameterPointer, mechanismParameterLength);
            return new CK_MECHANISM
            {
                Mechanism = mechanismType,
                Parameter = Unsafe.AsPointer(ref marshalledMechanismParameters.Ecdh1DeriveParams),
                ParameterLength = (CK_ULONG)(nuint)sizeof(CK_ECDH1_DERIVE_PARAMS),
            };
        }

        if (mechanismValue == Pkcs11AesCtrMechanism)
        {
            marshalledMechanismParameters.CtrParams = CreateAesCtrParams(mechanismParameterPointer, mechanismParameterLength);
            return new CK_MECHANISM
            {
                Mechanism = mechanismType,
                Parameter = Unsafe.AsPointer(ref marshalledMechanismParameters.CtrParams),
                ParameterLength = (CK_ULONG)(nuint)sizeof(CK_AES_CTR_PARAMS),
            };
        }

        if (mechanismValue == Pkcs11AesGcmMechanism)
        {
            marshalledMechanismParameters.GcmParams = CreateGcmParams(mechanismParameterPointer, mechanismParameterLength);
            return new CK_MECHANISM
            {
                Mechanism = mechanismType,
                Parameter = Unsafe.AsPointer(ref marshalledMechanismParameters.GcmParams),
                ParameterLength = (CK_ULONG)(nuint)sizeof(CK_GCM_PARAMS),
            };
        }

        if (mechanismValue == Pkcs11AesCcmMechanism)
        {
            marshalledMechanismParameters.CcmParams = CreateAesCcmParams(mechanismParameterPointer, mechanismParameterLength);
            return new CK_MECHANISM
            {
                Mechanism = mechanismType,
                Parameter = Unsafe.AsPointer(ref marshalledMechanismParameters.CcmParams),
                ParameterLength = (CK_ULONG)(nuint)sizeof(CK_CCM_PARAMS),
            };
        }

        if (mechanismValue == Pkcs11RsaPkcsOaepMechanism)
        {
            marshalledMechanismParameters.OaepParams = CreateRsaOaepParams(mechanismParameterPointer, mechanismParameterLength);
            return new CK_MECHANISM
            {
                Mechanism = mechanismType,
                Parameter = Unsafe.AsPointer(ref marshalledMechanismParameters.OaepParams),
                ParameterLength = (CK_ULONG)(nuint)sizeof(CK_RSA_PKCS_OAEP_PARAMS),
            };
        }

        if (mechanismValue is Pkcs11RsaPkcsPssMechanism or Pkcs11Sha1RsaPkcsPssMechanism or Pkcs11Sha224RsaPkcsPssMechanism or Pkcs11Sha256RsaPkcsPssMechanism or Pkcs11Sha384RsaPkcsPssMechanism or Pkcs11Sha512RsaPkcsPssMechanism)
        {
            marshalledMechanismParameters.PssParams = CreateRsaPssParams(mechanismParameterPointer, mechanismParameterLength);
            return new CK_MECHANISM
            {
                Mechanism = mechanismType,
                Parameter = Unsafe.AsPointer(ref marshalledMechanismParameters.PssParams),
                ParameterLength = (CK_ULONG)(nuint)sizeof(CK_RSA_PKCS_PSS_PARAMS),
            };
        }

        return CreateRawMechanism(mechanismType, mechanismParameterPointer, mechanismParameterLength);
    }

    public nuint GetObjectSize(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE objectHandle)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(GetObjectSize), "C_GetObjectSize", sessionHandle: sessionHandle);
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_GetObjectSize, "C_GetObjectSize");

            CK_ULONG objectSize = default;
            CK_RV result = FunctionList->C_GetObjectSize(sessionHandle, objectHandle, &objectSize);
            ThrowIfFailed(result, "C_GetObjectSize");
            telemetry.Succeeded(result);
            return (nuint)objectSize;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public int GetEncryptOutputLength(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<byte> plaintext)
        => GetSinglePartOutputLength(
            sessionHandle,
            keyHandle,
            mechanismType,
            mechanismParameter,
            plaintext,
            FunctionList->C_EncryptInit,
            FunctionList->C_Encrypt,
            "C_EncryptInit",
            "C_Encrypt",
            "encrypted output length");

    public bool TryEncrypt(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, out int written)
        => TrySinglePartCrypt(
            sessionHandle,
            keyHandle,
            mechanismType,
            mechanismParameter,
            plaintext,
            ciphertext,
            out written,
            FunctionList->C_EncryptInit,
            FunctionList->C_Encrypt,
            "C_EncryptInit",
            "C_Encrypt",
            "encrypted output");

    public int GetDecryptOutputLength(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<byte> ciphertext)
        => GetSinglePartOutputLength(
            sessionHandle,
            keyHandle,
            mechanismType,
            mechanismParameter,
            ciphertext,
            FunctionList->C_DecryptInit,
            FunctionList->C_Decrypt,
            "C_DecryptInit",
            "C_Decrypt",
            "decrypted output length");

    public bool TryDecrypt(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, out int written)
        => TrySinglePartCrypt(
            sessionHandle,
            keyHandle,
            mechanismType,
            mechanismParameter,
            ciphertext,
            plaintext,
            out written,
            FunctionList->C_DecryptInit,
            FunctionList->C_Decrypt,
            "C_DecryptInit",
            "C_Decrypt",
            "decrypted output");

    public int GetSignOutputLength(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<byte> data)
        => GetSinglePartOutputLength(
            sessionHandle,
            keyHandle,
            mechanismType,
            mechanismParameter,
            data,
            FunctionList->C_SignInit,
            FunctionList->C_Sign,
            "C_SignInit",
            "C_Sign",
            "signature length");

    public int GetDigestOutputLength(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<byte> data)
        => GetSinglePartDigestOutputLength(
            sessionHandle,
            mechanismType,
            mechanismParameter,
            data,
            FunctionList->C_DigestInit,
            FunctionList->C_Digest,
            "C_DigestInit",
            "C_Digest",
            "digest length");

    public bool TryDigest(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<byte> data, Span<byte> digest, out int written)
        => TrySinglePartDigest(
            sessionHandle,
            mechanismType,
            mechanismParameter,
            data,
            digest,
            out written,
            FunctionList->C_DigestInit,
            FunctionList->C_Digest,
            "C_DigestInit",
            "C_Digest",
            "digest");

    public void DigestKey(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(DigestKey), "C_DigestKey", sessionHandle: sessionHandle);
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_DigestKey, "C_DigestKey");

            CK_RV result = FunctionList->C_DigestKey(sessionHandle, keyHandle);
            ThrowIfFailed(result, "C_DigestKey");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool TrySign(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<byte> data, Span<byte> signature, out int written)
        => TrySinglePartCrypt(
            sessionHandle,
            keyHandle,
            mechanismType,
            mechanismParameter,
            data,
            signature,
            out written,
            FunctionList->C_SignInit,
            FunctionList->C_Sign,
            "C_SignInit",
            "C_Sign",
            "signature");

    public bool Verify(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(Verify), "C_Verify", sessionHandle: sessionHandle, mechanismType: mechanismType);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.MechanismParameters(mechanismType, mechanismParameter));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("data", data));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("signature", signature));
        }

        try
        {
            EnsureInitialized();
            EnsureVerifyFunctions(FunctionList->C_VerifyInit, FunctionList->C_Verify, "C_VerifyInit", "C_Verify");

            fixed (byte* mechanismParameterPointer = mechanismParameter)
            {
                CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length, out MarshalledMechanismParameters marshalledMechanismParameters);
                InitializeCryptOperation(sessionHandle, keyHandle, &mechanism, FunctionList->C_VerifyInit, "C_VerifyInit");
                bool verified = InvokeVerify(sessionHandle, data, signature, FunctionList->C_Verify, "C_Verify");
                if (verified)
                {
                    telemetry.Succeeded(CK_RV.Ok);
                }
                else
                {
                    telemetry.ReturnedFalse(Pkcs11ReturnValues.SignatureInvalid);
                }

                return verified;
            }
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public void SignInit(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter)
        => InitializeMultiPartCryptOperation(
            sessionHandle,
            keyHandle,
            mechanismType,
            mechanismParameter,
            FunctionList->C_SignInit,
            "C_SignInit");

    public void SignUpdate(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> data)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(SignUpdate), "C_SignUpdate", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("data", data));
        }

        try
        {
            EnsureDataUpdateFunction(FunctionList->C_SignUpdate, "C_SignUpdate");

            if (data.IsEmpty)
            {
                telemetry.Succeeded(CK_RV.Ok);
                return;
            }

            CK_RV result;
            fixed (byte* dataPointer = data)
            {
                result = FunctionList->C_SignUpdate(sessionHandle, dataPointer, (CK_ULONG)(nuint)data.Length);
            }

            ThrowIfFailed(result, "C_SignUpdate");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool TrySignFinal(CK_SESSION_HANDLE sessionHandle, Span<byte> signature, out int written)
        => TryCryptFinal(
            sessionHandle,
            signature,
            out written,
            FunctionList->C_SignFinal,
            "C_SignFinal",
            "signature");

    public void SignRecoverInit(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter)
        => InitializeMultiPartCryptOperation(
            sessionHandle,
            keyHandle,
            mechanismType,
            mechanismParameter,
            FunctionList->C_SignRecoverInit,
            "C_SignRecoverInit");

    public int GetSignRecoverOutputLength(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> data)
        => GetCryptInvokeOutputLength(
            sessionHandle,
            data,
            FunctionList->C_SignRecover,
            "C_SignRecover",
            "signature");

    public bool TrySignRecover(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> data, Span<byte> signature, out int written)
        => TryCryptUpdate(
            sessionHandle,
            data,
            signature,
            out written,
            FunctionList->C_SignRecover,
            "C_SignRecover",
            "signature");

    public void VerifyInit(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter)
        => InitializeMultiPartCryptOperation(
            sessionHandle,
            keyHandle,
            mechanismType,
            mechanismParameter,
            FunctionList->C_VerifyInit,
            "C_VerifyInit");

    public void VerifyUpdate(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> data)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(VerifyUpdate), "C_VerifyUpdate", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("data", data));
        }

        try
        {
            EnsureDataUpdateFunction(FunctionList->C_VerifyUpdate, "C_VerifyUpdate");

            if (data.IsEmpty)
            {
                telemetry.Succeeded(CK_RV.Ok);
                return;
            }

            CK_RV result;
            fixed (byte* dataPointer = data)
            {
                result = FunctionList->C_VerifyUpdate(sessionHandle, dataPointer, (CK_ULONG)(nuint)data.Length);
            }

            ThrowIfFailed(result, "C_VerifyUpdate");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool VerifyFinal(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> signature)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(VerifyFinal), "C_VerifyFinal", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("signature", signature));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_VerifyFinal, "C_VerifyFinal");

            CK_RV result;
            if (signature.IsEmpty)
            {
                result = FunctionList->C_VerifyFinal(sessionHandle, null, 0);
            }
            else
            {
                fixed (byte* signaturePointer = signature)
                {
                    result = FunctionList->C_VerifyFinal(sessionHandle, signaturePointer, (CK_ULONG)(nuint)signature.Length);
                }
            }

            if (result == Pkcs11ReturnValues.SignatureInvalid || result == Pkcs11ReturnValues.SignatureLenRange)
            {
                telemetry.ReturnedFalse(result);
                return false;
            }

            ThrowIfFailed(result, "C_VerifyFinal");
            telemetry.Succeeded(result);
            return true;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public void VerifyRecoverInit(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter)
        => InitializeMultiPartCryptOperation(
            sessionHandle,
            keyHandle,
            mechanismType,
            mechanismParameter,
            FunctionList->C_VerifyRecoverInit,
            "C_VerifyRecoverInit");

    public int GetVerifyRecoverOutputLength(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> signature)
        => GetCryptInvokeOutputLength(
            sessionHandle,
            signature,
            FunctionList->C_VerifyRecover,
            "C_VerifyRecover",
            "recovered data length");

    public bool TryVerifyRecover(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> signature, Span<byte> data, out int written)
        => TryCryptUpdate(
            sessionHandle,
            signature,
            data,
            out written,
            FunctionList->C_VerifyRecover,
            "C_VerifyRecover",
            "recovered data");

    public void DigestInit(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter)
        => InitializeMultiPartDigestOperation(
            sessionHandle,
            mechanismType,
            mechanismParameter,
            FunctionList->C_DigestInit,
            "C_DigestInit");

    public void DigestUpdate(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> data)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(DigestUpdate), "C_DigestUpdate", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("data", data));
        }

        try
        {
            EnsureDataUpdateFunction(FunctionList->C_DigestUpdate, "C_DigestUpdate");

            if (data.IsEmpty)
            {
                telemetry.Succeeded(CK_RV.Ok);
                return;
            }

            CK_RV result;
            fixed (byte* dataPointer = data)
            {
                result = FunctionList->C_DigestUpdate(sessionHandle, dataPointer, (CK_ULONG)(nuint)data.Length);
            }

            ThrowIfFailed(result, "C_DigestUpdate");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool TryDigestFinal(CK_SESSION_HANDLE sessionHandle, Span<byte> digest, out int written)
        => TryCryptFinal(
            sessionHandle,
            digest,
            out written,
            FunctionList->C_DigestFinal,
            "C_DigestFinal",
            "digest");

    public void GenerateRandom(CK_SESSION_HANDLE sessionHandle, Span<byte> destination)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(GenerateRandom), "C_GenerateRandom", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("random.output", destination.Length));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_GenerateRandom, "C_GenerateRandom");

            CK_RV result;
            if (destination.IsEmpty)
            {
                result = FunctionList->C_GenerateRandom(sessionHandle, null, 0);
            }
            else
            {
                fixed (byte* destinationPointer = destination)
                {
                    result = FunctionList->C_GenerateRandom(sessionHandle, destinationPointer, (CK_ULONG)(nuint)destination.Length);
                }
            }

            ThrowIfFailed(result, "C_GenerateRandom");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public void SeedRandom(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> seed)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(SeedRandom), "C_SeedRandom", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("random.seed", seed));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_SeedRandom, "C_SeedRandom");

            CK_RV result;
            if (seed.IsEmpty)
            {
                result = FunctionList->C_SeedRandom(sessionHandle, null, 0);
            }
            else
            {
                fixed (byte* seedPointer = seed)
                {
                    result = FunctionList->C_SeedRandom(sessionHandle, seedPointer, (CK_ULONG)(nuint)seed.Length);
                }
            }

            ThrowIfFailed(result, "C_SeedRandom");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public CK_SLOT_ID WaitForSlotEvent()
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(WaitForSlotEvent), "C_WaitForSlotEvent");
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_WaitForSlotEvent, "C_WaitForSlotEvent");

            CK_SLOT_ID slotId = default;
            CK_RV result = FunctionList->C_WaitForSlotEvent(new CK_FLAGS(0), &slotId, null);
            ThrowIfFailed(result, "C_WaitForSlotEvent");
            telemetry.Succeeded(result);
            return slotId;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool TryWaitForSlotEvent(out CK_SLOT_ID slotId)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(TryWaitForSlotEvent), "C_WaitForSlotEvent");
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_WaitForSlotEvent, "C_WaitForSlotEvent");

            CK_SLOT_ID nativeSlotId = default;
            CK_RV result = FunctionList->C_WaitForSlotEvent(new CK_FLAGS(Pkcs11SlotEventFlags.DontBlock), &nativeSlotId, null);
            if (result == Pkcs11ReturnValues.NoEvent)
            {
                slotId = default;
                telemetry.ReturnedFalse(result);
                return false;
            }

            ThrowIfFailed(result, "C_WaitForSlotEvent");
            slotId = nativeSlotId;
            telemetry.Succeeded(result);
            return true;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public void EncryptInit(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter)
        => InitializeMultiPartCryptOperation(
            sessionHandle,
            keyHandle,
            mechanismType,
            mechanismParameter,
            FunctionList->C_EncryptInit,
            "C_EncryptInit");

    public bool TryEncryptUpdate(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> input, Span<byte> output, out int written)
        => TryCryptUpdate(
            sessionHandle,
            input,
            output,
            out written,
            FunctionList->C_EncryptUpdate,
            "C_EncryptUpdate",
            "encrypted output");

    public bool TryDigestEncryptUpdate(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> input, Span<byte> output, out int written)
        => TryCryptUpdate(
            sessionHandle,
            input,
            output,
            out written,
            FunctionList->C_DigestEncryptUpdate,
            "C_DigestEncryptUpdate",
            "digested and encrypted output");

    public bool TrySignEncryptUpdate(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> input, Span<byte> output, out int written)
        => TryCryptUpdate(
            sessionHandle,
            input,
            output,
            out written,
            FunctionList->C_SignEncryptUpdate,
            "C_SignEncryptUpdate",
            "signed and encrypted output");

    public bool TryEncryptFinal(CK_SESSION_HANDLE sessionHandle, Span<byte> output, out int written)
        => TryCryptFinal(
            sessionHandle,
            output,
            out written,
            FunctionList->C_EncryptFinal,
            "C_EncryptFinal",
            "encrypted output");

    public void DecryptInit(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter)
        => InitializeMultiPartCryptOperation(
            sessionHandle,
            keyHandle,
            mechanismType,
            mechanismParameter,
            FunctionList->C_DecryptInit,
            "C_DecryptInit");

    public bool TryDecryptUpdate(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> input, Span<byte> output, out int written)
        => TryCryptUpdate(
            sessionHandle,
            input,
            output,
            out written,
            FunctionList->C_DecryptUpdate,
            "C_DecryptUpdate",
            "decrypted output");

    public bool TryDecryptDigestUpdate(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> input, Span<byte> output, out int written)
        => TryCryptUpdate(
            sessionHandle,
            input,
            output,
            out written,
            FunctionList->C_DecryptDigestUpdate,
            "C_DecryptDigestUpdate",
            "decrypted and digested output");

    public bool TryDecryptVerifyUpdate(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> input, Span<byte> output, out int written)
        => TryCryptUpdate(
            sessionHandle,
            input,
            output,
            out written,
            FunctionList->C_DecryptVerifyUpdate,
            "C_DecryptVerifyUpdate",
            "decrypted and verified output");

    public bool TryDecryptFinal(CK_SESSION_HANDLE sessionHandle, Span<byte> output, out int written)
        => TryCryptFinal(
            sessionHandle,
            output,
            out written,
            FunctionList->C_DecryptFinal,
            "C_DecryptFinal",
            "decrypted output");

    public int GetOperationStateLength(CK_SESSION_HANDLE sessionHandle)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(GetOperationStateLength), "C_GetOperationState", sessionHandle: sessionHandle);
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_GetOperationState, "C_GetOperationState");

            CK_ULONG stateLength = default;
            CK_RV result = FunctionList->C_GetOperationState(sessionHandle, null, &stateLength);
            ThrowIfFailed(result, "C_GetOperationState");
            telemetry.Succeeded(result);
            return ToInt32Checked(stateLength, "operation state length");
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool TryGetOperationState(CK_SESSION_HANDLE sessionHandle, Span<byte> destination, out int written)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(TryGetOperationState), "C_GetOperationState", sessionHandle: sessionHandle);
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_GetOperationState, "C_GetOperationState");

            CK_ULONG stateLength = (CK_ULONG)(nuint)destination.Length;
            CK_RV result;

            if (destination.IsEmpty)
            {
                result = FunctionList->C_GetOperationState(sessionHandle, null, &stateLength);
            }
            else
            {
                fixed (byte* destinationPointer = destination)
                {
                    result = FunctionList->C_GetOperationState(sessionHandle, destinationPointer, &stateLength);
                }
            }

            if (result == Pkcs11ReturnValues.BufferTooSmall)
            {
                written = ToInt32Checked(stateLength, "operation state length");
                telemetry.ReturnedFalse(result);
                return false;
            }

            ThrowIfFailed(result, "C_GetOperationState");
            written = ToInt32Checked(stateLength, "operation state length");
            telemetry.Succeeded(result);
            return true;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public void SetOperationState(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> state, CK_OBJECT_HANDLE encryptionKeyHandle, CK_OBJECT_HANDLE authenticationKeyHandle)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(SetOperationState), "C_SetOperationState", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("operation.state", state));
            telemetry.AddField(Pkcs11TelemetryRedaction.Safe("operation.encryptionKeyHandle", encryptionKeyHandle.Value));
            telemetry.AddField(Pkcs11TelemetryRedaction.Safe("operation.authenticationKeyHandle", authenticationKeyHandle.Value));
        }

        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_SetOperationState, "C_SetOperationState");

            CK_RV result;
            if (state.IsEmpty)
            {
                result = FunctionList->C_SetOperationState(sessionHandle, null, 0, encryptionKeyHandle, authenticationKeyHandle);
            }
            else
            {
                fixed (byte* statePointer = state)
                {
                    result = FunctionList->C_SetOperationState(sessionHandle, statePointer, (CK_ULONG)(nuint)state.Length, encryptionKeyHandle, authenticationKeyHandle);
                }
            }

            ThrowIfFailed(result, "C_SetOperationState");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool TryGetFunctionStatus(CK_SESSION_HANDLE sessionHandle)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(TryGetFunctionStatus), "C_GetFunctionStatus", sessionHandle: sessionHandle);
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_GetFunctionStatus, "C_GetFunctionStatus");

            CK_RV result = FunctionList->C_GetFunctionStatus(sessionHandle);
            if (result == Pkcs11ReturnValues.FunctionNotParallel || result == Pkcs11ReturnValues.FunctionNotSupported)
            {
                telemetry.ReturnedFalse(result);
                return false;
            }

            ThrowIfFailed(result, "C_GetFunctionStatus");
            telemetry.Succeeded(result);
            return true;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool TryCancelFunction(CK_SESSION_HANDLE sessionHandle)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(TryCancelFunction), "C_CancelFunction", sessionHandle: sessionHandle);
        try
        {
            EnsureInitialized();

            EnsureFunctionAvailable((void*)FunctionList->C_CancelFunction, "C_CancelFunction");

            CK_RV result = FunctionList->C_CancelFunction(sessionHandle);
            if (result == Pkcs11ReturnValues.FunctionNotParallel || result == Pkcs11ReturnValues.FunctionNotSupported)
            {
                telemetry.ReturnedFalse(result);
                return false;
            }

            ThrowIfFailed(result, "C_CancelFunction");
            telemetry.Succeeded(result);
            return true;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public void LoginUser(CK_SESSION_HANDLE sessionHandle, CK_USER_TYPE userType, ReadOnlySpan<byte> pinUtf8, ReadOnlySpan<byte> usernameUtf8)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(LoginUser), "C_LoginUser", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.Credentials(userType, pinUtf8, usernameUtf8));
        }

        try
        {
            EnsureInitialized();

            CK_FUNCTION_LIST_3_0* functionList = GetFunctionList30();
            EnsureFunctionAvailable((void*)functionList->C_LoginUser, "C_LoginUser");

            CK_RV result;
            if (pinUtf8.IsEmpty && usernameUtf8.IsEmpty)
            {
                result = functionList->C_LoginUser(sessionHandle, userType, null, 0, null, 0);
            }
            else
            {
                fixed (byte* pinPointer = pinUtf8)
                fixed (byte* usernamePointer = usernameUtf8)
                {
                    result = functionList->C_LoginUser(
                        sessionHandle,
                        userType,
                        pinUtf8.IsEmpty ? null : pinPointer,
                        (CK_ULONG)(nuint)pinUtf8.Length,
                        usernameUtf8.IsEmpty ? null : usernamePointer,
                        (CK_ULONG)(nuint)usernameUtf8.Length);
                }
            }

            ThrowIfFailed(result, "C_LoginUser");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public void SessionCancel(CK_SESSION_HANDLE sessionHandle, CK_FLAGS flags)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(SessionCancel), "C_SessionCancel", sessionHandle: sessionHandle);
        try
        {
            EnsureInitialized();
            CK_FUNCTION_LIST_3_0* functionList = GetFunctionList30();
            EnsureFunctionAvailable((void*)functionList->C_SessionCancel, "C_SessionCancel");
            CK_RV result = functionList->C_SessionCancel(sessionHandle, flags);
            ThrowIfFailed(result, "C_SessionCancel");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public void MessageEncryptInit(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter)
        => InitializeV3CryptOperation(sessionHandle, keyHandle, mechanismType, mechanismParameter, GetFunctionList30()->C_MessageEncryptInit, "C_MessageEncryptInit");

    public int GetMessageEncryptOutputLength(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext)
        => GetMessageOutputLength(sessionHandle, parameter, associatedData, plaintext, GetFunctionList30()->C_EncryptMessage, "C_EncryptMessage", "ciphertext length");

    public bool TryEncryptMessage(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, out int written)
        => TryMessageInvoke(sessionHandle, parameter, associatedData, plaintext, ciphertext, out written, GetFunctionList30()->C_EncryptMessage, "C_EncryptMessage", "ciphertext length");

    public void EncryptMessageBegin(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> associatedData)
        => MessageBegin(sessionHandle, parameter, associatedData, GetFunctionList30()->C_EncryptMessageBegin, "C_EncryptMessageBegin");

    public bool TryEncryptMessageNext(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> plaintextPart, Span<byte> ciphertextPart, CK_FLAGS flags, out int written)
        => TryMessageNext(sessionHandle, parameter, plaintextPart, ciphertextPart, flags, out written, GetFunctionList30()->C_EncryptMessageNext, "C_EncryptMessageNext", "ciphertext length");

    public void MessageEncryptFinal(CK_SESSION_HANDLE sessionHandle) => MessageFinal(sessionHandle, GetFunctionList30()->C_MessageEncryptFinal, "C_MessageEncryptFinal");

    public void MessageDecryptInit(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter)
        => InitializeV3CryptOperation(sessionHandle, keyHandle, mechanismType, mechanismParameter, GetFunctionList30()->C_MessageDecryptInit, "C_MessageDecryptInit");

    public int GetMessageDecryptOutputLength(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext)
        => GetMessageOutputLength(sessionHandle, parameter, associatedData, ciphertext, GetFunctionList30()->C_DecryptMessage, "C_DecryptMessage", "plaintext length");

    public bool TryDecryptMessage(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, out int written)
        => TryMessageInvoke(sessionHandle, parameter, associatedData, ciphertext, plaintext, out written, GetFunctionList30()->C_DecryptMessage, "C_DecryptMessage", "plaintext length");

    public void DecryptMessageBegin(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> associatedData)
        => MessageBegin(sessionHandle, parameter, associatedData, GetFunctionList30()->C_DecryptMessageBegin, "C_DecryptMessageBegin");

    public bool TryDecryptMessageNext(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> ciphertextPart, Span<byte> plaintextPart, CK_FLAGS flags, out int written)
        => TryMessageNext(sessionHandle, parameter, ciphertextPart, plaintextPart, flags, out written, GetFunctionList30()->C_DecryptMessageNext, "C_DecryptMessageNext", "plaintext length");

    public void MessageDecryptFinal(CK_SESSION_HANDLE sessionHandle) => MessageFinal(sessionHandle, GetFunctionList30()->C_MessageDecryptFinal, "C_MessageDecryptFinal");

    public void MessageSignInit(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter)
        => InitializeV3CryptOperation(sessionHandle, keyHandle, mechanismType, mechanismParameter, GetFunctionList30()->C_MessageSignInit, "C_MessageSignInit");

    public int GetSignMessageOutputLength(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> data)
        => GetSignMessageOutputLengthCore(sessionHandle, parameter, data, GetFunctionList30()->C_SignMessage, "C_SignMessage");

    public bool TrySignMessage(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> data, Span<byte> signature, out int written)
        => TrySignMessageCore(sessionHandle, parameter, data, signature, out written, GetFunctionList30()->C_SignMessage, "C_SignMessage");

    public void SignMessageBegin(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(SignMessageBegin), "C_SignMessageBegin", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.parameter", parameter));
        }

        try
        {
            EnsureInitialized();
            CK_FUNCTION_LIST_3_0* functionList = GetFunctionList30();
            EnsureFunctionAvailable((void*)functionList->C_SignMessageBegin, "C_SignMessageBegin");

            CK_RV result;
            if (parameter.IsEmpty)
            {
                result = functionList->C_SignMessageBegin(sessionHandle, null, 0);
            }
            else
            {
                fixed (byte* parameterPointer = parameter)
                {
                    result = functionList->C_SignMessageBegin(sessionHandle, parameterPointer, (CK_ULONG)(nuint)parameter.Length);
                }
            }

            ThrowIfFailed(result, "C_SignMessageBegin");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool TrySignMessageNext(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> data, Span<byte> signature, out int written)
        => TrySignMessageCore(sessionHandle, parameter, data, signature, out written, GetFunctionList30()->C_SignMessageNext, "C_SignMessageNext");

    public void MessageSignFinal(CK_SESSION_HANDLE sessionHandle) => MessageFinal(sessionHandle, GetFunctionList30()->C_MessageSignFinal, "C_MessageSignFinal");

    public void MessageVerifyInit(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE keyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter)
        => InitializeV3CryptOperation(sessionHandle, keyHandle, mechanismType, mechanismParameter, GetFunctionList30()->C_MessageVerifyInit, "C_MessageVerifyInit");

    public bool VerifyMessage(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        => VerifyMessageCore(sessionHandle, parameter, data, signature, GetFunctionList30()->C_VerifyMessage, "C_VerifyMessage");

    public void VerifyMessageBegin(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(nameof(VerifyMessageBegin), "C_VerifyMessageBegin", sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.parameter", parameter));
        }

        try
        {
            EnsureInitialized();
            CK_FUNCTION_LIST_3_0* functionList = GetFunctionList30();
            EnsureFunctionAvailable((void*)functionList->C_VerifyMessageBegin, "C_VerifyMessageBegin");

            CK_RV result;
            if (parameter.IsEmpty)
            {
                result = functionList->C_VerifyMessageBegin(sessionHandle, null, 0);
            }
            else
            {
                fixed (byte* parameterPointer = parameter)
                {
                    result = functionList->C_VerifyMessageBegin(sessionHandle, parameterPointer, (CK_ULONG)(nuint)parameter.Length);
                }
            }

            ThrowIfFailed(result, "C_VerifyMessageBegin");
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    public bool VerifyMessageNext(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        => VerifyMessageCore(sessionHandle, parameter, data, signature, GetFunctionList30()->C_VerifyMessageNext, "C_VerifyMessageNext");

    public void MessageVerifyFinal(CK_SESSION_HANDLE sessionHandle) => MessageFinal(sessionHandle, GetFunctionList30()->C_MessageVerifyFinal, "C_MessageVerifyFinal");

    public void Dispose()
    {
        lock (_lifecycleSync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;

            try
            {
                if (_isInitialized && _ownsInitialization)
                {
                    try
                    {
                        InvokeFinalize();
                    }
                    catch (Pkcs11Exception)
                    {
                    }
                }
            }
            finally
            {
                _isInitialized = false;
                _ownsInitialization = false;
                NativeLibrary.Free(_handle);
            }
        }
    }

    private CK_FUNCTION_LIST_3_0* GetFunctionList30()
    {
        if (!TryGetInterface([], new CK_VERSION(3, 0), new CK_FLAGS(0), out CK_INTERFACE nativeInterface))
        {
            throw new InvalidOperationException("The PKCS#11 module does not expose a PKCS#11 v3.0 interface.");
        }

        if (nativeInterface.FunctionList is null)
        {
            throw new InvalidOperationException("C_GetInterface returned a null function list pointer.");
        }

        return (CK_FUNCTION_LIST_3_0*)nativeInterface.FunctionList;
    }

    private void InitializeV3CryptOperation(
        CK_SESSION_HANDLE sessionHandle,
        CK_OBJECT_HANDLE keyHandle,
        CK_MECHANISM_TYPE mechanismType,
        ReadOnlySpan<byte> mechanismParameter,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_RV> init,
        string operation)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(operation, operation, sessionHandle: sessionHandle, mechanismType: mechanismType);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.MechanismParameters(mechanismType, mechanismParameter));
        }

        try
        {
            EnsureInitialized();
            EnsureFunctionAvailable((void*)init, operation);

            fixed (byte* mechanismParameterPointer = mechanismParameter)
            {
                CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length, out MarshalledMechanismParameters marshalledMechanismParameters);
                CK_RV result = init(sessionHandle, &mechanism, keyHandle);
                ThrowIfFailed(result, operation);
                telemetry.Succeeded(result);
            }
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private int GetMessageOutputLength(
        CK_SESSION_HANDLE sessionHandle,
        ReadOnlySpan<byte> parameter,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> input,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> invoke,
        string operation,
        string outputName)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(operation, operation, sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.parameter", parameter));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.associatedData", associatedData));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.input", input));
        }

        try
        {
            EnsureInitialized();
            EnsureFunctionAvailable((void*)invoke, operation);
            CK_ULONG outputLength = default;
            CK_RV result = InvokeMessage(sessionHandle, parameter, associatedData, input, null, &outputLength, invoke, operation);
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.output", ToInt32Checked(outputLength, outputName)));
            telemetry.Succeeded(result);
            return ToInt32Checked(outputLength, outputName);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private bool TryMessageInvoke(
        CK_SESSION_HANDLE sessionHandle,
        ReadOnlySpan<byte> parameter,
        ReadOnlySpan<byte> associatedData,
        ReadOnlySpan<byte> input,
        Span<byte> output,
        out int written,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> invoke,
        string operation,
        string outputName)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(operation, operation, sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.parameter", parameter));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.associatedData", associatedData));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.input", input));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.outputDestination", output.Length));
        }

        try
        {
            EnsureInitialized();
            EnsureFunctionAvailable((void*)invoke, operation);
            CK_ULONG outputLength = (CK_ULONG)(nuint)output.Length;

            fixed (byte* outputPointer = output)
            {
                CK_RV result = InvokeMessage(sessionHandle, parameter, associatedData, input, output.IsEmpty ? null : outputPointer, &outputLength, invoke, operation, throwOnError: false);
                if (result == Pkcs11ReturnValues.BufferTooSmall)
                {
                    written = ToInt32Checked(outputLength, outputName);
                    telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.output", written));
                    telemetry.ReturnedFalse(result);
                    return false;
                }

                ThrowIfFailed(result, operation);
                telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.output", ToInt32Checked(outputLength, outputName)));
                telemetry.Succeeded(result);
            }

            written = ToInt32Checked(outputLength, outputName);
            return true;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private void MessageBegin(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> associatedData, delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, CK_RV> begin, string operation)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(operation, operation, sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.parameter", parameter));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.associatedData", associatedData));
        }

        try
        {
            EnsureInitialized();
            EnsureFunctionAvailable((void*)begin, operation);

            fixed (byte* parameterPointer = parameter)
            fixed (byte* associatedDataPointer = associatedData)
            {
                CK_RV result = begin(
                    sessionHandle,
                    parameter.IsEmpty ? null : parameterPointer,
                    (CK_ULONG)(nuint)parameter.Length,
                    associatedData.IsEmpty ? null : associatedDataPointer,
                    (CK_ULONG)(nuint)associatedData.Length);
                ThrowIfFailed(result, operation);
                telemetry.Succeeded(result);
            }
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private bool TryMessageNext(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> input, Span<byte> output, CK_FLAGS flags, out int written, delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG*, CK_FLAGS, CK_RV> next, string operation, string outputName)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(operation, operation, sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.parameter", parameter));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.input", input));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.outputDestination", output.Length));
            telemetry.AddField(Pkcs11TelemetryRedaction.SafeHex("message.flags", flags.Value));
        }

        try
        {
            EnsureInitialized();
            EnsureFunctionAvailable((void*)next, operation);

            CK_ULONG outputLength = (CK_ULONG)(nuint)output.Length;
            fixed (byte* parameterPointer = parameter)
            fixed (byte* inputPointer = input)
            fixed (byte* outputPointer = output)
            {
                CK_RV result = next(
                    sessionHandle,
                    parameter.IsEmpty ? null : parameterPointer,
                    (CK_ULONG)(nuint)parameter.Length,
                    input.IsEmpty ? null : inputPointer,
                    (CK_ULONG)(nuint)input.Length,
                    output.IsEmpty ? null : outputPointer,
                    &outputLength,
                    flags);

                if (result == Pkcs11ReturnValues.BufferTooSmall)
                {
                    written = ToInt32Checked(outputLength, outputName);
                    telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.output", written));
                    telemetry.ReturnedFalse(result);
                    return false;
                }

                ThrowIfFailed(result, operation);
                telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.output", ToInt32Checked(outputLength, outputName)));
                telemetry.Succeeded(result);
            }

            written = ToInt32Checked(outputLength, outputName);
            return true;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private void MessageFinal(CK_SESSION_HANDLE sessionHandle, delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_RV> final, string operation)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(operation, operation, sessionHandle: sessionHandle);
        try
        {
            EnsureInitialized();
            EnsureFunctionAvailable((void*)final, operation);
            CK_RV result = final(sessionHandle);
            ThrowIfFailed(result, operation);
            telemetry.Succeeded(result);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private int GetSignMessageOutputLengthCore(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> data, delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> invoke, string operation)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(operation, operation, sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.parameter", parameter));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("data", data));
        }

        try
        {
            EnsureInitialized();
            EnsureFunctionAvailable((void*)invoke, operation);
            CK_ULONG signatureLength = default;
            CK_RV result = InvokeSignMessage(sessionHandle, parameter, data, null, &signatureLength, invoke, operation);
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("signature", ToInt32Checked(signatureLength, "signature length")));
            telemetry.Succeeded(result);
            return ToInt32Checked(signatureLength, "signature length");
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private bool TrySignMessageCore(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> data, Span<byte> signature, out int written, delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> invoke, string operation)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(operation, operation, sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.parameter", parameter));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("data", data));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("signature.destination", signature.Length));
        }

        try
        {
            EnsureInitialized();
            EnsureFunctionAvailable((void*)invoke, operation);
            CK_ULONG signatureLength = (CK_ULONG)(nuint)signature.Length;

            fixed (byte* signaturePointer = signature)
            {
                CK_RV result = InvokeSignMessage(sessionHandle, parameter, data, signature.IsEmpty ? null : signaturePointer, &signatureLength, invoke, operation, throwOnError: false);
                if (result == Pkcs11ReturnValues.BufferTooSmall)
                {
                    written = ToInt32Checked(signatureLength, "signature length");
                    telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("signature", written));
                    telemetry.ReturnedFalse(result);
                    return false;
                }

                ThrowIfFailed(result, operation);
                telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("signature", ToInt32Checked(signatureLength, "signature length")));
                telemetry.Succeeded(result);
            }

            written = ToInt32Checked(signatureLength, "signature length");
            return true;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private bool VerifyMessageCore(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG, CK_RV> verify, string operation)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(operation, operation, sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("message.parameter", parameter));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("data", data));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("signature", signature));
        }

        try
        {
            EnsureInitialized();
            EnsureFunctionAvailable((void*)verify, operation);

            fixed (byte* parameterPointer = parameter)
            fixed (byte* dataPointer = data)
            fixed (byte* signaturePointer = signature)
            {
                CK_RV result = verify(
                    sessionHandle,
                    parameter.IsEmpty ? null : parameterPointer,
                    (CK_ULONG)(nuint)parameter.Length,
                    data.IsEmpty ? null : dataPointer,
                    (CK_ULONG)(nuint)data.Length,
                    signature.IsEmpty ? null : signaturePointer,
                    (CK_ULONG)(nuint)signature.Length);

                if (result == Pkcs11ReturnValues.SignatureInvalid || result == Pkcs11ReturnValues.SignatureLenRange)
                {
                    telemetry.ReturnedFalse(result);
                    return false;
                }

                ThrowIfFailed(result, operation);
                telemetry.Succeeded(result);
                return true;
            }
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private CK_RV InvokeMessage(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> input, byte* output, CK_ULONG* outputLength, delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> invoke, string operation, bool throwOnError = true)
    {
        fixed (byte* parameterPointer = parameter)
        fixed (byte* associatedDataPointer = associatedData)
        fixed (byte* inputPointer = input)
        {
            CK_RV result = invoke(
                sessionHandle,
                parameter.IsEmpty ? null : parameterPointer,
                (CK_ULONG)(nuint)parameter.Length,
                associatedData.IsEmpty ? null : associatedDataPointer,
                (CK_ULONG)(nuint)associatedData.Length,
                input.IsEmpty ? null : inputPointer,
                (CK_ULONG)(nuint)input.Length,
                output,
                outputLength);

            if (throwOnError)
            {
                ThrowIfFailed(result, operation);
            }

            return result;
        }
    }

    private CK_RV InvokeSignMessage(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> data, byte* signature, CK_ULONG* signatureLength, delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, void*, CK_ULONG, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> invoke, string operation, bool throwOnError = true)
    {
        fixed (byte* parameterPointer = parameter)
        fixed (byte* dataPointer = data)
        {
            CK_RV result = invoke(
                sessionHandle,
                parameter.IsEmpty ? null : parameterPointer,
                (CK_ULONG)(nuint)parameter.Length,
                data.IsEmpty ? null : dataPointer,
                (CK_ULONG)(nuint)data.Length,
                signature,
                signatureLength);

            if (throwOnError)
            {
                ThrowIfFailed(result, operation);
            }

            return result;
        }
    }

    private void EnsureInitialized()
    {
        EnsureNotDisposed();

        if (!_isInitialized)
        {
            throw new InvalidOperationException("The PKCS#11 module must be initialized before invoking this operation.");
        }
    }

    private void EnsureNotDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(Pkcs11NativeModule));
        }
    }

    private static void EnsureFunctionAvailable(void* function, string operation)
    {
        if (function is null)
        {
            throw new InvalidOperationException($"The PKCS#11 function list does not expose {operation}.");
        }
    }

    private void InvokeFinalize()
    {
        EnsureFunctionAvailable((void*)_functionList->C_Finalize, "C_Finalize");

        CK_RV result = _functionList->C_Finalize(null);
        if (result == Pkcs11ReturnValues.CryptokiNotInitialized)
        {
            return;
        }

        ThrowIfFailed(result, "C_Finalize");
    }

    private CK_RV GetSlotList(bool tokenPresentOnly, CK_SLOT_ID* slotList, CK_ULONG* count)
    {
        EnsureFunctionAvailable((void*)FunctionList->C_GetSlotList, "C_GetSlotList");

        CK_BBOOL tokenPresent = tokenPresentOnly ? CK_BBOOL.True : CK_BBOOL.False;
        return FunctionList->C_GetSlotList(tokenPresent, slotList, count);
    }

    private CK_RV GetMechanismList(CK_SLOT_ID slotId, CK_MECHANISM_TYPE* mechanismList, CK_ULONG* count)
    {
        EnsureFunctionAvailable((void*)FunctionList->C_GetMechanismList, "C_GetMechanismList");

        return FunctionList->C_GetMechanismList(slotId, mechanismList, count);
    }

    private int GetSinglePartOutputLength(
        CK_SESSION_HANDLE sessionHandle,
        CK_OBJECT_HANDLE keyHandle,
        CK_MECHANISM_TYPE mechanismType,
        ReadOnlySpan<byte> mechanismParameter,
        ReadOnlySpan<byte> input,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_RV> init,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> invoke,
        string initOperation,
        string invokeOperation,
        string outputName)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(invokeOperation, invokeOperation, sessionHandle: sessionHandle, mechanismType: mechanismType);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.MechanismParameters(mechanismType, mechanismParameter));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("input", input));
        }

        try
        {
            EnsureInitialized();
            EnsureCryptFunctions(init, invoke, initOperation, invokeOperation);

            CK_ULONG outputLength = default;

            fixed (byte* mechanismParameterPointer = mechanismParameter)
            {
                CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length, out MarshalledMechanismParameters marshalledMechanismParameters);
                InitializeCryptOperation(sessionHandle, keyHandle, &mechanism, init, initOperation);
                InvokeCrypt(sessionHandle, input, null, &outputLength, invoke, invokeOperation);
                DrainActiveCryptOperation(sessionHandle, input, outputLength, invoke, invokeOperation, outputName);
            }

            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("output", ToInt32Checked(outputLength, outputName)));
            telemetry.Succeeded(CK_RV.Ok);
            return ToInt32Checked(outputLength, outputName);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private int GetSinglePartDigestOutputLength(
        CK_SESSION_HANDLE sessionHandle,
        CK_MECHANISM_TYPE mechanismType,
        ReadOnlySpan<byte> mechanismParameter,
        ReadOnlySpan<byte> input,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_RV> init,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> invoke,
        string initOperation,
        string invokeOperation,
        string outputName)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(invokeOperation, invokeOperation, sessionHandle: sessionHandle, mechanismType: mechanismType);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.MechanismParameters(mechanismType, mechanismParameter));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("input", input));
        }

        try
        {
            EnsureInitialized();
            EnsureMechanismFunctions(init, invoke, initOperation, invokeOperation);

            CK_ULONG outputLength = default;

            fixed (byte* mechanismParameterPointer = mechanismParameter)
            {
                CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length, out MarshalledMechanismParameters marshalledMechanismParameters);
                InitializeMechanismOperation(sessionHandle, &mechanism, init, initOperation);
                InvokeCrypt(sessionHandle, input, null, &outputLength, invoke, invokeOperation);
                DrainActiveCryptOperation(sessionHandle, input, outputLength, invoke, invokeOperation, outputName);
            }

            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("output", ToInt32Checked(outputLength, outputName)));
            telemetry.Succeeded(CK_RV.Ok);
            return ToInt32Checked(outputLength, outputName);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private bool TrySinglePartCrypt(
        CK_SESSION_HANDLE sessionHandle,
        CK_OBJECT_HANDLE keyHandle,
        CK_MECHANISM_TYPE mechanismType,
        ReadOnlySpan<byte> mechanismParameter,
        ReadOnlySpan<byte> input,
        Span<byte> output,
        out int written,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_RV> init,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> invoke,
        string initOperation,
        string invokeOperation,
        string outputName)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(invokeOperation, invokeOperation, sessionHandle: sessionHandle, mechanismType: mechanismType);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.MechanismParameters(mechanismType, mechanismParameter));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("input", input));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("output.destination", output.Length));
        }

        try
        {
            EnsureInitialized();
            EnsureCryptFunctions(init, invoke, initOperation, invokeOperation);

            fixed (byte* mechanismParameterPointer = mechanismParameter)
            {
                CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length, out MarshalledMechanismParameters marshalledMechanismParameters);
                InitializeCryptOperation(sessionHandle, keyHandle, &mechanism, init, initOperation);

                CK_ULONG outputLength = (CK_ULONG)(nuint)output.Length;
                CK_RV result;

                fixed (byte* inputPointer = input)
                fixed (byte* outputPointer = output)
                {
                    result = invoke(sessionHandle, inputPointer, (CK_ULONG)(nuint)input.Length, outputPointer, &outputLength);
                }

                if (result == Pkcs11ReturnValues.BufferTooSmall)
                {
                    written = ToInt32Checked(outputLength, outputName);
                    DrainActiveCryptOperation(sessionHandle, input, outputLength, invoke, invokeOperation, outputName);
                    telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("output", written));
                    telemetry.ReturnedFalse(result);
                    return false;
                }

                ThrowIfFailed(result, invokeOperation);
                written = ToInt32Checked(outputLength, outputName);
                telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("output", written));
                telemetry.Succeeded(result);
                return true;
            }
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private bool TrySinglePartDigest(
        CK_SESSION_HANDLE sessionHandle,
        CK_MECHANISM_TYPE mechanismType,
        ReadOnlySpan<byte> mechanismParameter,
        ReadOnlySpan<byte> input,
        Span<byte> output,
        out int written,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_RV> init,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> invoke,
        string initOperation,
        string invokeOperation,
        string outputName)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(invokeOperation, invokeOperation, sessionHandle: sessionHandle, mechanismType: mechanismType);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.MechanismParameters(mechanismType, mechanismParameter));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("input", input));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("output.destination", output.Length));
        }

        try
        {
            EnsureInitialized();
            EnsureMechanismFunctions(init, invoke, initOperation, invokeOperation);

            fixed (byte* mechanismParameterPointer = mechanismParameter)
            {
                CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length, out MarshalledMechanismParameters marshalledMechanismParameters);
                InitializeMechanismOperation(sessionHandle, &mechanism, init, initOperation);

                CK_ULONG outputLength = (CK_ULONG)(nuint)output.Length;
                CK_RV result;

                fixed (byte* inputPointer = input)
                fixed (byte* outputPointer = output)
                {
                    result = invoke(sessionHandle, inputPointer, (CK_ULONG)(nuint)input.Length, outputPointer, &outputLength);
                }

                if (result == Pkcs11ReturnValues.BufferTooSmall)
                {
                    written = ToInt32Checked(outputLength, outputName);
                    DrainActiveCryptOperation(sessionHandle, input, outputLength, invoke, invokeOperation, outputName);
                    telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("output", written));
                    telemetry.ReturnedFalse(result);
                    return false;
                }

                ThrowIfFailed(result, invokeOperation);
                written = ToInt32Checked(outputLength, outputName);
                telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("output", written));
                telemetry.Succeeded(result);
                return true;
            }
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private static CK_MECHANISM CreateRawMechanism(CK_MECHANISM_TYPE mechanismType, byte* mechanismParameterPointer, int mechanismParameterLength)
        => new()
        {
            Mechanism = mechanismType,
            Parameter = mechanismParameterLength == 0 ? null : mechanismParameterPointer,
            ParameterLength = (CK_ULONG)(nuint)mechanismParameterLength,
        };

    private static CK_AES_CTR_PARAMS CreateAesCtrParams(byte* mechanismParameterPointer, int mechanismParameterLength)
    {
        int expectedLength = IntPtr.Size + 16;
        if (mechanismParameterLength < expectedLength)
        {
            throw new ArgumentException("CKM_AES_CTR parameters are incomplete.", nameof(mechanismParameterLength));
        }

        ReadOnlySpan<byte> parameter = new(mechanismParameterPointer, mechanismParameterLength);
        CK_AES_CTR_PARAMS ctrParams = default;
        ctrParams.CounterBits = (CK_ULONG)ReadPackedNuint(parameter);

        for (int i = 0; i < 16; i++)
        {
            ctrParams.Cb[i] = parameter[IntPtr.Size + i];
        }

        return ctrParams;
    }

    private static CK_CCM_PARAMS CreateAesCcmParams(byte* mechanismParameterPointer, int mechanismParameterLength)
    {
        int headerLength = IntPtr.Size * 4;
        if (mechanismParameterLength < headerLength)
        {
            throw new ArgumentException("CKM_AES_CCM parameters are incomplete.", nameof(mechanismParameterLength));
        }

        ReadOnlySpan<byte> parameter = new(mechanismParameterPointer, mechanismParameterLength);
        nuint dataLength = ReadPackedNuint(parameter);
        nuint nonceLength = ReadPackedNuint(parameter[IntPtr.Size..]);
        nuint aadLength = ReadPackedNuint(parameter[(IntPtr.Size * 2)..]);
        nuint macLength = ReadPackedNuint(parameter[(IntPtr.Size * 3)..]);
        nuint payloadLength = nonceLength + aadLength;

        if (payloadLength > (nuint)(mechanismParameterLength - headerLength))
        {
            throw new ArgumentException("CKM_AES_CCM parameter payload is truncated.", nameof(mechanismParameterLength));
        }

        byte* payloadPointer = mechanismParameterPointer + headerLength;
        byte* noncePointer = nonceLength == 0 ? null : payloadPointer;
        byte* aadPointer = aadLength == 0 ? null : payloadPointer + (int)nonceLength;

        return new CK_CCM_PARAMS
        {
            DataLen = (CK_ULONG)dataLength,
            Nonce = noncePointer,
            NonceLen = (CK_ULONG)nonceLength,
            Aad = aadPointer,
            AadLen = (CK_ULONG)aadLength,
            MacLen = (CK_ULONG)macLength,
        };
    }

    private static CK_GCM_PARAMS CreateGcmParams(byte* mechanismParameterPointer, int mechanismParameterLength)
    {
        int headerLength = IntPtr.Size * 4;
        if (mechanismParameterLength < headerLength)
        {
            throw new ArgumentException("CKM_AES_GCM parameters are incomplete.", nameof(mechanismParameterLength));
        }

        ReadOnlySpan<byte> parameter = new(mechanismParameterPointer, mechanismParameterLength);
        nuint ivLength = ReadPackedNuint(parameter);
        nuint ivBits = ReadPackedNuint(parameter[IntPtr.Size..]);
        nuint aadLength = ReadPackedNuint(parameter[(IntPtr.Size * 2)..]);
        nuint tagBits = ReadPackedNuint(parameter[(IntPtr.Size * 3)..]);
        nuint payloadLength = ivLength + aadLength;

        if (payloadLength > (nuint)(mechanismParameterLength - headerLength))
        {
            throw new ArgumentException("CKM_AES_GCM parameter payload is truncated.", nameof(mechanismParameterLength));
        }

        byte* payloadPointer = mechanismParameterPointer + headerLength;
        byte* ivPointer = ivLength == 0 ? null : payloadPointer;
        byte* aadPointer = aadLength == 0 ? null : payloadPointer + (int)ivLength;

        return new CK_GCM_PARAMS
        {
            Iv = ivPointer,
            IvLen = (CK_ULONG)ivLength,
            IvBits = (CK_ULONG)ivBits,
            Aad = aadPointer,
            AadLen = (CK_ULONG)aadLength,
            TagBits = (CK_ULONG)tagBits,
        };
    }

    private static CK_RSA_PKCS_OAEP_PARAMS CreateRsaOaepParams(byte* mechanismParameterPointer, int mechanismParameterLength)
    {
        int headerLength = IntPtr.Size * 4;
        if (mechanismParameterLength < headerLength)
        {
            throw new ArgumentException("CKM_RSA_PKCS_OAEP parameters are incomplete.", nameof(mechanismParameterLength));
        }

        ReadOnlySpan<byte> parameter = new(mechanismParameterPointer, mechanismParameterLength);
        nuint hashAlgorithm = ReadPackedNuint(parameter);
        nuint mgf = ReadPackedNuint(parameter[IntPtr.Size..]);
        nuint source = ReadPackedNuint(parameter[(IntPtr.Size * 2)..]);
        nuint sourceDataLength = ReadPackedNuint(parameter[(IntPtr.Size * 3)..]);

        if (sourceDataLength > (nuint)(mechanismParameterLength - headerLength))
        {
            throw new ArgumentException("CKM_RSA_PKCS_OAEP parameter payload is truncated.", nameof(mechanismParameterLength));
        }

        byte* payloadPointer = mechanismParameterPointer + headerLength;
        return new CK_RSA_PKCS_OAEP_PARAMS
        {
            HashAlg = new CK_MECHANISM_TYPE(hashAlgorithm),
            Mgf = new CK_RSA_PKCS_MGF_TYPE(mgf),
            Source = new CK_RSA_PKCS_OAEP_SOURCE_TYPE(source),
            SourceData = sourceDataLength == 0 ? null : payloadPointer,
            SourceDataLen = (CK_ULONG)sourceDataLength,
        };
    }

    private static CK_RSA_PKCS_PSS_PARAMS CreateRsaPssParams(byte* mechanismParameterPointer, int mechanismParameterLength)
    {
        int expectedLength = IntPtr.Size * 3;
        if (mechanismParameterLength < expectedLength)
        {
            throw new ArgumentException("CKM_RSA_PKCS_PSS parameters are incomplete.", nameof(mechanismParameterLength));
        }

        ReadOnlySpan<byte> parameter = new(mechanismParameterPointer, mechanismParameterLength);
        return new CK_RSA_PKCS_PSS_PARAMS
        {
            HashAlg = new CK_MECHANISM_TYPE(ReadPackedNuint(parameter)),
            Mgf = new CK_RSA_PKCS_MGF_TYPE(ReadPackedNuint(parameter[IntPtr.Size..])),
            SaltLen = (CK_ULONG)ReadPackedNuint(parameter[(IntPtr.Size * 2)..]),
        };
    }

    private static CK_ECDH1_DERIVE_PARAMS CreateEcdh1DeriveParams(byte* mechanismParameterPointer, int mechanismParameterLength)
    {
        int headerLength = IntPtr.Size * 3;
        if (mechanismParameterLength < headerLength)
        {
            throw new ArgumentException("CKM_ECDH1_DERIVE parameters are incomplete.", nameof(mechanismParameterLength));
        }

        ReadOnlySpan<byte> parameter = new(mechanismParameterPointer, mechanismParameterLength);
        nuint kdf = ReadPackedNuint(parameter);
        nuint sharedDataLength = ReadPackedNuint(parameter[IntPtr.Size..]);
        nuint publicDataLength = ReadPackedNuint(parameter[(IntPtr.Size * 2)..]);
        nuint payloadLength = sharedDataLength + publicDataLength;

        if (payloadLength > (nuint)(mechanismParameterLength - headerLength))
        {
            throw new ArgumentException("CKM_ECDH1_DERIVE parameter payload is truncated.", nameof(mechanismParameterLength));
        }

        byte* payloadPointer = mechanismParameterPointer + headerLength;
        byte* sharedDataPointer = sharedDataLength == 0 ? null : payloadPointer;
        byte* publicDataPointer = publicDataLength == 0 ? null : payloadPointer + (int)sharedDataLength;

        return new CK_ECDH1_DERIVE_PARAMS
        {
            Kdf = new CK_EC_KDF_TYPE(kdf),
            SharedDataLen = (CK_ULONG)sharedDataLength,
            SharedData = sharedDataPointer,
            PublicDataLen = (CK_ULONG)publicDataLength,
            PublicData = publicDataPointer,
        };
    }

    private static nuint ReadPackedNuint(ReadOnlySpan<byte> bytes)
        => MemoryMarshal.Read<nuint>(bytes[..IntPtr.Size]);

    private void InitializeMultiPartCryptOperation(
        CK_SESSION_HANDLE sessionHandle,
        CK_OBJECT_HANDLE keyHandle,
        CK_MECHANISM_TYPE mechanismType,
        ReadOnlySpan<byte> mechanismParameter,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_RV> init,
        string initOperation)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(initOperation, initOperation, sessionHandle: sessionHandle, mechanismType: mechanismType);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.MechanismParameters(mechanismType, mechanismParameter));
        }

        try
        {
            EnsureInitialized();

            if (init is null)
            {
                throw new InvalidOperationException($"The PKCS#11 function list does not expose {initOperation}.");
            }

            fixed (byte* mechanismParameterPointer = mechanismParameter)
            {
                CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length, out MarshalledMechanismParameters marshalledMechanismParameters);
                InitializeCryptOperation(sessionHandle, keyHandle, &mechanism, init, initOperation);
            }

            telemetry.Succeeded(CK_RV.Ok);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private void InitializeMultiPartDigestOperation(
        CK_SESSION_HANDLE sessionHandle,
        CK_MECHANISM_TYPE mechanismType,
        ReadOnlySpan<byte> mechanismParameter,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_RV> init,
        string initOperation)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(initOperation, initOperation, sessionHandle: sessionHandle, mechanismType: mechanismType);
        if (telemetry.IsEnabled)
        {
            telemetry.AddFields(Pkcs11TelemetryRedaction.MechanismParameters(mechanismType, mechanismParameter));
        }

        try
        {
            EnsureInitialized();

            if (init is null)
            {
                throw new InvalidOperationException($"The PKCS#11 function list does not expose {initOperation}.");
            }

            fixed (byte* mechanismParameterPointer = mechanismParameter)
            {
                CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length, out MarshalledMechanismParameters marshalledMechanismParameters);
                InitializeMechanismOperation(sessionHandle, &mechanism, init, initOperation);
            }

            telemetry.Succeeded(CK_RV.Ok);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private void EnsureUpdateFunction(delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> update, string updateOperation)
    {
        EnsureInitialized();

        if (update is null)
        {
            throw new InvalidOperationException($"The PKCS#11 function list does not expose {updateOperation}.");
        }
    }

    private void EnsureFinalFunction(delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG*, CK_RV> final, string finalOperation)
    {
        EnsureInitialized();

        if (final is null)
        {
            throw new InvalidOperationException($"The PKCS#11 function list does not expose {finalOperation}.");
        }
    }

    private void EnsureDataUpdateFunction(delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, CK_RV> update, string updateOperation)
    {
        EnsureInitialized();

        if (update is null)
        {
            throw new InvalidOperationException($"The PKCS#11 function list does not expose {updateOperation}.");
        }
    }

    private bool TryCryptUpdate(
        CK_SESSION_HANDLE sessionHandle,
        ReadOnlySpan<byte> input,
        Span<byte> output,
        out int written,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> update,
        string updateOperation,
        string outputName)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(updateOperation, updateOperation, sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("input", input));
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("output.destination", output.Length));
        }

        try
        {
            EnsureUpdateFunction(update, updateOperation);

            CK_ULONG outputLength = (CK_ULONG)(nuint)output.Length;
            CK_RV result;

            if (input.IsEmpty)
            {
                fixed (byte* outputPointer = output)
                {
                    result = update(sessionHandle, null, 0, outputPointer, &outputLength);
                }
            }
            else
            {
                fixed (byte* inputPointer = input)
                fixed (byte* outputPointer = output)
                {
                    result = update(sessionHandle, inputPointer, (CK_ULONG)(nuint)input.Length, outputPointer, &outputLength);
                }
            }

            if (result == Pkcs11ReturnValues.BufferTooSmall)
            {
                written = ToInt32Checked(outputLength, outputName);
                telemetry.ReturnedFalse(result);
                return false;
            }

            ThrowIfFailed(result, updateOperation);
            written = ToInt32Checked(outputLength, outputName);
            telemetry.Succeeded(result);
            return true;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private bool TryCryptFinal(
        CK_SESSION_HANDLE sessionHandle,
        Span<byte> output,
        out int written,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG*, CK_RV> final,
        string finalOperation,
        string outputName)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(finalOperation, finalOperation, sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("output.destination", output.Length));
        }

        try
        {
            EnsureFinalFunction(final, finalOperation);

            CK_ULONG outputLength = (CK_ULONG)(nuint)output.Length;
            CK_RV result;

            if (output.IsEmpty)
            {
                result = final(sessionHandle, null, &outputLength);
            }
            else
            {
                fixed (byte* outputPointer = output)
                {
                    result = final(sessionHandle, outputPointer, &outputLength);
                }
            }

            if (result == Pkcs11ReturnValues.BufferTooSmall)
            {
                written = ToInt32Checked(outputLength, outputName);
                telemetry.ReturnedFalse(result);
                return false;
            }

            ThrowIfFailed(result, finalOperation);
            written = ToInt32Checked(outputLength, outputName);
            telemetry.Succeeded(result);
            return true;
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private int GetCryptInvokeOutputLength(
        CK_SESSION_HANDLE sessionHandle,
        ReadOnlySpan<byte> input,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> invoke,
        string invokeOperation,
        string outputName)
    {
        Pkcs11OperationTelemetryScope telemetry = BeginTelemetry(invokeOperation, invokeOperation, sessionHandle: sessionHandle);
        if (telemetry.IsEnabled)
        {
            telemetry.AddField(Pkcs11TelemetryRedaction.LengthOnly("input", input));
        }

        try
        {
            EnsureUpdateFunction(invoke, invokeOperation);

            CK_ULONG outputLength = default;
            CK_RV result;

            if (input.IsEmpty)
            {
                result = invoke(sessionHandle, null, 0, null, &outputLength);
            }
            else
            {
                fixed (byte* inputPointer = input)
                {
                    result = invoke(sessionHandle, inputPointer, (CK_ULONG)(nuint)input.Length, null, &outputLength);
                }
            }

            ThrowIfFailed(result, invokeOperation);
            DrainActiveCryptOperation(sessionHandle, input, outputLength, invoke, invokeOperation, outputName);
            telemetry.Succeeded(result);
            return ToInt32Checked(outputLength, outputName);
        }
        catch (Exception ex)
        {
            telemetry.Failed(ex);
            throw;
        }
    }

    private static void EnsureCryptFunctions(
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_RV> init,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> invoke,
        string initOperation,
        string invokeOperation)
    {
        if (init is null)
        {
            throw new InvalidOperationException($"The PKCS#11 function list does not expose {initOperation}.");
        }

        if (invoke is null)
        {
            throw new InvalidOperationException($"The PKCS#11 function list does not expose {invokeOperation}.");
        }
    }

    private static void EnsureVerifyFunctions(
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_RV> init,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG, CK_RV> invoke,
        string initOperation,
        string invokeOperation)
    {
        if (init is null)
        {
            throw new InvalidOperationException($"The PKCS#11 function list does not expose {initOperation}.");
        }

        if (invoke is null)
        {
            throw new InvalidOperationException($"The PKCS#11 function list does not expose {invokeOperation}.");
        }
    }

    private static void EnsureMechanismFunctions(
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_RV> init,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> invoke,
        string initOperation,
        string invokeOperation)
    {
        if (init is null)
        {
            throw new InvalidOperationException($"The PKCS#11 function list does not expose {initOperation}.");
        }

        if (invoke is null)
        {
            throw new InvalidOperationException($"The PKCS#11 function list does not expose {invokeOperation}.");
        }
    }

    private static void InitializeCryptOperation(
        CK_SESSION_HANDLE sessionHandle,
        CK_OBJECT_HANDLE keyHandle,
        CK_MECHANISM* mechanism,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE, CK_RV> init,
        string initOperation)
    {
        CK_RV result = init(sessionHandle, mechanism, keyHandle);
        ThrowIfFailed(result, initOperation);
    }

    private static void InitializeMechanismOperation(
        CK_SESSION_HANDLE sessionHandle,
        CK_MECHANISM* mechanism,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_RV> init,
        string initOperation)
    {
        CK_RV result = init(sessionHandle, mechanism);
        ThrowIfFailed(result, initOperation);
    }

    private static void InvokeCrypt(
        CK_SESSION_HANDLE sessionHandle,
        ReadOnlySpan<byte> input,
        byte* outputPointer,
        CK_ULONG* outputLength,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> invoke,
        string invokeOperation)
    {
        CK_RV result;

        if (input.IsEmpty)
        {
            result = invoke(sessionHandle, null, 0, outputPointer, outputLength);
        }
        else
        {
            fixed (byte* inputPointer = input)
            {
                result = invoke(sessionHandle, inputPointer, (CK_ULONG)(nuint)input.Length, outputPointer, outputLength);
            }
        }

        ThrowIfFailed(result, invokeOperation);
    }

    private static bool InvokeVerify(
        CK_SESSION_HANDLE sessionHandle,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG, CK_RV> invoke,
        string invokeOperation)
    {
        CK_RV result;

        if (data.IsEmpty)
        {
            fixed (byte* signaturePointer = signature)
            {
                result = invoke(sessionHandle, null, 0, signaturePointer, (CK_ULONG)(nuint)signature.Length);
            }
        }
        else
        {
            fixed (byte* dataPointer = data)
            fixed (byte* signaturePointer = signature)
            {
                result = invoke(sessionHandle, dataPointer, (CK_ULONG)(nuint)data.Length, signaturePointer, (CK_ULONG)(nuint)signature.Length);
            }
        }

        if (result == Pkcs11ReturnValues.SignatureInvalid || result == Pkcs11ReturnValues.SignatureLenRange)
        {
            return false;
        }

        ThrowIfFailed(result, invokeOperation);
        return true;
    }

    private static void DrainActiveCryptOperation(
        CK_SESSION_HANDLE sessionHandle,
        ReadOnlySpan<byte> input,
        CK_ULONG requiredLength,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> invoke,
        string invokeOperation,
        string outputName)
    {
        int bufferLength = ToInt32Checked(requiredLength, outputName);
        byte[] rented = ArrayPool<byte>.Shared.Rent(Math.Max(bufferLength, 1));

        try
        {
            while (true)
            {
                CK_ULONG retryLength = (CK_ULONG)(nuint)bufferLength;
                CK_RV retryResult;

                fixed (byte* inputPointer = input)
                fixed (byte* outputPointer = rented)
                {
                    retryResult = invoke(sessionHandle, inputPointer, (CK_ULONG)(nuint)input.Length, outputPointer, &retryLength);
                }

                if (retryResult == Pkcs11ReturnValues.BufferTooSmall)
                {
                    int nextLength = ToInt32Checked(retryLength, outputName);
                    if (nextLength <= bufferLength)
                    {
                        throw new InvalidOperationException($"{invokeOperation} reported CKR_BUFFER_TOO_SMALL without increasing the required output length.");
                    }

                    ArrayPool<byte>.Shared.Return(rented);
                    bufferLength = nextLength;
                    rented = ArrayPool<byte>.Shared.Rent(bufferLength);
                    continue;
                }

                if (retryResult == Pkcs11ReturnValues.OperationNotInitialized)
                {
                    return;
                }

                ThrowIfFailed(retryResult, invokeOperation);
                return;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MarshalledMechanismParameters
    {
        public CK_ECDH1_DERIVE_PARAMS Ecdh1DeriveParams;
        public CK_AES_CTR_PARAMS CtrParams;
        public CK_GCM_PARAMS GcmParams;
        public CK_CCM_PARAMS CcmParams;
        public CK_RSA_PKCS_OAEP_PARAMS OaepParams;
        public CK_RSA_PKCS_PSS_PARAMS PssParams;
    }

    private static class Pkcs11SessionFlags
    {
        public const nuint ReadWriteSession = 0x00000002u;
        public const nuint SerialSession = 0x00000004u;
    }

    private static class Pkcs11SlotEventFlags
    {
        public const nuint DontBlock = 0x00000001u;
    }

    private static int ToInt32Checked(CK_ULONG value, string name)
    {
        nuint nativeValue = (nuint)value;
        if (nativeValue > int.MaxValue)
        {
            throw new InvalidOperationException($"The PKCS#11 {name} exceeds Int32.MaxValue.");
        }

        return (int)nativeValue;
    }

    private static void ThrowIfAttributeQueryFailed(CK_RV result, string operation)
    {
        if (result == CK_RV.Ok ||
            result == Pkcs11ReturnValues.AttributeSensitive ||
            result == Pkcs11ReturnValues.AttributeTypeInvalid)
        {
            return;
        }

        ThrowIfFailed(result, operation);
    }

    private static void ThrowIfBatchedAttributeQueryFailed(CK_RV result, string operation)
    {
        if (result == CK_RV.Ok ||
            result == Pkcs11ReturnValues.AttributeSensitive ||
            result == Pkcs11ReturnValues.AttributeTypeInvalid ||
            result == Pkcs11ReturnValues.BufferTooSmall)
        {
            return;
        }

        ThrowIfFailed(result, operation);
    }

    private static bool IsReadableAttributeLength(CK_ULONG valueLength)
        => (nuint)valueLength != Pkcs11NativeAttributeQuery.UnavailableInformation;

    private static Pkcs11NativeAttributeQuery CreateBatchedAttributeQuery(CK_RV queryResult, CK_RV readResult, CK_ULONG queriedLength, CK_ULONG readLength, int requestedLength)
    {
        nuint queriedLengthValue = (nuint)queriedLength;
        nuint readLengthValue = (nuint)readLength;

        if (queriedLengthValue == Pkcs11NativeAttributeQuery.UnavailableInformation || readLengthValue == Pkcs11NativeAttributeQuery.UnavailableInformation)
        {
            CK_RV result = queryResult == Pkcs11ReturnValues.AttributeTypeInvalid || readResult == Pkcs11ReturnValues.AttributeTypeInvalid
                ? Pkcs11ReturnValues.AttributeTypeInvalid
                : queryResult == Pkcs11ReturnValues.AttributeSensitive || readResult == Pkcs11ReturnValues.AttributeSensitive
                    ? Pkcs11ReturnValues.AttributeSensitive
                    : CK_RV.Ok;
            return new Pkcs11NativeAttributeQuery(result, Pkcs11NativeAttributeQuery.UnavailableInformation);
        }

        if (readResult == Pkcs11ReturnValues.BufferTooSmall && requestedLength < ToInt32Checked(readLength, "attribute length"))
        {
            return new Pkcs11NativeAttributeQuery(Pkcs11ReturnValues.BufferTooSmall, readLengthValue);
        }

        return new Pkcs11NativeAttributeQuery(CK_RV.Ok, readLengthValue);
    }

    internal static void ThrowIfFailed(CK_RV result, string operation)
    {
        if (!result.IsSuccess)
        {
            Pkcs11ErrorMetadata metadata = Pkcs11ReturnValueTaxonomy.Classify(result);
            throw new Pkcs11Exception(operation, result, metadata);
        }
    }
}

public readonly struct Pkcs11NativeAttributeValue
{
    public Pkcs11NativeAttributeValue(CK_ATTRIBUTE_TYPE type, Pkcs11NativeAttributeQuery query, byte[]? value)
    {
        Type = type;
        Query = query;
        Value = value;
    }

    public CK_ATTRIBUTE_TYPE Type { get; }

    public Pkcs11NativeAttributeQuery Query { get; }

    public byte[]? Value { get; }
}

public readonly struct Pkcs11NativeAttributeQuery
{
    public static readonly nuint UnavailableInformation = nuint.MaxValue;

    public Pkcs11NativeAttributeQuery(CK_RV result, nuint length)
    {
        Result = result;
        Length = length;
    }

    public CK_RV Result { get; }

    public nuint Length { get; }

    public bool IsBufferTooSmall => Result == Pkcs11ReturnValues.BufferTooSmall;

    public bool IsAttributeSensitive => Result == Pkcs11ReturnValues.AttributeSensitive;

    public bool IsAttributeTypeInvalid => Result == Pkcs11ReturnValues.AttributeTypeInvalid;

    public bool IsUnavailableInformation => Length == UnavailableInformation;

    public bool IsReadable => Result == CK_RV.Ok && !IsUnavailableInformation;
}
