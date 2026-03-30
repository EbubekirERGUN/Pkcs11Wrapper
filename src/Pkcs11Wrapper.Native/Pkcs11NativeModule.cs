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
    private readonly object _lifecycleSync = new();
    private volatile bool _disposed;
    private volatile bool _isInitialized;
    private bool _ownsInitialization;

    private Pkcs11NativeModule(nint handle, CK_FUNCTION_LIST* functionList)
    {
        _handle = handle;
        _functionList = functionList;
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

    public static Pkcs11NativeModule Load(string libraryPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(libraryPath);

        nint handle = NativeLibrary.Load(libraryPath);

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

            return new Pkcs11NativeModule(handle, functionList);
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
            EnsureNotDisposed();

            if (_isInitialized)
            {
                return;
            }

            EnsureFunctionAvailable((void*)FunctionList->C_Initialize, "C_Initialize");

            CK_RV result = FunctionList->C_Initialize(initializeArgs);
            if (result == Pkcs11ReturnValues.CryptokiAlreadyInitialized)
            {
                _isInitialized = true;
                _ownsInitialization = false;
                return;
            }

            ThrowIfFailed(result, "C_Initialize");
            _isInitialized = true;
            _ownsInitialization = true;
        }
    }

    public void FinalizeModule()
    {
        lock (_lifecycleSync)
        {
            EnsureNotDisposed();

            if (!_isInitialized)
            {
                return;
            }

            if (_ownsInitialization)
            {
                InvokeFinalize();
            }

            _isInitialized = false;
            _ownsInitialization = false;
        }
    }

    public CK_INFO GetInfo()
    {
        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_GetInfo, "C_GetInfo");

        var info = default(CK_INFO);
        CK_RV result = FunctionList->C_GetInfo(&info);
        ThrowIfFailed(result, "C_GetInfo");
        return info;
    }

    public CK_VERSION GetFunctionListVersion()
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

        return functionList->Version;
    }

    public int GetSlotCount(bool tokenPresentOnly)
    {
        EnsureInitialized();

        CK_ULONG count = default;
        CK_RV result = GetSlotList(tokenPresentOnly, null, &count);
        ThrowIfFailed(result, "C_GetSlotList");
        return ToInt32Checked(count, "slot count");
    }

    public bool TryGetSlots(Span<CK_SLOT_ID> destination, out int written, bool tokenPresentOnly)
    {
        EnsureInitialized();

        CK_ULONG count = default;
        CK_RV result = GetSlotList(tokenPresentOnly, null, &count);
        ThrowIfFailed(result, "C_GetSlotList");

        int required = ToInt32Checked(count, "slot count");
        if (destination.Length < required)
        {
            written = required;
            return false;
        }

        if (required == 0)
        {
            written = 0;
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
            return false;
        }

        ThrowIfFailed(result, "C_GetSlotList");
        written = ToInt32Checked(count, "slot count");
        return true;
    }

    public CK_SLOT_INFO GetSlotInfo(CK_SLOT_ID slotId)
    {
        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_GetSlotInfo, "C_GetSlotInfo");

        var slotInfo = default(CK_SLOT_INFO);
        CK_RV result = FunctionList->C_GetSlotInfo(slotId, &slotInfo);
        ThrowIfFailed(result, "C_GetSlotInfo");
        return slotInfo;
    }

    public bool TryGetTokenInfo(CK_SLOT_ID slotId, out CK_TOKEN_INFO tokenInfo)
    {
        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_GetTokenInfo, "C_GetTokenInfo");

        CK_TOKEN_INFO nativeTokenInfo = default;
        CK_RV result = FunctionList->C_GetTokenInfo(slotId, &nativeTokenInfo);
        if (result == Pkcs11ReturnValues.TokenNotPresent)
        {
            tokenInfo = default;
            return false;
        }

        ThrowIfFailed(result, "C_GetTokenInfo");
        tokenInfo = nativeTokenInfo;
        return true;
    }

    public void InitToken(CK_SLOT_ID slotId, ReadOnlySpan<byte> soPinUtf8, ReadOnlySpan<byte> label)
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
    }

    public int GetMechanismCount(CK_SLOT_ID slotId)
    {
        EnsureInitialized();

        CK_ULONG count = default;
        CK_RV result = GetMechanismList(slotId, null, &count);
        ThrowIfFailed(result, "C_GetMechanismList");
        return ToInt32Checked(count, "mechanism count");
    }

    public bool TryGetMechanisms(CK_SLOT_ID slotId, Span<CK_MECHANISM_TYPE> destination, out int written)
    {
        EnsureInitialized();

        CK_ULONG count = default;
        CK_RV result = GetMechanismList(slotId, null, &count);
        ThrowIfFailed(result, "C_GetMechanismList");

        int required = ToInt32Checked(count, "mechanism count");
        if (destination.Length < required)
        {
            written = required;
            return false;
        }

        if (required == 0)
        {
            written = 0;
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
            return false;
        }

        ThrowIfFailed(result, "C_GetMechanismList");
        written = ToInt32Checked(count, "mechanism count");
        return true;
    }

    public CK_MECHANISM_INFO GetMechanismInfo(CK_SLOT_ID slotId, CK_MECHANISM_TYPE mechanismType)
    {
        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_GetMechanismInfo, "C_GetMechanismInfo");

        CK_MECHANISM_INFO info = default;
        CK_RV result = FunctionList->C_GetMechanismInfo(slotId, mechanismType, &info);
        ThrowIfFailed(result, "C_GetMechanismInfo");
        return info;
    }

    public CK_SESSION_HANDLE OpenSession(CK_SLOT_ID slotId, bool readWrite)
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
        return sessionHandle;
    }

    public void CloseSession(CK_SESSION_HANDLE sessionHandle)
    {
        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_CloseSession, "C_CloseSession");

        CK_RV result = FunctionList->C_CloseSession(sessionHandle);
        ThrowIfFailed(result, "C_CloseSession");
    }

    public void CloseAllSessions(CK_SLOT_ID slotId)
    {
        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_CloseAllSessions, "C_CloseAllSessions");

        CK_RV result = FunctionList->C_CloseAllSessions(slotId);
        ThrowIfFailed(result, "C_CloseAllSessions");
    }

    public CK_SESSION_INFO GetSessionInfo(CK_SESSION_HANDLE sessionHandle)
    {
        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_GetSessionInfo, "C_GetSessionInfo");

        CK_SESSION_INFO sessionInfo = default;
        CK_RV result = FunctionList->C_GetSessionInfo(sessionHandle, &sessionInfo);
        ThrowIfFailed(result, "C_GetSessionInfo");
        return sessionInfo;
    }

    public void Login(CK_SESSION_HANDLE sessionHandle, CK_USER_TYPE userType, ReadOnlySpan<byte> pinUtf8)
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
    }

    public void Logout(CK_SESSION_HANDLE sessionHandle)
    {
        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_Logout, "C_Logout");

        CK_RV result = FunctionList->C_Logout(sessionHandle);
        ThrowIfFailed(result, "C_Logout");
    }

    public void InitPin(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> pinUtf8)
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
    }

    public void SetPin(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> oldPinUtf8, ReadOnlySpan<byte> newPinUtf8)
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
    }

    public bool TryFindObjects(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<CK_ATTRIBUTE> template, Span<CK_OBJECT_HANDLE> destination, out int written, out bool hasMore)
    {
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
                return true;
            }

            CK_OBJECT_HANDLE extraObject = default;
            CK_ULONG extraFound = default;
            CK_RV extraFindResult = FunctionList->C_FindObjects(sessionHandle, &extraObject, 1, &extraFound);
            ThrowIfFailed(extraFindResult, "C_FindObjects");

            hasMore = extraFound.Value != 0;
            return !hasMore;
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
        return new Pkcs11NativeAttributeQuery(result, (nuint)attribute.ValueLength);
    }

    public bool TryGetAttributeValue(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE objectHandle, CK_ATTRIBUTE_TYPE attributeType, Span<byte> destination, out int written, out Pkcs11NativeAttributeQuery query)
    {
        query = QueryAttributeValue(sessionHandle, objectHandle, attributeType);
        if (!query.IsReadable)
        {
            written = 0;
            return false;
        }

        if (query.IsUnavailableInformation)
        {
            written = 0;
            return false;
        }

        int requiredLength = ToInt32Checked(new CK_ULONG(query.Length), "attribute length");
        if (destination.Length < requiredLength)
        {
            written = requiredLength;
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
            return false;
        }

        ThrowIfAttributeQueryFailed(result, "C_GetAttributeValue");
        written = ToInt32Checked(attribute.ValueLength, "attribute length");
        query = new Pkcs11NativeAttributeQuery(result, (nuint)attribute.ValueLength);
        return true;
    }

    public CK_OBJECT_HANDLE CreateObject(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<CK_ATTRIBUTE> template)
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
        return objectHandle;
    }

    public CK_OBJECT_HANDLE CopyObject(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE sourceObjectHandle, ReadOnlySpan<CK_ATTRIBUTE> template)
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
        return objectHandle;
    }

    public void SetAttributeValue(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE objectHandle, ReadOnlySpan<CK_ATTRIBUTE> template)
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
    }

    public void DestroyObject(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE objectHandle)
    {
        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_DestroyObject, "C_DestroyObject");

        CK_RV result = FunctionList->C_DestroyObject(sessionHandle, objectHandle);
        ThrowIfFailed(result, "C_DestroyObject");
    }

    public CK_OBJECT_HANDLE GenerateKey(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<CK_ATTRIBUTE> template)
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
        }

        return keyHandle;
    }

    public (CK_OBJECT_HANDLE PublicKeyHandle, CK_OBJECT_HANDLE PrivateKeyHandle) GenerateKeyPair(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<CK_ATTRIBUTE> publicKeyTemplate, ReadOnlySpan<CK_ATTRIBUTE> privateKeyTemplate)
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
            }
        }

        return (publicKeyHandle, privateKeyHandle);
    }

    public int GetWrapKeyOutputLength(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE wrappingKeyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, CK_OBJECT_HANDLE keyHandle)
    {
        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_WrapKey, "C_WrapKey");

        CK_ULONG wrappedKeyLength = default;
        fixed (byte* mechanismParameterPointer = mechanismParameter)
        {
            CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length, out MarshalledMechanismParameters marshalledMechanismParameters);
            CK_RV result = FunctionList->C_WrapKey(sessionHandle, &mechanism, wrappingKeyHandle, keyHandle, null, &wrappedKeyLength);
            ThrowIfFailed(result, "C_WrapKey");
        }

        return ToInt32Checked(wrappedKeyLength, "wrapped key length");
    }

    public bool TryWrapKey(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE wrappingKeyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, CK_OBJECT_HANDLE keyHandle, Span<byte> wrappedKey, out int written)
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
                return false;
            }

            ThrowIfFailed(result, "C_WrapKey");
        }

        written = ToInt32Checked(wrappedKeyLength, "wrapped key length");
        return true;
    }

    public CK_OBJECT_HANDLE UnwrapKey(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE unwrappingKeyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<byte> wrappedKey, ReadOnlySpan<CK_ATTRIBUTE> template)
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
        }

        return keyHandle;
    }

    public CK_OBJECT_HANDLE DeriveKey(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE baseKeyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<CK_ATTRIBUTE> template)
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
        }

        return keyHandle;
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
        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_GetObjectSize, "C_GetObjectSize");

        CK_ULONG objectSize = default;
        CK_RV result = FunctionList->C_GetObjectSize(sessionHandle, objectHandle, &objectSize);
        ThrowIfFailed(result, "C_GetObjectSize");
        return (nuint)objectSize;
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
        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_DigestKey, "C_DigestKey");

        CK_RV result = FunctionList->C_DigestKey(sessionHandle, keyHandle);
        ThrowIfFailed(result, "C_DigestKey");
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
        EnsureInitialized();
        EnsureVerifyFunctions(FunctionList->C_VerifyInit, FunctionList->C_Verify, "C_VerifyInit", "C_Verify");

        fixed (byte* mechanismParameterPointer = mechanismParameter)
        {
            CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length, out MarshalledMechanismParameters marshalledMechanismParameters);
            InitializeCryptOperation(sessionHandle, keyHandle, &mechanism, FunctionList->C_VerifyInit, "C_VerifyInit");
            return InvokeVerify(sessionHandle, data, signature, FunctionList->C_Verify, "C_Verify");
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
        EnsureDataUpdateFunction(FunctionList->C_SignUpdate, "C_SignUpdate");

        if (data.IsEmpty)
        {
            return;
        }

        CK_RV result;
        fixed (byte* dataPointer = data)
        {
            result = FunctionList->C_SignUpdate(sessionHandle, dataPointer, (CK_ULONG)(nuint)data.Length);
        }

        ThrowIfFailed(result, "C_SignUpdate");
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
        EnsureDataUpdateFunction(FunctionList->C_VerifyUpdate, "C_VerifyUpdate");

        if (data.IsEmpty)
        {
            return;
        }

        CK_RV result;
        fixed (byte* dataPointer = data)
        {
            result = FunctionList->C_VerifyUpdate(sessionHandle, dataPointer, (CK_ULONG)(nuint)data.Length);
        }

        ThrowIfFailed(result, "C_VerifyUpdate");
    }

    public bool VerifyFinal(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> signature)
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
            return false;
        }

        ThrowIfFailed(result, "C_VerifyFinal");
        return true;
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
        EnsureDataUpdateFunction(FunctionList->C_DigestUpdate, "C_DigestUpdate");

        if (data.IsEmpty)
        {
            return;
        }

        CK_RV result;
        fixed (byte* dataPointer = data)
        {
            result = FunctionList->C_DigestUpdate(sessionHandle, dataPointer, (CK_ULONG)(nuint)data.Length);
        }

        ThrowIfFailed(result, "C_DigestUpdate");
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
    }

    public void SeedRandom(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> seed)
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
    }

    public CK_SLOT_ID WaitForSlotEvent()
    {
        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_WaitForSlotEvent, "C_WaitForSlotEvent");

        CK_SLOT_ID slotId = default;
        CK_RV result = FunctionList->C_WaitForSlotEvent(new CK_FLAGS(0), &slotId, null);
        ThrowIfFailed(result, "C_WaitForSlotEvent");
        return slotId;
    }

    public bool TryWaitForSlotEvent(out CK_SLOT_ID slotId)
    {
        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_WaitForSlotEvent, "C_WaitForSlotEvent");

        CK_SLOT_ID nativeSlotId = default;
        CK_RV result = FunctionList->C_WaitForSlotEvent(new CK_FLAGS(Pkcs11SlotEventFlags.DontBlock), &nativeSlotId, null);
        if (result == Pkcs11ReturnValues.NoEvent)
        {
            slotId = default;
            return false;
        }

        ThrowIfFailed(result, "C_WaitForSlotEvent");
        slotId = nativeSlotId;
        return true;
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
        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_GetOperationState, "C_GetOperationState");

        CK_ULONG stateLength = default;
        CK_RV result = FunctionList->C_GetOperationState(sessionHandle, null, &stateLength);
        ThrowIfFailed(result, "C_GetOperationState");
        return ToInt32Checked(stateLength, "operation state length");
    }

    public bool TryGetOperationState(CK_SESSION_HANDLE sessionHandle, Span<byte> destination, out int written)
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
            return false;
        }

        ThrowIfFailed(result, "C_GetOperationState");
        written = ToInt32Checked(stateLength, "operation state length");
        return true;
    }

    public void SetOperationState(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> state, CK_OBJECT_HANDLE encryptionKeyHandle, CK_OBJECT_HANDLE authenticationKeyHandle)
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
    }

    public bool TryGetFunctionStatus(CK_SESSION_HANDLE sessionHandle)
    {
        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_GetFunctionStatus, "C_GetFunctionStatus");

        CK_RV result = FunctionList->C_GetFunctionStatus(sessionHandle);
        if (result == Pkcs11ReturnValues.FunctionNotParallel || result == Pkcs11ReturnValues.FunctionNotSupported)
        {
            return false;
        }

        ThrowIfFailed(result, "C_GetFunctionStatus");
        return true;
    }

    public bool TryCancelFunction(CK_SESSION_HANDLE sessionHandle)
    {
        EnsureInitialized();

        EnsureFunctionAvailable((void*)FunctionList->C_CancelFunction, "C_CancelFunction");

        CK_RV result = FunctionList->C_CancelFunction(sessionHandle);
        if (result == Pkcs11ReturnValues.FunctionNotParallel || result == Pkcs11ReturnValues.FunctionNotSupported)
        {
            return false;
        }

        ThrowIfFailed(result, "C_CancelFunction");
        return true;
    }

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

        return ToInt32Checked(outputLength, outputName);
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

        return ToInt32Checked(outputLength, outputName);
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
                return false;
            }

            ThrowIfFailed(result, invokeOperation);
            written = ToInt32Checked(outputLength, outputName);
            return true;
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
                return false;
            }

            ThrowIfFailed(result, invokeOperation);
            written = ToInt32Checked(outputLength, outputName);
            return true;
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
    }

    private void InitializeMultiPartDigestOperation(
        CK_SESSION_HANDLE sessionHandle,
        CK_MECHANISM_TYPE mechanismType,
        ReadOnlySpan<byte> mechanismParameter,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, CK_MECHANISM*, CK_RV> init,
        string initOperation)
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
            return false;
        }

        ThrowIfFailed(result, updateOperation);
        written = ToInt32Checked(outputLength, outputName);
        return true;
    }

    private bool TryCryptFinal(
        CK_SESSION_HANDLE sessionHandle,
        Span<byte> output,
        out int written,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG*, CK_RV> final,
        string finalOperation,
        string outputName)
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
            return false;
        }

        ThrowIfFailed(result, finalOperation);
        written = ToInt32Checked(outputLength, outputName);
        return true;
    }

    private int GetCryptInvokeOutputLength(
        CK_SESSION_HANDLE sessionHandle,
        ReadOnlySpan<byte> input,
        delegate* unmanaged[Cdecl]<CK_SESSION_HANDLE, byte*, CK_ULONG, byte*, CK_ULONG*, CK_RV> invoke,
        string invokeOperation,
        string outputName)
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
        return ToInt32Checked(outputLength, outputName);
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

    internal static void ThrowIfFailed(CK_RV result, string operation)
    {
        if (!result.IsSuccess)
        {
            Pkcs11ErrorMetadata metadata = Pkcs11ReturnValueTaxonomy.Classify(result);
            throw new Pkcs11Exception(operation, result, metadata);
        }
    }
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
