using System.Buffers;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper.Native;

public sealed unsafe class Pkcs11NativeModule : IDisposable
{
    private const nuint Pkcs11Ecdh1DeriveMechanism = 0x00001050u;
    private readonly nint _handle;
    private readonly CK_FUNCTION_LIST* _functionList;
    private bool _disposed;
    private bool _isInitialized;
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

    public void Initialize()
    {
        EnsureNotDisposed();

        if (_isInitialized)
        {
            return;
        }

        if (FunctionList->C_Initialize is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_Initialize.");
        }

        CK_RV result = FunctionList->C_Initialize(null);
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

    public void FinalizeModule()
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

    public CK_INFO GetInfo()
    {
        EnsureInitialized();

        if (FunctionList->C_GetInfo is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_GetInfo.");
        }

        var info = default(CK_INFO);
        CK_RV result = FunctionList->C_GetInfo(&info);
        ThrowIfFailed(result, "C_GetInfo");
        return info;
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

        if (FunctionList->C_GetSlotInfo is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_GetSlotInfo.");
        }

        var slotInfo = default(CK_SLOT_INFO);
        CK_RV result = FunctionList->C_GetSlotInfo(slotId, &slotInfo);
        ThrowIfFailed(result, "C_GetSlotInfo");
        return slotInfo;
    }

    public bool TryGetTokenInfo(CK_SLOT_ID slotId, out CK_TOKEN_INFO tokenInfo)
    {
        EnsureInitialized();

        if (FunctionList->C_GetTokenInfo is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_GetTokenInfo.");
        }

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

        if (FunctionList->C_InitToken is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_InitToken.");
        }

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

        if (FunctionList->C_GetMechanismInfo is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_GetMechanismInfo.");
        }

        CK_MECHANISM_INFO info = default;
        CK_RV result = FunctionList->C_GetMechanismInfo(slotId, mechanismType, &info);
        ThrowIfFailed(result, "C_GetMechanismInfo");
        return info;
    }

    public CK_SESSION_HANDLE OpenSession(CK_SLOT_ID slotId, bool readWrite)
    {
        EnsureInitialized();

        if (FunctionList->C_OpenSession is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_OpenSession.");
        }

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

        if (FunctionList->C_CloseSession is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_CloseSession.");
        }

        CK_RV result = FunctionList->C_CloseSession(sessionHandle);
        ThrowIfFailed(result, "C_CloseSession");
    }

    public void CloseAllSessions(CK_SLOT_ID slotId)
    {
        EnsureInitialized();

        if (FunctionList->C_CloseAllSessions is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_CloseAllSessions.");
        }

        CK_RV result = FunctionList->C_CloseAllSessions(slotId);
        ThrowIfFailed(result, "C_CloseAllSessions");
    }

    public CK_SESSION_INFO GetSessionInfo(CK_SESSION_HANDLE sessionHandle)
    {
        EnsureInitialized();

        if (FunctionList->C_GetSessionInfo is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_GetSessionInfo.");
        }

        CK_SESSION_INFO sessionInfo = default;
        CK_RV result = FunctionList->C_GetSessionInfo(sessionHandle, &sessionInfo);
        ThrowIfFailed(result, "C_GetSessionInfo");
        return sessionInfo;
    }

    public void Login(CK_SESSION_HANDLE sessionHandle, CK_USER_TYPE userType, ReadOnlySpan<byte> pinUtf8)
    {
        EnsureInitialized();

        if (FunctionList->C_Login is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_Login.");
        }

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

        if (FunctionList->C_Logout is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_Logout.");
        }

        CK_RV result = FunctionList->C_Logout(sessionHandle);
        ThrowIfFailed(result, "C_Logout");
    }

    public void InitPin(CK_SESSION_HANDLE sessionHandle, ReadOnlySpan<byte> pinUtf8)
    {
        EnsureInitialized();

        if (FunctionList->C_InitPIN is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_InitPIN.");
        }

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

        if (FunctionList->C_SetPIN is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_SetPIN.");
        }

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

        if (FunctionList->C_FindObjectsInit is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_FindObjectsInit.");
        }

        if (FunctionList->C_FindObjects is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_FindObjects.");
        }

        if (FunctionList->C_FindObjectsFinal is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_FindObjectsFinal.");
        }

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

        if (FunctionList->C_GetAttributeValue is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_GetAttributeValue.");
        }

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

        if (FunctionList->C_CreateObject is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_CreateObject.");
        }

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

    public void SetAttributeValue(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE objectHandle, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        EnsureInitialized();

        if (FunctionList->C_SetAttributeValue is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_SetAttributeValue.");
        }

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

        if (FunctionList->C_DestroyObject is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_DestroyObject.");
        }

        CK_RV result = FunctionList->C_DestroyObject(sessionHandle, objectHandle);
        ThrowIfFailed(result, "C_DestroyObject");
    }

    public CK_OBJECT_HANDLE GenerateKey(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, ReadOnlySpan<CK_ATTRIBUTE> template)
    {
        EnsureInitialized();

        if (FunctionList->C_GenerateKey is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_GenerateKey.");
        }

        CK_OBJECT_HANDLE keyHandle = default;
        fixed (byte* mechanismParameterPointer = mechanismParameter)
        {
            CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length);
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

        if (FunctionList->C_GenerateKeyPair is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_GenerateKeyPair.");
        }

        CK_OBJECT_HANDLE publicKeyHandle = default;
        CK_OBJECT_HANDLE privateKeyHandle = default;
        fixed (byte* mechanismParameterPointer = mechanismParameter)
        {
            CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length);
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

        if (FunctionList->C_WrapKey is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_WrapKey.");
        }

        CK_ULONG wrappedKeyLength = default;
        fixed (byte* mechanismParameterPointer = mechanismParameter)
        {
            CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length);
            CK_RV result = FunctionList->C_WrapKey(sessionHandle, &mechanism, wrappingKeyHandle, keyHandle, null, &wrappedKeyLength);
            ThrowIfFailed(result, "C_WrapKey");
        }

        return ToInt32Checked(wrappedKeyLength, "wrapped key length");
    }

    public bool TryWrapKey(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE wrappingKeyHandle, CK_MECHANISM_TYPE mechanismType, ReadOnlySpan<byte> mechanismParameter, CK_OBJECT_HANDLE keyHandle, Span<byte> wrappedKey, out int written)
    {
        EnsureInitialized();

        if (FunctionList->C_WrapKey is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_WrapKey.");
        }

        CK_ULONG wrappedKeyLength = (CK_ULONG)(nuint)wrappedKey.Length;

        fixed (byte* mechanismParameterPointer = mechanismParameter)
        fixed (byte* wrappedKeyPointer = wrappedKey)
        {
            CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length);
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

        if (FunctionList->C_UnwrapKey is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_UnwrapKey.");
        }

        CK_OBJECT_HANDLE keyHandle = default;
        fixed (byte* mechanismParameterPointer = mechanismParameter)
        fixed (byte* wrappedKeyPointer = wrappedKey)
        fixed (CK_ATTRIBUTE* templatePointer = template)
        {
            CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length);
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

        if (FunctionList->C_DeriveKey is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_DeriveKey.");
        }

        CK_OBJECT_HANDLE keyHandle = default;
        fixed (byte* mechanismParameterPointer = mechanismParameter)
        fixed (CK_ATTRIBUTE* templatePointer = template)
        {
            CK_ECDH1_DERIVE_PARAMS ecdh1DeriveParams = default;
            CK_MECHANISM mechanism = CreateDeriveMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length, out ecdh1DeriveParams);
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

    private static CK_MECHANISM CreateDeriveMechanism(CK_MECHANISM_TYPE mechanismType, byte* mechanismParameterPointer, int mechanismParameterLength, out CK_ECDH1_DERIVE_PARAMS ecdh1DeriveParams)
    {
        if ((nuint)mechanismType.Value != Pkcs11Ecdh1DeriveMechanism)
        {
            ecdh1DeriveParams = default;
            return CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameterLength);
        }

        ecdh1DeriveParams = CreateEcdh1DeriveParams(mechanismParameterPointer, mechanismParameterLength);
        return new CK_MECHANISM
        {
            Mechanism = mechanismType,
            Parameter = Unsafe.AsPointer(ref ecdh1DeriveParams),
            ParameterLength = (CK_ULONG)(nuint)sizeof(CK_ECDH1_DERIVE_PARAMS),
        };
    }

    public nuint GetObjectSize(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE objectHandle)
    {
        EnsureInitialized();

        if (FunctionList->C_GetObjectSize is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_GetObjectSize.");
        }

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
            CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length);
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

        if (FunctionList->C_VerifyFinal is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_VerifyFinal.");
        }

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

        if (FunctionList->C_GenerateRandom is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_GenerateRandom.");
        }

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

        if (FunctionList->C_GetOperationState is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_GetOperationState.");
        }

        CK_ULONG stateLength = default;
        CK_RV result = FunctionList->C_GetOperationState(sessionHandle, null, &stateLength);
        ThrowIfFailed(result, "C_GetOperationState");
        return ToInt32Checked(stateLength, "operation state length");
    }

    public bool TryGetOperationState(CK_SESSION_HANDLE sessionHandle, Span<byte> destination, out int written)
    {
        EnsureInitialized();

        if (FunctionList->C_GetOperationState is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_GetOperationState.");
        }

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

        if (FunctionList->C_SetOperationState is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_SetOperationState.");
        }

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

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

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
            _disposed = true;
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

    private void InvokeFinalize()
    {
        if (FunctionList->C_Finalize is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_Finalize.");
        }

        CK_RV result = FunctionList->C_Finalize(null);
        if (result == Pkcs11ReturnValues.CryptokiNotInitialized)
        {
            return;
        }

        ThrowIfFailed(result, "C_Finalize");
    }

    private CK_RV GetSlotList(bool tokenPresentOnly, CK_SLOT_ID* slotList, CK_ULONG* count)
    {
        if (FunctionList->C_GetSlotList is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_GetSlotList.");
        }

        CK_BBOOL tokenPresent = tokenPresentOnly ? CK_BBOOL.True : CK_BBOOL.False;
        return FunctionList->C_GetSlotList(tokenPresent, slotList, count);
    }

    private CK_RV GetMechanismList(CK_SLOT_ID slotId, CK_MECHANISM_TYPE* mechanismList, CK_ULONG* count)
    {
        if (FunctionList->C_GetMechanismList is null)
        {
            throw new InvalidOperationException("The PKCS#11 function list does not expose C_GetMechanismList.");
        }

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
            CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length);
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
            CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length);
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
            CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length);
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
            CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length);
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

    private static CK_MECHANISM CreateMechanism(CK_MECHANISM_TYPE mechanismType, byte* mechanismParameterPointer, int mechanismParameterLength)
        => new()
        {
            Mechanism = mechanismType,
            Parameter = mechanismParameterLength == 0 ? null : mechanismParameterPointer,
            ParameterLength = (CK_ULONG)(nuint)mechanismParameterLength,
        };

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
            CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length);
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
            CK_MECHANISM mechanism = CreateMechanism(mechanismType, mechanismParameterPointer, mechanismParameter.Length);
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

    private static class Pkcs11SessionFlags
    {
        public const nuint ReadWriteSession = 0x00000002u;
        public const nuint SerialSession = 0x00000004u;
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
            throw new Pkcs11Exception(operation, result);
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

    public bool IsUnavailableInformation => Length == UnavailableInformation;

    public bool IsReadable => Result == CK_RV.Ok && !IsUnavailableInformation;
}
