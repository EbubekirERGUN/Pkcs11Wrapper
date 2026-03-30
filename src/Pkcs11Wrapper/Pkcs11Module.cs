using System.Buffers;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Pkcs11Wrapper.Native;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper;

public sealed class Pkcs11Module : IDisposable
{
    private static readonly CK_RV BufferTooSmallResult = Pkcs11ResultCodes.BufferTooSmall;
    private static readonly CK_RV AttributeSensitiveResult = Pkcs11ResultCodes.AttributeSensitive;
    private static readonly CK_RV AttributeTypeInvalidResult = Pkcs11ResultCodes.AttributeTypeInvalid;
    private readonly Pkcs11NativeModule _nativeModule;
    private readonly object _lifecycleSync = new();
    private readonly object _sessionStateLock = new();
    private readonly Dictionary<Pkcs11SlotId, int> _slotSessionGenerations = [];
    private int _sessionGeneration;
    private bool _disposed;

    private Pkcs11Module(Pkcs11NativeModule nativeModule) => _nativeModule = nativeModule;

    public CK_VERSION CryptokiVersion => _nativeModule.CryptokiVersion;

    public static Pkcs11Module Load(string libraryPath) => new(Pkcs11NativeModule.Load(libraryPath));

    public void Initialize()
    {
        lock (_lifecycleSync)
        {
            ThrowIfDisposed();
            _nativeModule.Initialize();
        }
    }

    public void FinalizeModule()
    {
        lock (_lifecycleSync)
        {
            ThrowIfDisposed();
            bool wasInitialized = _nativeModule.IsInitialized;
            _nativeModule.FinalizeModule();

            if (wasInitialized)
            {
                lock (_sessionStateLock)
                {
                    _sessionGeneration++;
                }
            }
        }
    }

    public Pkcs11ModuleInfo GetInfo() => Pkcs11ModuleInfo.FromNative(_nativeModule.GetInfo());

    public int GetSlotCount(bool tokenPresentOnly = false) => _nativeModule.GetSlotCount(tokenPresentOnly);

    public bool TryGetSlots(Span<Pkcs11SlotId> destination, out int written, bool tokenPresentOnly = false)
    {
        Span<CK_SLOT_ID> nativeDestination = MemoryMarshal.Cast<Pkcs11SlotId, CK_SLOT_ID>(destination);
        return _nativeModule.TryGetSlots(nativeDestination, out written, tokenPresentOnly);
    }

    public Pkcs11SlotId WaitForSlotEvent()
    {
        ThrowIfDisposed();
        return new Pkcs11SlotId((nuint)_nativeModule.WaitForSlotEvent().Value);
    }

    public bool TryWaitForSlotEvent(out Pkcs11SlotId slotId)
    {
        ThrowIfDisposed();

        if (_nativeModule.TryWaitForSlotEvent(out CK_SLOT_ID nativeSlotId))
        {
            slotId = new Pkcs11SlotId((nuint)nativeSlotId.Value);
            return true;
        }

        slotId = default;
        return false;
    }

    public Pkcs11SlotInfo GetSlotInfo(Pkcs11SlotId slotId) => Pkcs11SlotInfo.FromNative(_nativeModule.GetSlotInfo(slotId.NativeValue));

    public bool TryGetTokenInfo(Pkcs11SlotId slotId, out Pkcs11TokenInfo tokenInfo)
    {
        if (_nativeModule.TryGetTokenInfo(slotId.NativeValue, out CK_TOKEN_INFO nativeInfo))
        {
            tokenInfo = Pkcs11TokenInfo.FromNative(nativeInfo);
            return true;
        }

        tokenInfo = default;
        return false;
    }

    public void InitToken(Pkcs11SlotId slotId, ReadOnlySpan<byte> soPin, ReadOnlySpan<byte> label)
    {
        lock (_lifecycleSync)
        {
            ThrowIfDisposed();

            if (label.Length > 32)
            {
                throw new ArgumentException("The PKCS#11 token label cannot exceed 32 bytes before blank padding.", nameof(label));
            }

            Span<byte> paddedLabel = stackalloc byte[32];
            paddedLabel.Fill((byte)' ');
            label.CopyTo(paddedLabel);

            if (GetSlotInfo(slotId).Flags.HasFlag(Pkcs11SlotFlags.TokenPresent))
            {
                _nativeModule.CloseAllSessions(slotId.NativeValue);
                IncrementSlotSessionGeneration(slotId);
            }

            _nativeModule.InitToken(slotId.NativeValue, soPin, paddedLabel);
            IncrementSlotSessionGeneration(slotId);
        }
    }

    public int GetMechanismCount(Pkcs11SlotId slotId) => _nativeModule.GetMechanismCount(slotId.NativeValue);

    public bool TryGetMechanisms(Pkcs11SlotId slotId, Span<Pkcs11MechanismType> destination, out int written)
    {
        Span<CK_MECHANISM_TYPE> nativeDestination = MemoryMarshal.Cast<Pkcs11MechanismType, CK_MECHANISM_TYPE>(destination);
        return _nativeModule.TryGetMechanisms(slotId.NativeValue, nativeDestination, out written);
    }

    public Pkcs11MechanismInfo GetMechanismInfo(Pkcs11SlotId slotId, Pkcs11MechanismType mechanismType)
        => Pkcs11MechanismInfo.FromNative(_nativeModule.GetMechanismInfo(slotId.NativeValue, mechanismType.NativeValue));

    public Pkcs11Session OpenSession(Pkcs11SlotId slotId, bool readWrite = false)
    {
        lock (_lifecycleSync)
        {
            ThrowIfDisposed();

            int generation;
            int slotGeneration;
            lock (_sessionStateLock)
            {
                generation = _sessionGeneration;
                slotGeneration = _slotSessionGenerations.GetValueOrDefault(slotId);
            }

            CK_SESSION_HANDLE sessionHandle = _nativeModule.OpenSession(slotId.NativeValue, readWrite);
            return new Pkcs11Session(this, generation, slotId, slotGeneration, sessionHandle, readWrite);
        }
    }

    public void CloseAllSessions(Pkcs11SlotId slotId)
    {
        lock (_lifecycleSync)
        {
            ThrowIfDisposed();
            _nativeModule.CloseAllSessions(slotId.NativeValue);
            IncrementSlotSessionGeneration(slotId);
        }
    }

    public void Dispose()
    {
        lock (_lifecycleSync)
        {
            lock (_sessionStateLock)
            {
                if (_disposed)
                {
                    return;
                }

                _disposed = true;
                _sessionGeneration++;
            }

            _nativeModule.Dispose();
        }
    }

    internal Pkcs11SessionInfo GetSessionInfo(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return Pkcs11SessionInfo.FromNative(_nativeModule.GetSessionInfo(sessionHandle));
    }

    internal void Login(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11UserType userType, ReadOnlySpan<byte> pinUtf8)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.Login(sessionHandle, userType.ToNative(), pinUtf8);
    }

    internal void Logout(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.Logout(sessionHandle);
    }

    internal void InitPin(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> pinUtf8)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.InitPin(sessionHandle, pinUtf8);
    }

    internal void SetPin(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> oldPinUtf8, ReadOnlySpan<byte> newPinUtf8)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.SetPin(sessionHandle, oldPinUtf8, newPinUtf8);
    }

    internal unsafe bool TryFindObjects(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectSearchParameters search, Span<Pkcs11ObjectHandle> destination, out int written, out bool hasMore)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);

        Span<CK_ATTRIBUTE> template = stackalloc CK_ATTRIBUTE[10];
        int attributeCount = 0;
        CK_OBJECT_CLASS objectClass = default;
        CK_KEY_TYPE keyType = default;
        CK_BBOOL requireEncrypt = default;
        CK_BBOOL requireDecrypt = default;
        CK_BBOOL requireSign = default;
        CK_BBOOL requireVerify = default;
        CK_BBOOL requireWrap = default;
        CK_BBOOL requireUnwrap = default;

        fixed (byte* labelPointer = search.Label)
        fixed (byte* idPointer = search.Id)
        {
            if (!search.Label.IsEmpty)
            {
                template[attributeCount++] = CreateAttribute(Pkcs11AttributeTypes.Label.NativeValue, labelPointer, search.Label.Length);
            }

            if (!search.Id.IsEmpty)
            {
                template[attributeCount++] = CreateAttribute(Pkcs11AttributeTypes.Id.NativeValue, idPointer, search.Id.Length);
            }

            if (search.ObjectClass is Pkcs11ObjectClass searchObjectClass)
            {
                objectClass = searchObjectClass.NativeValue;
                template[attributeCount++] = CreateAttribute(Pkcs11AttributeTypes.Class.NativeValue, &objectClass, sizeof(CK_OBJECT_CLASS));
            }

            if (search.KeyType is Pkcs11KeyType searchKeyType)
            {
                keyType = searchKeyType.NativeValue;
                template[attributeCount++] = CreateAttribute(Pkcs11AttributeTypes.KeyType.NativeValue, &keyType, sizeof(CK_KEY_TYPE));
            }

            if (search.RequireEncrypt is bool canEncrypt)
            {
                requireEncrypt = canEncrypt ? CK_BBOOL.True : CK_BBOOL.False;
                template[attributeCount++] = CreateAttribute(Pkcs11AttributeTypes.Encrypt.NativeValue, &requireEncrypt, sizeof(CK_BBOOL));
            }

            if (search.RequireDecrypt is bool canDecrypt)
            {
                requireDecrypt = canDecrypt ? CK_BBOOL.True : CK_BBOOL.False;
                template[attributeCount++] = CreateAttribute(Pkcs11AttributeTypes.Decrypt.NativeValue, &requireDecrypt, sizeof(CK_BBOOL));
            }

            if (search.RequireSign is bool canSign)
            {
                requireSign = canSign ? CK_BBOOL.True : CK_BBOOL.False;
                template[attributeCount++] = CreateAttribute(Pkcs11AttributeTypes.Sign.NativeValue, &requireSign, sizeof(CK_BBOOL));
            }

            if (search.RequireVerify is bool canVerify)
            {
                requireVerify = canVerify ? CK_BBOOL.True : CK_BBOOL.False;
                template[attributeCount++] = CreateAttribute(Pkcs11AttributeTypes.Verify.NativeValue, &requireVerify, sizeof(CK_BBOOL));
            }

            if (search.RequireWrap is bool canWrap)
            {
                requireWrap = canWrap ? CK_BBOOL.True : CK_BBOOL.False;
                template[attributeCount++] = CreateAttribute(Pkcs11AttributeTypes.Wrap.NativeValue, &requireWrap, sizeof(CK_BBOOL));
            }

            if (search.RequireUnwrap is bool canUnwrap)
            {
                requireUnwrap = canUnwrap ? CK_BBOOL.True : CK_BBOOL.False;
                template[attributeCount++] = CreateAttribute(Pkcs11AttributeTypes.Unwrap.NativeValue, &requireUnwrap, sizeof(CK_BBOOL));
            }

            Span<CK_OBJECT_HANDLE> nativeDestination = MemoryMarshal.Cast<Pkcs11ObjectHandle, CK_OBJECT_HANDLE>(destination);
            return _nativeModule.TryFindObjects(sessionHandle, template[..attributeCount], nativeDestination, out written, out hasMore);
        }
    }

    internal Pkcs11AttributeReadResult GetAttributeValueInfo(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle objectHandle, Pkcs11AttributeType attributeType)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        Pkcs11NativeAttributeQuery query = _nativeModule.QueryAttributeValue(sessionHandle, objectHandle.NativeValue, attributeType.NativeValue);
        return MapAttributeQueryResult(query);
    }

    internal bool TryGetAttributeValue(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle objectHandle, Pkcs11AttributeType attributeType, Span<byte> destination, out int written, out Pkcs11AttributeReadResult result)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        bool success = _nativeModule.TryGetAttributeValue(sessionHandle, objectHandle.NativeValue, attributeType.NativeValue, destination, out written, out Pkcs11NativeAttributeQuery query);
        result = MapAttributeQueryResult(query);
        return success;
    }

    internal unsafe Pkcs11ObjectHandle CreateObject(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);

        CK_ATTRIBUTE[]? rentedTemplate = null;
        byte[]? rentedValueBuffer = null;
        int totalValueLength = GetTotalAttributeValueLength(attributes);

        Span<CK_ATTRIBUTE> template = attributes.Length <= 8
            ? stackalloc CK_ATTRIBUTE[attributes.Length]
            : (rentedTemplate = ArrayPool<CK_ATTRIBUTE>.Shared.Rent(attributes.Length));

        Span<byte> valueBuffer = totalValueLength <= 256
            ? stackalloc byte[totalValueLength]
            : (rentedValueBuffer = ArrayPool<byte>.Shared.Rent(totalValueLength));

        try
        {
            fixed (byte* valueBufferPointer = valueBuffer)
            {
                PopulateAttributeTemplate(attributes, template, valueBufferPointer);
                return new Pkcs11ObjectHandle((nuint)_nativeModule.CreateObject(sessionHandle, template[..attributes.Length]).Value);
            }
        }
        finally
        {
            ReturnPackedAttributeTemplate(rentedTemplate, rentedValueBuffer, totalValueLength);
        }
    }

    internal unsafe Pkcs11ObjectHandle CopyObject(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle sourceObjectHandle, ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);

        CK_ATTRIBUTE[]? rentedTemplate = null;
        byte[]? rentedValueBuffer = null;
        int totalValueLength = GetTotalAttributeValueLength(attributes);

        Span<CK_ATTRIBUTE> template = attributes.Length <= 8
            ? stackalloc CK_ATTRIBUTE[attributes.Length]
            : (rentedTemplate = ArrayPool<CK_ATTRIBUTE>.Shared.Rent(attributes.Length));

        Span<byte> valueBuffer = totalValueLength <= 256
            ? stackalloc byte[totalValueLength]
            : (rentedValueBuffer = ArrayPool<byte>.Shared.Rent(totalValueLength));

        try
        {
            fixed (byte* valueBufferPointer = valueBuffer)
            {
                PopulateAttributeTemplate(attributes, template, valueBufferPointer);
                return new Pkcs11ObjectHandle((nuint)_nativeModule.CopyObject(sessionHandle, sourceObjectHandle.NativeValue, template[..attributes.Length]).Value);
            }
        }
        finally
        {
            ReturnPackedAttributeTemplate(rentedTemplate, rentedValueBuffer, totalValueLength);
        }
    }

    internal unsafe void SetAttributeValue(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle objectHandle, ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);

        CK_ATTRIBUTE[]? rentedTemplate = null;
        byte[]? rentedValueBuffer = null;
        int totalValueLength = GetTotalAttributeValueLength(attributes);

        Span<CK_ATTRIBUTE> template = attributes.Length <= 8
            ? stackalloc CK_ATTRIBUTE[attributes.Length]
            : (rentedTemplate = ArrayPool<CK_ATTRIBUTE>.Shared.Rent(attributes.Length));

        Span<byte> valueBuffer = totalValueLength <= 256
            ? stackalloc byte[totalValueLength]
            : (rentedValueBuffer = ArrayPool<byte>.Shared.Rent(totalValueLength));

        try
        {
            fixed (byte* valueBufferPointer = valueBuffer)
            {
                PopulateAttributeTemplate(attributes, template, valueBufferPointer);
                _nativeModule.SetAttributeValue(sessionHandle, objectHandle.NativeValue, template[..attributes.Length]);
            }
        }
        finally
        {
            ReturnPackedAttributeTemplate(rentedTemplate, rentedValueBuffer, totalValueLength);
        }
    }

    internal unsafe Pkcs11ObjectHandle GenerateKey(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11Mechanism mechanism, ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);

        CK_ATTRIBUTE[]? rentedTemplate = null;
        byte[]? rentedValueBuffer = null;
        int totalValueLength = GetTotalAttributeValueLength(attributes);

        Span<CK_ATTRIBUTE> template = attributes.Length <= 8
            ? stackalloc CK_ATTRIBUTE[attributes.Length]
            : (rentedTemplate = ArrayPool<CK_ATTRIBUTE>.Shared.Rent(attributes.Length));

        Span<byte> valueBuffer = totalValueLength <= 256
            ? stackalloc byte[totalValueLength]
            : (rentedValueBuffer = ArrayPool<byte>.Shared.Rent(totalValueLength));

        try
        {
            fixed (byte* valueBufferPointer = valueBuffer)
            {
                PopulateAttributeTemplate(attributes, template, valueBufferPointer);
                return new Pkcs11ObjectHandle((nuint)_nativeModule.GenerateKey(sessionHandle, mechanism.Type.NativeValue, mechanism.Parameter, template[..attributes.Length]).Value);
            }
        }
        finally
        {
            ReturnPackedAttributeTemplate(rentedTemplate, rentedValueBuffer, totalValueLength);
        }
    }

    internal unsafe Pkcs11GeneratedKeyPair GenerateKeyPair(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11Mechanism mechanism, ReadOnlySpan<Pkcs11ObjectAttribute> publicKeyAttributes, ReadOnlySpan<Pkcs11ObjectAttribute> privateKeyAttributes)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);

        CK_ATTRIBUTE[]? rentedPublicTemplate = null;
        byte[]? rentedPublicValueBuffer = null;
        int publicValueLength = GetTotalAttributeValueLength(publicKeyAttributes);
        Span<CK_ATTRIBUTE> publicTemplate = publicKeyAttributes.Length <= 8
            ? stackalloc CK_ATTRIBUTE[publicKeyAttributes.Length]
            : (rentedPublicTemplate = ArrayPool<CK_ATTRIBUTE>.Shared.Rent(publicKeyAttributes.Length));
        Span<byte> publicValueBuffer = publicValueLength <= 256
            ? stackalloc byte[publicValueLength]
            : (rentedPublicValueBuffer = ArrayPool<byte>.Shared.Rent(publicValueLength));

        CK_ATTRIBUTE[]? rentedPrivateTemplate = null;
        byte[]? rentedPrivateValueBuffer = null;
        int privateValueLength = GetTotalAttributeValueLength(privateKeyAttributes);
        Span<CK_ATTRIBUTE> privateTemplate = privateKeyAttributes.Length <= 8
            ? stackalloc CK_ATTRIBUTE[privateKeyAttributes.Length]
            : (rentedPrivateTemplate = ArrayPool<CK_ATTRIBUTE>.Shared.Rent(privateKeyAttributes.Length));
        Span<byte> privateValueBuffer = privateValueLength <= 256
            ? stackalloc byte[privateValueLength]
            : (rentedPrivateValueBuffer = ArrayPool<byte>.Shared.Rent(privateValueLength));

        try
        {
            fixed (byte* publicValueBufferPointer = publicValueBuffer)
            fixed (byte* privateValueBufferPointer = privateValueBuffer)
            {
                PopulateAttributeTemplate(publicKeyAttributes, publicTemplate, publicValueBufferPointer);
                PopulateAttributeTemplate(privateKeyAttributes, privateTemplate, privateValueBufferPointer);

                (CK_OBJECT_HANDLE publicKeyHandle, CK_OBJECT_HANDLE privateKeyHandle) = _nativeModule.GenerateKeyPair(
                    sessionHandle,
                    mechanism.Type.NativeValue,
                    mechanism.Parameter,
                    publicTemplate[..publicKeyAttributes.Length],
                    privateTemplate[..privateKeyAttributes.Length]);

                return new Pkcs11GeneratedKeyPair(
                    new Pkcs11ObjectHandle((nuint)publicKeyHandle.Value),
                    new Pkcs11ObjectHandle((nuint)privateKeyHandle.Value));
            }
        }
        finally
        {
            ReturnPackedAttributeTemplate(rentedPrivateTemplate, rentedPrivateValueBuffer, privateValueLength);
            ReturnPackedAttributeTemplate(rentedPublicTemplate, rentedPublicValueBuffer, publicValueLength);
        }
    }

    internal int GetWrapOutputLength(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle wrappingKeyHandle, Pkcs11Mechanism mechanism, Pkcs11ObjectHandle keyHandle)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.GetWrapKeyOutputLength(sessionHandle, wrappingKeyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter, keyHandle.NativeValue);
    }

    internal bool TryWrapKey(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle wrappingKeyHandle, Pkcs11Mechanism mechanism, Pkcs11ObjectHandle keyHandle, Span<byte> wrappedKey, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryWrapKey(sessionHandle, wrappingKeyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter, keyHandle.NativeValue, wrappedKey, out written);
    }

    internal unsafe Pkcs11ObjectHandle UnwrapKey(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle unwrappingKeyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> wrappedKey, ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);

        CK_ATTRIBUTE[]? rentedTemplate = null;
        byte[]? rentedValueBuffer = null;
        int totalValueLength = GetTotalAttributeValueLength(attributes);

        Span<CK_ATTRIBUTE> template = attributes.Length <= 8
            ? stackalloc CK_ATTRIBUTE[attributes.Length]
            : (rentedTemplate = ArrayPool<CK_ATTRIBUTE>.Shared.Rent(attributes.Length));

        Span<byte> valueBuffer = totalValueLength <= 256
            ? stackalloc byte[totalValueLength]
            : (rentedValueBuffer = ArrayPool<byte>.Shared.Rent(totalValueLength));

        try
        {
            fixed (byte* valueBufferPointer = valueBuffer)
            {
                PopulateAttributeTemplate(attributes, template, valueBufferPointer);
                return new Pkcs11ObjectHandle((nuint)_nativeModule.UnwrapKey(sessionHandle, unwrappingKeyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter, wrappedKey, template[..attributes.Length]).Value);
            }
        }
        finally
        {
            ReturnPackedAttributeTemplate(rentedTemplate, rentedValueBuffer, totalValueLength);
        }
    }

    internal unsafe Pkcs11ObjectHandle DeriveKey(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle baseKeyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);

        CK_ATTRIBUTE[]? rentedTemplate = null;
        byte[]? rentedValueBuffer = null;
        int totalValueLength = GetTotalAttributeValueLength(attributes);

        Span<CK_ATTRIBUTE> template = attributes.Length <= 8
            ? stackalloc CK_ATTRIBUTE[attributes.Length]
            : (rentedTemplate = ArrayPool<CK_ATTRIBUTE>.Shared.Rent(attributes.Length));

        Span<byte> valueBuffer = totalValueLength <= 256
            ? stackalloc byte[totalValueLength]
            : (rentedValueBuffer = ArrayPool<byte>.Shared.Rent(totalValueLength));

        try
        {
            fixed (byte* valueBufferPointer = valueBuffer)
            {
                PopulateAttributeTemplate(attributes, template, valueBufferPointer);
                return new Pkcs11ObjectHandle((nuint)_nativeModule.DeriveKey(sessionHandle, baseKeyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter, template[..attributes.Length]).Value);
            }
        }
        finally
        {
            ReturnPackedAttributeTemplate(rentedTemplate, rentedValueBuffer, totalValueLength);
        }
    }

    internal void DestroyObject(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle objectHandle)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.DestroyObject(sessionHandle, objectHandle.NativeValue);
    }

    internal nuint GetObjectSize(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle objectHandle)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.GetObjectSize(sessionHandle, objectHandle.NativeValue);
    }

    internal int GetEncryptOutputLength(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> plaintext)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.GetEncryptOutputLength(sessionHandle, keyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter, plaintext);
    }

    internal bool TryEncrypt(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryEncrypt(sessionHandle, keyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter, plaintext, ciphertext, out written);
    }

    internal int GetDecryptOutputLength(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> ciphertext)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.GetDecryptOutputLength(sessionHandle, keyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter, ciphertext);
    }

    internal bool TryDecrypt(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryDecrypt(sessionHandle, keyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter, ciphertext, plaintext, out written);
    }

    internal int GetSignOutputLength(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.GetSignOutputLength(sessionHandle, keyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter, data);
    }

    internal int GetDigestOutputLength(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.GetDigestOutputLength(sessionHandle, mechanism.Type.NativeValue, mechanism.Parameter, data);
    }

    internal bool TrySign(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> data, Span<byte> signature, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TrySign(sessionHandle, keyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter, data, signature, out written);
    }

    internal bool TryDigest(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> data, Span<byte> digest, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryDigest(sessionHandle, mechanism.Type.NativeValue, mechanism.Parameter, data, digest, out written);
    }

    internal void DigestKey(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.DigestKey(sessionHandle, keyHandle.NativeValue);
    }

    internal bool Verify(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.Verify(sessionHandle, keyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter, data, signature);
    }

    internal void SignInit(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.SignInit(sessionHandle, keyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter);
    }

    internal void SignUpdate(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> data)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.SignUpdate(sessionHandle, data);
    }

    internal bool TrySignFinal(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Span<byte> signature, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TrySignFinal(sessionHandle, signature, out written);
    }

    internal void SignRecoverInit(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.SignRecoverInit(sessionHandle, keyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter);
    }

    internal int GetSignRecoverOutputLength(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> data)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.GetSignRecoverOutputLength(sessionHandle, data);
    }

    internal bool TrySignRecover(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> data, Span<byte> signature, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TrySignRecover(sessionHandle, data, signature, out written);
    }

    internal void VerifyInit(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.VerifyInit(sessionHandle, keyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter);
    }

    internal void VerifyUpdate(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> data)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.VerifyUpdate(sessionHandle, data);
    }

    internal bool VerifyFinal(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> signature)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.VerifyFinal(sessionHandle, signature);
    }

    internal void VerifyRecoverInit(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.VerifyRecoverInit(sessionHandle, keyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter);
    }

    internal int GetVerifyRecoverOutputLength(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> signature)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.GetVerifyRecoverOutputLength(sessionHandle, signature);
    }

    internal bool TryVerifyRecover(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> signature, Span<byte> data, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryVerifyRecover(sessionHandle, signature, data, out written);
    }

    internal void DigestInit(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11Mechanism mechanism)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.DigestInit(sessionHandle, mechanism.Type.NativeValue, mechanism.Parameter);
    }

    internal void DigestUpdate(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> data)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.DigestUpdate(sessionHandle, data);
    }

    internal bool TryDigestFinal(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Span<byte> digest, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryDigestFinal(sessionHandle, digest, out written);
    }

    internal void GenerateRandom(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Span<byte> destination)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.GenerateRandom(sessionHandle, destination);
    }

    internal void SeedRandom(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> seed)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.SeedRandom(sessionHandle, seed);
    }

    internal void EncryptInit(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.EncryptInit(sessionHandle, keyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter);
    }

    internal bool TryEncryptUpdate(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> input, Span<byte> output, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryEncryptUpdate(sessionHandle, input, output, out written);
    }

    internal bool TryDigestEncryptUpdate(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> input, Span<byte> output, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryDigestEncryptUpdate(sessionHandle, input, output, out written);
    }

    internal bool TrySignEncryptUpdate(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> input, Span<byte> output, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TrySignEncryptUpdate(sessionHandle, input, output, out written);
    }

    internal bool TryEncryptFinal(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Span<byte> output, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryEncryptFinal(sessionHandle, output, out written);
    }

    internal void DecryptInit(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.DecryptInit(sessionHandle, keyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter);
    }

    internal bool TryDecryptUpdate(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> input, Span<byte> output, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryDecryptUpdate(sessionHandle, input, output, out written);
    }

    internal bool TryDecryptDigestUpdate(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> input, Span<byte> output, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryDecryptDigestUpdate(sessionHandle, input, output, out written);
    }

    internal bool TryDecryptVerifyUpdate(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> input, Span<byte> output, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryDecryptVerifyUpdate(sessionHandle, input, output, out written);
    }

    internal bool TryDecryptFinal(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Span<byte> output, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryDecryptFinal(sessionHandle, output, out written);
    }

    internal int GetOperationStateLength(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.GetOperationStateLength(sessionHandle);
    }

    internal bool TryGetOperationState(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Span<byte> destination, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryGetOperationState(sessionHandle, destination, out written);
    }

    internal void SetOperationState(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> state, Pkcs11ObjectHandle? encryptionKeyHandle, Pkcs11ObjectHandle? authenticationKeyHandle)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.SetOperationState(
            sessionHandle,
            state,
            encryptionKeyHandle?.NativeValue ?? default,
            authenticationKeyHandle?.NativeValue ?? default);
    }

    internal void CloseSession(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration)
    {
        if (!CanUseSession(generation, slotId, slotGeneration))
        {
            return;
        }

        _nativeModule.CloseSession(sessionHandle);
    }

    private bool CanUseSession(int generation, Pkcs11SlotId slotId, int slotGeneration)
    {
        lock (_sessionStateLock)
        {
            return !_disposed &&
                   _nativeModule.IsInitialized &&
                   generation == _sessionGeneration &&
                   slotGeneration == _slotSessionGenerations.GetValueOrDefault(slotId);
        }
    }

    private void EnsureSessionIsUsable(int generation, Pkcs11SlotId slotId, int slotGeneration)
    {
        if (!CanUseSession(generation, slotId, slotGeneration))
        {
            throw new InvalidOperationException("The session is no longer valid because it was closed, invalidated by CloseAllSessions or InitToken, or the owning PKCS#11 module was finalized or disposed.");
        }
    }

    private int GetSlotSessionGeneration(Pkcs11SlotId slotId)
    {
        lock (_sessionStateLock)
        {
            return _slotSessionGenerations.GetValueOrDefault(slotId);
        }
    }

    private void IncrementSlotSessionGeneration(Pkcs11SlotId slotId)
    {
        lock (_sessionStateLock)
        {
            _slotSessionGenerations[slotId] = _slotSessionGenerations.GetValueOrDefault(slotId) + 1;
        }
    }

    private void ThrowIfDisposed()
    {
        lock (_sessionStateLock)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(Pkcs11Module));
            }
        }
    }

    private static unsafe CK_ATTRIBUTE CreateAttribute(CK_ATTRIBUTE_TYPE type, void* value, int valueLength)
        => new()
        {
            Type = type,
            Value = value,
            ValueLength = (CK_ULONG)(nuint)valueLength,
        };

    private static int GetTotalAttributeValueLength(ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        int total = 0;
        for (int i = 0; i < attributes.Length; i++)
        {
            total = checked(total + attributes[i].Value.Length);
        }

        return total;
    }

    private static void ReturnPackedAttributeTemplate(CK_ATTRIBUTE[]? rentedTemplate, byte[]? rentedValueBuffer, int totalValueLength)
    {
        if (rentedValueBuffer is not null)
        {
            CryptographicOperations.ZeroMemory(rentedValueBuffer.AsSpan(0, totalValueLength));
            ArrayPool<byte>.Shared.Return(rentedValueBuffer);
        }

        if (rentedTemplate is not null)
        {
            ArrayPool<CK_ATTRIBUTE>.Shared.Return(rentedTemplate, clearArray: true);
        }
    }

    private static unsafe void PopulateAttributeTemplate(ReadOnlySpan<Pkcs11ObjectAttribute> attributes, Span<CK_ATTRIBUTE> template, byte* valueBufferPointer)
    {
        int valueOffset = 0;

        for (int i = 0; i < attributes.Length; i++)
        {
            Pkcs11ObjectAttribute attribute = attributes[i];
            ReadOnlySpan<byte> value = attribute.Value;
            void* valuePointer = null;

            if (!value.IsEmpty)
            {
                value.CopyTo(new Span<byte>(valueBufferPointer + valueOffset, value.Length));
                valuePointer = valueBufferPointer + valueOffset;
                valueOffset += value.Length;
            }

            template[i] = CreateAttribute(attribute.Type.NativeValue, valuePointer, value.Length);
        }
    }

    private static Pkcs11AttributeReadResult MapAttributeQueryResult(Pkcs11NativeAttributeQuery query)
    {
        Pkcs11AttributeReadStatus status = query.Result switch
        {
            var result when result == CK_RV.Ok && query.IsUnavailableInformation => Pkcs11AttributeReadStatus.UnavailableInformation,
            var result when result == CK_RV.Ok => Pkcs11AttributeReadStatus.Success,
            var result when result == BufferTooSmallResult => Pkcs11AttributeReadStatus.BufferTooSmall,
            var result when result == AttributeSensitiveResult => Pkcs11AttributeReadStatus.Sensitive,
            var result when result == AttributeTypeInvalidResult => Pkcs11AttributeReadStatus.TypeInvalid,
            _ => throw new InvalidOperationException($"Unexpected PKCS#11 attribute query result {query.Result}.")
        };

        return new Pkcs11AttributeReadResult(status, query.Length);
    }

    private static class Pkcs11ResultCodes
    {
        public static readonly CK_RV BufferTooSmall = new(0x00000150u);
        public static readonly CK_RV AttributeSensitive = new(0x00000011u);
        public static readonly CK_RV AttributeTypeInvalid = new(0x00000012u);
    }
}

[StructLayout(LayoutKind.Sequential)]
public readonly struct Pkcs11SlotId : IEquatable<Pkcs11SlotId>
{
    private readonly CK_SLOT_ID _value;

    public Pkcs11SlotId(nuint value) => _value = new CK_SLOT_ID(value);

    internal CK_SLOT_ID NativeValue => _value;

    public nuint Value => (nuint)_value;

    public bool Equals(Pkcs11SlotId other) => _value == other._value;

    public override bool Equals(object? obj) => obj is Pkcs11SlotId other && Equals(other);

    public override int GetHashCode() => _value.GetHashCode();

    public override string ToString() => Value.ToString();

    public static bool operator ==(Pkcs11SlotId left, Pkcs11SlotId right) => left.Equals(right);

    public static bool operator !=(Pkcs11SlotId left, Pkcs11SlotId right) => !left.Equals(right);
}

public readonly record struct Pkcs11ModuleInfo(
    CK_VERSION CryptokiVersion,
    string ManufacturerId,
    ulong Flags,
    string LibraryDescription,
    CK_VERSION LibraryVersion)
{
    internal static unsafe Pkcs11ModuleInfo FromNative(CK_INFO info)
    {
        CK_INFO* infoPointer = &info;

        return new Pkcs11ModuleInfo(
            infoPointer->CryptokiVersion,
            Pkcs11Text.Read(infoPointer->ManufacturerId, 32),
            (ulong)infoPointer->Flags.Value,
            Pkcs11Text.Read(infoPointer->LibraryDescription, 32),
            infoPointer->LibraryVersion);
    }
}

[Flags]
public enum Pkcs11SlotFlags : ulong
{
    None = 0,
    TokenPresent = 0x00000001,
    RemovableDevice = 0x00000002,
    HardwareSlot = 0x00000004,
}

public readonly record struct Pkcs11SlotInfo(
    string SlotDescription,
    string ManufacturerId,
    Pkcs11SlotFlags Flags,
    CK_VERSION HardwareVersion,
    CK_VERSION FirmwareVersion)
{
    internal static unsafe Pkcs11SlotInfo FromNative(CK_SLOT_INFO info)
    {
        CK_SLOT_INFO* infoPointer = &info;

        return new Pkcs11SlotInfo(
            Pkcs11Text.Read(infoPointer->SlotDescription, 64),
            Pkcs11Text.Read(infoPointer->ManufacturerId, 32),
            (Pkcs11SlotFlags)(ulong)infoPointer->Flags.Value,
            infoPointer->HardwareVersion,
            infoPointer->FirmwareVersion);
    }
}

[Flags]
public enum Pkcs11TokenFlags : ulong
{
    None = 0,
    Rng = 0x00000001,
    WriteProtected = 0x00000002,
    LoginRequired = 0x00000004,
    UserPinInitialized = 0x00000008,
    RestoreKeyNotNeeded = 0x00000020,
    ClockOnToken = 0x00000040,
    ProtectedAuthenticationPath = 0x00000100,
    DualCryptoOperations = 0x00000200,
    TokenInitialized = 0x00000400,
    SecondaryAuthentication = 0x00000800,
    UserPinCountLow = 0x00010000,
    UserPinFinalTry = 0x00020000,
    UserPinLocked = 0x00040000,
    UserPinToBeChanged = 0x00080000,
    SoPinCountLow = 0x00100000,
    SoPinFinalTry = 0x00200000,
    SoPinLocked = 0x00400000,
    SoPinToBeChanged = 0x00800000,
    ErrorState = 0x01000000,
}

public readonly record struct Pkcs11TokenInfo(
    string Label,
    string ManufacturerId,
    string Model,
    string SerialNumber,
    Pkcs11TokenFlags Flags,
    nuint MaxSessionCount,
    nuint SessionCount,
    nuint MaxRwSessionCount,
    nuint RwSessionCount,
    nuint MaxPinLen,
    nuint MinPinLen,
    nuint TotalPublicMemory,
    nuint FreePublicMemory,
    nuint TotalPrivateMemory,
    nuint FreePrivateMemory,
    CK_VERSION HardwareVersion,
    CK_VERSION FirmwareVersion,
    string UtcTime)
{
    internal static unsafe Pkcs11TokenInfo FromNative(CK_TOKEN_INFO info)
    {
        CK_TOKEN_INFO* infoPointer = &info;

        return new Pkcs11TokenInfo(
            Pkcs11Text.Read(infoPointer->Label, 32),
            Pkcs11Text.Read(infoPointer->ManufacturerId, 32),
            Pkcs11Text.Read(infoPointer->Model, 16),
            Pkcs11Text.Read(infoPointer->SerialNumber, 16),
            (Pkcs11TokenFlags)(ulong)infoPointer->Flags.Value,
            (nuint)infoPointer->MaxSessionCount,
            (nuint)infoPointer->SessionCount,
            (nuint)infoPointer->MaxRwSessionCount,
            (nuint)infoPointer->RwSessionCount,
            (nuint)infoPointer->MaxPinLen,
            (nuint)infoPointer->MinPinLen,
            (nuint)infoPointer->TotalPublicMemory,
            (nuint)infoPointer->FreePublicMemory,
            (nuint)infoPointer->TotalPrivateMemory,
            (nuint)infoPointer->FreePrivateMemory,
            infoPointer->HardwareVersion,
            infoPointer->FirmwareVersion,
            Pkcs11Text.Read(infoPointer->UtcTime, 16));
    }
}

internal static class Pkcs11Text
{
    public static unsafe string Read(byte* value, int length)
    {
        ReadOnlySpan<byte> bytes = new(value, length);
        int end = bytes.Length;

        while (end > 0 && bytes[end - 1] == (byte)' ')
        {
            end--;
        }

        return Encoding.ASCII.GetString(bytes[..end]);
    }
}
