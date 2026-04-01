using System.Buffers;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Pkcs11Wrapper.Native;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper;

public sealed class Pkcs11Module : IDisposable
{
    private const Pkcs11InitializeFlags SupportedInitializeFlags =
        Pkcs11InitializeFlags.LibraryCannotCreateOsThreads |
        Pkcs11InitializeFlags.UseOperatingSystemLocking;

    private readonly Pkcs11NativeModule _nativeModule;
    private readonly object _lifecycleSync = new();
    private SessionState _sessionState = SessionState.Empty;

    private Pkcs11Module(Pkcs11NativeModule nativeModule) => _nativeModule = nativeModule;

    public CK_VERSION CryptokiVersion => _nativeModule.CryptokiVersion;

    public CK_VERSION FunctionListVersion => _nativeModule.FunctionListVersion;

    public bool SupportsInterfaceDiscovery => _nativeModule.SupportsInterfaceDiscovery;

    public static Pkcs11Module Load(string libraryPath) => new(Pkcs11NativeModule.Load(libraryPath));

    public void Initialize() => Initialize(default);

    public unsafe void Initialize(Pkcs11InitializeOptions options)
    {
        lock (_lifecycleSync)
        {
            ThrowIfDisposed();

            if (_nativeModule.IsInitialized)
            {
                return;
            }

            ValidateInitializeOptions(options);
            if (options.Flags == Pkcs11InitializeFlags.None && options.MutexCallbacks.IsEmpty)
            {
                _nativeModule.Initialize();
                return;
            }

            CK_C_INITIALIZE_ARGS initializeArgs = new()
            {
                CreateMutex = options.MutexCallbacks.CreateMutex,
                DestroyMutex = options.MutexCallbacks.DestroyMutex,
                LockMutex = options.MutexCallbacks.LockMutex,
                UnlockMutex = options.MutexCallbacks.UnlockMutex,
                Flags = (CK_FLAGS)(nuint)(ulong)options.Flags,
                Reserved = null
            };

            _nativeModule.Initialize(&initializeArgs);
        }
    }

    private static void ValidateInitializeOptions(Pkcs11InitializeOptions options)
    {
        if ((options.Flags & ~SupportedInitializeFlags) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(options), options.Flags, "Unsupported PKCS#11 initialize flags were supplied.");
        }

        if (!options.MutexCallbacks.IsEmpty && !options.MutexCallbacks.IsComplete)
        {
            throw new ArgumentException("Mutex callbacks must be omitted or supplied as a complete set.", nameof(options));
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
                WriteSessionState(ReadSessionState().IncrementSessionGeneration());
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

    public int GetInterfaceCount()
    {
        ThrowIfDisposed();
        return _nativeModule.GetInterfaceCount();
    }

    public bool TryGetInterfaces(Span<Pkcs11Interface> destination, out int written)
    {
        ThrowIfDisposed();

        Span<CK_INTERFACE> nativeInterfaces = destination.Length <= 16
            ? stackalloc CK_INTERFACE[destination.Length]
            : new CK_INTERFACE[destination.Length];

        bool success = _nativeModule.TryGetInterfaces(nativeInterfaces, out written);
        int copyCount = Math.Min(destination.Length, Math.Min(written, nativeInterfaces.Length));
        for (int i = 0; i < copyCount; i++)
        {
            destination[i] = Pkcs11Interface.FromNative(nativeInterfaces[i]);
        }

        return success;
    }

    public bool TryGetInterface(ReadOnlySpan<byte> nameUtf8, CK_VERSION? version, Pkcs11InterfaceFlags flags, out Pkcs11Interface pkcs11Interface)
    {
        ThrowIfDisposed();

        if (_nativeModule.TryGetInterface(nameUtf8, version, new CK_FLAGS((nuint)(ulong)flags), out CK_INTERFACE nativeInterface))
        {
            pkcs11Interface = Pkcs11Interface.FromNative(nativeInterface);
            return true;
        }

        pkcs11Interface = default;
        return false;
    }

    public Pkcs11MechanismInfo GetMechanismInfo(Pkcs11SlotId slotId, Pkcs11MechanismType mechanismType)
        => Pkcs11MechanismInfo.FromNative(_nativeModule.GetMechanismInfo(slotId.NativeValue, mechanismType.NativeValue));

    public Pkcs11Session OpenSession(Pkcs11SlotId slotId, bool readWrite = false)
    {
        lock (_lifecycleSync)
        {
            ThrowIfDisposed();

            SessionState sessionState = ReadSessionState();
            int generation = sessionState.SessionGeneration;
            int slotGeneration = sessionState.GetSlotGeneration(slotId);

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
            SessionState sessionState = ReadSessionState();
            if (sessionState.IsDisposed)
            {
                return;
            }

            WriteSessionState(sessionState.MarkDisposedAndIncrementSessionGeneration());
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

    internal void LoginUser(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11UserType userType, ReadOnlySpan<byte> pinUtf8, ReadOnlySpan<byte> usernameUtf8)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.LoginUser(sessionHandle, userType.ToNative(), pinUtf8, usernameUtf8);
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

    internal IReadOnlyList<Pkcs11AttributeValue> GetAttributeValues(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle objectHandle, ReadOnlySpan<Pkcs11AttributeType> attributeTypes)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);

        if (attributeTypes.IsEmpty)
        {
            return [];
        }

        CK_ATTRIBUTE_TYPE[] nativeAttributeTypes = new CK_ATTRIBUTE_TYPE[attributeTypes.Length];
        for (int i = 0; i < attributeTypes.Length; i++)
        {
            nativeAttributeTypes[i] = attributeTypes[i].NativeValue;
        }

        Pkcs11NativeAttributeValue[] nativeValues = _nativeModule.GetAttributeValues(sessionHandle, objectHandle.NativeValue, nativeAttributeTypes);
        Pkcs11AttributeValue[] values = new Pkcs11AttributeValue[nativeValues.Length];
        for (int i = 0; i < nativeValues.Length; i++)
        {
            Pkcs11NativeAttributeValue nativeValue = nativeValues[i];
            values[i] = new Pkcs11AttributeValue(
                new Pkcs11AttributeType((nuint)nativeValue.Type),
                MapAttributeQueryResult(nativeValue.Query),
                nativeValue.Value);
        }

        return values;
    }

    internal Pkcs11ObjectHandle CreateObject(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);

        using PackedAttributeTemplate packedTemplate = PackedAttributeTemplate.Create(attributes);
        return new Pkcs11ObjectHandle((nuint)_nativeModule.CreateObject(sessionHandle, packedTemplate.Template).Value);
    }

    internal Pkcs11ObjectHandle CopyObject(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle sourceObjectHandle, ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);

        using PackedAttributeTemplate packedTemplate = PackedAttributeTemplate.Create(attributes);
        return new Pkcs11ObjectHandle((nuint)_nativeModule.CopyObject(sessionHandle, sourceObjectHandle.NativeValue, packedTemplate.Template).Value);
    }

    internal void SetAttributeValue(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle objectHandle, ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);

        using PackedAttributeTemplate packedTemplate = PackedAttributeTemplate.Create(attributes);
        _nativeModule.SetAttributeValue(sessionHandle, objectHandle.NativeValue, packedTemplate.Template);
    }

    internal Pkcs11ObjectHandle GenerateKey(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11Mechanism mechanism, ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);

        using PackedAttributeTemplate packedTemplate = PackedAttributeTemplate.Create(attributes);
        return new Pkcs11ObjectHandle((nuint)_nativeModule.GenerateKey(sessionHandle, mechanism.Type.NativeValue, mechanism.Parameter, packedTemplate.Template).Value);
    }

    internal Pkcs11GeneratedKeyPair GenerateKeyPair(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11Mechanism mechanism, ReadOnlySpan<Pkcs11ObjectAttribute> publicKeyAttributes, ReadOnlySpan<Pkcs11ObjectAttribute> privateKeyAttributes)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);

        using PackedAttributeTemplate packedPublicTemplate = PackedAttributeTemplate.Create(publicKeyAttributes);
        using PackedAttributeTemplate packedPrivateTemplate = PackedAttributeTemplate.Create(privateKeyAttributes);

        (CK_OBJECT_HANDLE publicKeyHandle, CK_OBJECT_HANDLE privateKeyHandle) = _nativeModule.GenerateKeyPair(
            sessionHandle,
            mechanism.Type.NativeValue,
            mechanism.Parameter,
            packedPublicTemplate.Template,
            packedPrivateTemplate.Template);

        return new Pkcs11GeneratedKeyPair(
            new Pkcs11ObjectHandle((nuint)publicKeyHandle.Value),
            new Pkcs11ObjectHandle((nuint)privateKeyHandle.Value));
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

    internal Pkcs11ObjectHandle UnwrapKey(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle unwrappingKeyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> wrappedKey, ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);

        using PackedAttributeTemplate packedTemplate = PackedAttributeTemplate.Create(attributes);
        return new Pkcs11ObjectHandle((nuint)_nativeModule.UnwrapKey(sessionHandle, unwrappingKeyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter, wrappedKey, packedTemplate.Template).Value);
    }

    internal Pkcs11ObjectHandle DeriveKey(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle baseKeyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);

        using PackedAttributeTemplate packedTemplate = PackedAttributeTemplate.Create(attributes);
        return new Pkcs11ObjectHandle((nuint)_nativeModule.DeriveKey(sessionHandle, baseKeyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter, packedTemplate.Template).Value);
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

    internal bool TryGetFunctionStatus(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryGetFunctionStatus(sessionHandle);
    }

    internal bool TryCancelFunction(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryCancelFunction(sessionHandle);
    }

    internal void SessionCancel(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11MessageFlags flags)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.SessionCancel(sessionHandle, new CK_FLAGS((nuint)(ulong)flags));
    }

    internal void MessageEncryptInit(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.MessageEncryptInit(sessionHandle, keyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter);
    }

    internal int GetMessageEncryptOutputLength(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.GetMessageEncryptOutputLength(sessionHandle, parameter, associatedData, plaintext);
    }

    internal bool TryEncryptMessage(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryEncryptMessage(sessionHandle, parameter, associatedData, plaintext, ciphertext, out written);
    }

    internal void EncryptMessageBegin(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> associatedData)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.EncryptMessageBegin(sessionHandle, parameter, associatedData);
    }

    internal bool TryEncryptMessageNext(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> plaintextPart, Span<byte> ciphertextPart, Pkcs11MessageFlags flags, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryEncryptMessageNext(sessionHandle, parameter, plaintextPart, ciphertextPart, new CK_FLAGS((nuint)(ulong)flags), out written);
    }

    internal void MessageEncryptFinal(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.MessageEncryptFinal(sessionHandle);
    }

    internal void MessageDecryptInit(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.MessageDecryptInit(sessionHandle, keyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter);
    }

    internal int GetMessageDecryptOutputLength(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.GetMessageDecryptOutputLength(sessionHandle, parameter, associatedData, ciphertext);
    }

    internal bool TryDecryptMessage(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> associatedData, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryDecryptMessage(sessionHandle, parameter, associatedData, ciphertext, plaintext, out written);
    }

    internal void DecryptMessageBegin(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> associatedData)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.DecryptMessageBegin(sessionHandle, parameter, associatedData);
    }

    internal bool TryDecryptMessageNext(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> ciphertextPart, Span<byte> plaintextPart, Pkcs11MessageFlags flags, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TryDecryptMessageNext(sessionHandle, parameter, ciphertextPart, plaintextPart, new CK_FLAGS((nuint)(ulong)flags), out written);
    }

    internal void MessageDecryptFinal(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.MessageDecryptFinal(sessionHandle);
    }

    internal void MessageSignInit(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.MessageSignInit(sessionHandle, keyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter);
    }

    internal int GetSignMessageOutputLength(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> data)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.GetSignMessageOutputLength(sessionHandle, parameter, data);
    }

    internal bool TrySignMessage(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> data, Span<byte> signature, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TrySignMessage(sessionHandle, parameter, data, signature, out written);
    }

    internal void SignMessageBegin(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> parameter)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.SignMessageBegin(sessionHandle, parameter);
    }

    internal bool TrySignMessageNext(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> data, Span<byte> signature, out int written)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.TrySignMessageNext(sessionHandle, parameter, data, signature, out written);
    }

    internal void MessageSignFinal(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.MessageSignFinal(sessionHandle);
    }

    internal void MessageVerifyInit(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.MessageVerifyInit(sessionHandle, keyHandle.NativeValue, mechanism.Type.NativeValue, mechanism.Parameter);
    }

    internal bool VerifyMessage(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.VerifyMessage(sessionHandle, parameter, data, signature);
    }

    internal void VerifyMessageBegin(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> parameter)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.VerifyMessageBegin(sessionHandle, parameter);
    }

    internal bool VerifyMessageNext(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration, ReadOnlySpan<byte> parameter, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        return _nativeModule.VerifyMessageNext(sessionHandle, parameter, data, signature);
    }

    internal void MessageVerifyFinal(CK_SESSION_HANDLE sessionHandle, int generation, Pkcs11SlotId slotId, int slotGeneration)
    {
        EnsureSessionIsUsable(generation, slotId, slotGeneration);
        _nativeModule.MessageVerifyFinal(sessionHandle);
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
        SessionState sessionState = ReadSessionState();
        return !sessionState.IsDisposed &&
               _nativeModule.IsInitialized &&
               generation == sessionState.SessionGeneration &&
               slotGeneration == sessionState.GetSlotGeneration(slotId);
    }

    private void EnsureSessionIsUsable(int generation, Pkcs11SlotId slotId, int slotGeneration)
    {
        if (!CanUseSession(generation, slotId, slotGeneration))
        {
            throw new InvalidOperationException("The session is no longer valid because it was closed, invalidated by CloseAllSessions or InitToken, or the owning PKCS#11 module was finalized or disposed.");
        }
    }

    private void IncrementSlotSessionGeneration(Pkcs11SlotId slotId)
    {
        WriteSessionState(ReadSessionState().IncrementSlotGeneration(slotId));
    }

    private void ThrowIfDisposed()
    {
        if (ReadSessionState().IsDisposed)
        {
            throw new ObjectDisposedException(nameof(Pkcs11Module));
        }
    }

    private SessionState ReadSessionState() => Volatile.Read(ref _sessionState);

    private void WriteSessionState(SessionState sessionState) => Volatile.Write(ref _sessionState, sessionState);

    private sealed class SessionState
    {
        public static readonly SessionState Empty = new(false, 0, new Dictionary<Pkcs11SlotId, int>());

        private readonly Dictionary<Pkcs11SlotId, int> _slotSessionGenerations;

        private SessionState(bool isDisposed, int sessionGeneration, Dictionary<Pkcs11SlotId, int> slotSessionGenerations)
        {
            IsDisposed = isDisposed;
            SessionGeneration = sessionGeneration;
            _slotSessionGenerations = slotSessionGenerations;
        }

        public bool IsDisposed { get; }

        public int SessionGeneration { get; }

        public int GetSlotGeneration(Pkcs11SlotId slotId) => _slotSessionGenerations.GetValueOrDefault(slotId);

        public SessionState IncrementSessionGeneration()
            => new(IsDisposed, checked(SessionGeneration + 1), new Dictionary<Pkcs11SlotId, int>(_slotSessionGenerations));

        public SessionState MarkDisposedAndIncrementSessionGeneration()
            => new(true, checked(SessionGeneration + 1), new Dictionary<Pkcs11SlotId, int>(_slotSessionGenerations));

        public SessionState IncrementSlotGeneration(Pkcs11SlotId slotId)
        {
            Dictionary<Pkcs11SlotId, int> slotSessionGenerations = new(_slotSessionGenerations);
            slotSessionGenerations[slotId] = checked(slotSessionGenerations.GetValueOrDefault(slotId) + 1);
            return new(IsDisposed, SessionGeneration, slotSessionGenerations);
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
        Pkcs11AttributeReadStatus status;
        if (query.Result == CK_RV.Ok)
        {
            status = query.IsUnavailableInformation
                ? Pkcs11AttributeReadStatus.UnavailableInformation
                : Pkcs11AttributeReadStatus.Success;
        }
        else if (query.IsBufferTooSmall)
        {
            status = Pkcs11AttributeReadStatus.BufferTooSmall;
        }
        else if (query.IsAttributeSensitive)
        {
            status = Pkcs11AttributeReadStatus.Sensitive;
        }
        else if (query.IsAttributeTypeInvalid)
        {
            status = Pkcs11AttributeReadStatus.TypeInvalid;
        }
        else
        {
            throw new InvalidOperationException($"Unexpected PKCS#11 attribute query result {query.Result}.");
        }

        return new Pkcs11AttributeReadResult(status, query.Length);
    }

    private sealed class PackedAttributeTemplate : IDisposable
    {
        private readonly CK_ATTRIBUTE[] _templateBuffer;
        private readonly byte[] _valueBuffer;
        private readonly bool _returnTemplateToPool;
        private readonly bool _returnValueBufferToPool;
        private readonly int _attributeCount;
        private readonly int _valueLength;

        private PackedAttributeTemplate(int attributeCount, int valueLength)
        {
            _attributeCount = attributeCount;
            _valueLength = valueLength;

            _returnTemplateToPool = attributeCount > 8;
            _templateBuffer = _returnTemplateToPool
                ? ArrayPool<CK_ATTRIBUTE>.Shared.Rent(attributeCount)
                : new CK_ATTRIBUTE[attributeCount];

            int valueBufferCapacity = Math.Max(valueLength, 1);
            _returnValueBufferToPool = valueLength > 256;
            _valueBuffer = _returnValueBufferToPool
                ? ArrayPool<byte>.Shared.Rent(valueBufferCapacity)
                : new byte[valueBufferCapacity];
        }

        public ReadOnlySpan<CK_ATTRIBUTE> Template => _templateBuffer.AsSpan(0, _attributeCount);

        public static PackedAttributeTemplate Create(ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
        {
            PackedAttributeTemplate packedTemplate = new(attributes.Length, GetTotalAttributeValueLength(attributes));
            packedTemplate.Populate(attributes);
            return packedTemplate;
        }

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(_valueBuffer.AsSpan(0, _valueLength));

            if (_returnValueBufferToPool)
            {
                ArrayPool<byte>.Shared.Return(_valueBuffer);
            }

            if (_returnTemplateToPool)
            {
                ArrayPool<CK_ATTRIBUTE>.Shared.Return(_templateBuffer, clearArray: true);
            }
        }

        private unsafe void Populate(ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
        {
            fixed (byte* valueBufferPointer = _valueBuffer)
            {
                PopulateAttributeTemplate(attributes, _templateBuffer.AsSpan(0, _attributeCount), valueBufferPointer);
            }
        }
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
