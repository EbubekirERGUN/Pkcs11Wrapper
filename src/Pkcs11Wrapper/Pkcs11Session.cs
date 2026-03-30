using System.Runtime.InteropServices;
using System.Threading;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper;

public sealed class Pkcs11Session : IDisposable
{
    private readonly Pkcs11Module _module;
    private readonly int _generation;
    private readonly int _slotGeneration;
    private readonly CK_SESSION_HANDLE _sessionHandle;
    private int _disposed;

    internal Pkcs11Session(Pkcs11Module module, int generation, Pkcs11SlotId slotId, int slotGeneration, CK_SESSION_HANDLE sessionHandle, bool isReadWrite)
    {
        _module = module;
        _generation = generation;
        _slotGeneration = slotGeneration;
        _sessionHandle = sessionHandle;
        SlotId = slotId;
        IsReadWrite = isReadWrite;
    }

    public Pkcs11SlotId SlotId { get; }

    public bool IsReadWrite { get; }

    public Pkcs11SessionInfo GetInfo()
    {
        ThrowIfDisposed();
        return _module.GetSessionInfo(_sessionHandle, _generation, SlotId, _slotGeneration);
    }

    public void Login(Pkcs11UserType userType, ReadOnlySpan<byte> pinUtf8)
    {
        ThrowIfDisposed();
        _module.Login(_sessionHandle, _generation, SlotId, _slotGeneration, userType, pinUtf8);
    }

    public void Logout()
    {
        ThrowIfDisposed();
        _module.Logout(_sessionHandle, _generation, SlotId, _slotGeneration);
    }

    public void InitPin(ReadOnlySpan<byte> pin)
    {
        ThrowIfDisposed();
        _module.InitPin(_sessionHandle, _generation, SlotId, _slotGeneration, pin);
    }

    public void SetPin(ReadOnlySpan<byte> oldPin, ReadOnlySpan<byte> newPin)
    {
        ThrowIfDisposed();
        _module.SetPin(_sessionHandle, _generation, SlotId, _slotGeneration, oldPin, newPin);
    }

    public bool TryFindObjects(Pkcs11ObjectSearchParameters search, Span<Pkcs11ObjectHandle> destination, out int written, out bool hasMore)
    {
        ThrowIfDisposed();
        return _module.TryFindObjects(_sessionHandle, _generation, SlotId, _slotGeneration, search, destination, out written, out hasMore);
    }

    public bool TryFindObject(Pkcs11ObjectSearchParameters search, out Pkcs11ObjectHandle handle)
    {
        ThrowIfDisposed();

        Span<Pkcs11ObjectHandle> buffer = stackalloc Pkcs11ObjectHandle[1];
        _module.TryFindObjects(_sessionHandle, _generation, SlotId, _slotGeneration, search, buffer, out int written, out _);
        if (written == 0)
        {
            handle = default;
            return false;
        }

        handle = buffer[0];
        return true;
    }

    public Pkcs11ObjectHandle CreateObject(ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        ThrowIfDisposed();
        return _module.CreateObject(_sessionHandle, _generation, SlotId, _slotGeneration, attributes);
    }

    public Pkcs11ObjectHandle CopyObject(Pkcs11ObjectHandle sourceObjectHandle, ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        ThrowIfDisposed();
        return _module.CopyObject(_sessionHandle, _generation, SlotId, _slotGeneration, sourceObjectHandle, attributes);
    }

    public void SetAttributeValue(Pkcs11ObjectHandle handle, ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        ThrowIfDisposed();
        _module.SetAttributeValue(_sessionHandle, _generation, SlotId, _slotGeneration, handle, attributes);
    }

    public Pkcs11ObjectHandle GenerateKey(Pkcs11Mechanism mechanism, ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        ThrowIfDisposed();
        return _module.GenerateKey(_sessionHandle, _generation, SlotId, _slotGeneration, mechanism, attributes);
    }

    public Pkcs11GeneratedKeyPair GenerateKeyPair(Pkcs11Mechanism mechanism, ReadOnlySpan<Pkcs11ObjectAttribute> publicKeyAttributes, ReadOnlySpan<Pkcs11ObjectAttribute> privateKeyAttributes)
    {
        ThrowIfDisposed();
        return _module.GenerateKeyPair(_sessionHandle, _generation, SlotId, _slotGeneration, mechanism, publicKeyAttributes, privateKeyAttributes);
    }

    public int GetWrapOutputLength(Pkcs11ObjectHandle wrappingKeyHandle, Pkcs11Mechanism mechanism, Pkcs11ObjectHandle keyHandle)
    {
        ThrowIfDisposed();
        return _module.GetWrapOutputLength(_sessionHandle, _generation, SlotId, _slotGeneration, wrappingKeyHandle, mechanism, keyHandle);
    }

    public bool TryWrapKey(Pkcs11ObjectHandle wrappingKeyHandle, Pkcs11Mechanism mechanism, Pkcs11ObjectHandle keyHandle, Span<byte> wrappedKey, out int written)
    {
        ThrowIfDisposed();
        return _module.TryWrapKey(_sessionHandle, _generation, SlotId, _slotGeneration, wrappingKeyHandle, mechanism, keyHandle, wrappedKey, out written);
    }

    public Pkcs11ObjectHandle UnwrapKey(Pkcs11ObjectHandle unwrappingKeyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> wrappedKey, ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        ThrowIfDisposed();
        return _module.UnwrapKey(_sessionHandle, _generation, SlotId, _slotGeneration, unwrappingKeyHandle, mechanism, wrappedKey, attributes);
    }

    public Pkcs11ObjectHandle DeriveKey(Pkcs11ObjectHandle baseKeyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<Pkcs11ObjectAttribute> attributes)
    {
        ThrowIfDisposed();
        return _module.DeriveKey(_sessionHandle, _generation, SlotId, _slotGeneration, baseKeyHandle, mechanism, attributes);
    }

    public void DestroyObject(Pkcs11ObjectHandle handle)
    {
        ThrowIfDisposed();
        _module.DestroyObject(_sessionHandle, _generation, SlotId, _slotGeneration, handle);
    }

    public nuint GetObjectSize(Pkcs11ObjectHandle handle)
    {
        ThrowIfDisposed();
        return _module.GetObjectSize(_sessionHandle, _generation, SlotId, _slotGeneration, handle);
    }

    public Pkcs11AttributeReadResult GetAttributeValueInfo(Pkcs11ObjectHandle objectHandle, Pkcs11AttributeType attributeType)
    {
        ThrowIfDisposed();
        return _module.GetAttributeValueInfo(_sessionHandle, _generation, SlotId, _slotGeneration, objectHandle, attributeType);
    }

    public bool TryGetAttributeValue(Pkcs11ObjectHandle objectHandle, Pkcs11AttributeType attributeType, Span<byte> destination, out int written, out Pkcs11AttributeReadResult result)
    {
        ThrowIfDisposed();
        return _module.TryGetAttributeValue(_sessionHandle, _generation, SlotId, _slotGeneration, objectHandle, attributeType, destination, out written, out result);
    }

    public bool TryGetAttributeBoolean(Pkcs11ObjectHandle objectHandle, Pkcs11AttributeType attributeType, out bool value, out Pkcs11AttributeReadResult result)
    {
        ThrowIfDisposed();

        Span<byte> buffer = stackalloc byte[1];
        if (!_module.TryGetAttributeValue(_sessionHandle, _generation, SlotId, _slotGeneration, objectHandle, attributeType, buffer, out int written, out result) || written != 1)
        {
            value = default;
            return false;
        }

        value = buffer[0] != 0;
        return true;
    }

    public bool TryGetAttributeNuint(Pkcs11ObjectHandle objectHandle, Pkcs11AttributeType attributeType, out nuint value, out Pkcs11AttributeReadResult result)
    {
        ThrowIfDisposed();

        Span<byte> buffer = stackalloc byte[IntPtr.Size];
        if (!_module.TryGetAttributeValue(_sessionHandle, _generation, SlotId, _slotGeneration, objectHandle, attributeType, buffer, out int written, out result) || written != IntPtr.Size)
        {
            value = default;
            return false;
        }

        value = IntPtr.Size == sizeof(uint)
            ? (nuint)MemoryMarshal.Read<uint>(buffer)
            : (nuint)MemoryMarshal.Read<ulong>(buffer);

        return true;
    }

    public int GetEncryptOutputLength(Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> plaintext)
    {
        ThrowIfDisposed();
        return _module.GetEncryptOutputLength(_sessionHandle, _generation, SlotId, _slotGeneration, keyHandle, mechanism, plaintext);
    }

    public bool TryEncrypt(Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, out int written)
    {
        ThrowIfDisposed();
        return _module.TryEncrypt(_sessionHandle, _generation, SlotId, _slotGeneration, keyHandle, mechanism, plaintext, ciphertext, out written);
    }

    public int GetDecryptOutputLength(Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> ciphertext)
    {
        ThrowIfDisposed();
        return _module.GetDecryptOutputLength(_sessionHandle, _generation, SlotId, _slotGeneration, keyHandle, mechanism, ciphertext);
    }

    public bool TryDecrypt(Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, out int written)
    {
        ThrowIfDisposed();
        return _module.TryDecrypt(_sessionHandle, _generation, SlotId, _slotGeneration, keyHandle, mechanism, ciphertext, plaintext, out written);
    }

    public int GetSignOutputLength(Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        ThrowIfDisposed();
        return _module.GetSignOutputLength(_sessionHandle, _generation, SlotId, _slotGeneration, keyHandle, mechanism, data);
    }

    public int GetDigestOutputLength(Pkcs11Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        ThrowIfDisposed();
        return _module.GetDigestOutputLength(_sessionHandle, _generation, SlotId, _slotGeneration, mechanism, data);
    }

    public bool TrySign(Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> data, Span<byte> signature, out int written)
    {
        ThrowIfDisposed();
        return _module.TrySign(_sessionHandle, _generation, SlotId, _slotGeneration, keyHandle, mechanism, data, signature, out written);
    }

    public bool TryDigest(Pkcs11Mechanism mechanism, ReadOnlySpan<byte> data, Span<byte> digest, out int written)
    {
        ThrowIfDisposed();
        return _module.TryDigest(_sessionHandle, _generation, SlotId, _slotGeneration, mechanism, data, digest, out written);
    }

    public void DigestKey(Pkcs11ObjectHandle keyHandle)
    {
        ThrowIfDisposed();
        _module.DigestKey(_sessionHandle, _generation, SlotId, _slotGeneration, keyHandle);
    }

    public bool Verify(Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        ThrowIfDisposed();
        return _module.Verify(_sessionHandle, _generation, SlotId, _slotGeneration, keyHandle, mechanism, data, signature);
    }

    public int GetEncryptOutputLength(Pkcs11ObjectSearchParameters keySearch, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> plaintext)
    {
        ThrowIfDisposed();
        return _module.GetEncryptOutputLength(_sessionHandle, _generation, SlotId, _slotGeneration, ResolveRequiredObjectHandle(keySearch), mechanism, plaintext);
    }

    public bool TryEncrypt(Pkcs11ObjectSearchParameters keySearch, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, out int written)
    {
        ThrowIfDisposed();
        return _module.TryEncrypt(_sessionHandle, _generation, SlotId, _slotGeneration, ResolveRequiredObjectHandle(keySearch), mechanism, plaintext, ciphertext, out written);
    }

    public int GetDecryptOutputLength(Pkcs11ObjectSearchParameters keySearch, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> ciphertext)
    {
        ThrowIfDisposed();
        return _module.GetDecryptOutputLength(_sessionHandle, _generation, SlotId, _slotGeneration, ResolveRequiredObjectHandle(keySearch), mechanism, ciphertext);
    }

    public bool TryDecrypt(Pkcs11ObjectSearchParameters keySearch, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, out int written)
    {
        ThrowIfDisposed();
        return _module.TryDecrypt(_sessionHandle, _generation, SlotId, _slotGeneration, ResolveRequiredObjectHandle(keySearch), mechanism, ciphertext, plaintext, out written);
    }

    public int GetSignOutputLength(Pkcs11ObjectSearchParameters keySearch, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> data)
    {
        ThrowIfDisposed();
        return _module.GetSignOutputLength(_sessionHandle, _generation, SlotId, _slotGeneration, ResolveRequiredObjectHandle(keySearch), mechanism, data);
    }

    public bool TrySign(Pkcs11ObjectSearchParameters keySearch, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> data, Span<byte> signature, out int written)
    {
        ThrowIfDisposed();
        return _module.TrySign(_sessionHandle, _generation, SlotId, _slotGeneration, ResolveRequiredObjectHandle(keySearch), mechanism, data, signature, out written);
    }

    public void DigestKey(Pkcs11ObjectSearchParameters keySearch)
    {
        ThrowIfDisposed();
        _module.DigestKey(_sessionHandle, _generation, SlotId, _slotGeneration, ResolveRequiredObjectHandle(keySearch));
    }

    public bool Verify(Pkcs11ObjectSearchParameters keySearch, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        ThrowIfDisposed();
        return _module.Verify(_sessionHandle, _generation, SlotId, _slotGeneration, ResolveRequiredObjectHandle(keySearch), mechanism, data, signature);
    }

    public void SignInit(Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism)
    {
        ThrowIfDisposed();
        _module.SignInit(_sessionHandle, _generation, SlotId, _slotGeneration, keyHandle, mechanism);
    }

    public void SignInit(Pkcs11ObjectSearchParameters keySearch, Pkcs11Mechanism mechanism)
    {
        ThrowIfDisposed();
        _module.SignInit(_sessionHandle, _generation, SlotId, _slotGeneration, ResolveRequiredObjectHandle(keySearch), mechanism);
    }

    public void SignUpdate(ReadOnlySpan<byte> data)
    {
        ThrowIfDisposed();
        _module.SignUpdate(_sessionHandle, _generation, SlotId, _slotGeneration, data);
    }

    public bool TrySignFinal(Span<byte> signature, out int written)
    {
        ThrowIfDisposed();
        return _module.TrySignFinal(_sessionHandle, _generation, SlotId, _slotGeneration, signature, out written);
    }

    public void SignRecoverInit(Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism)
    {
        ThrowIfDisposed();
        _module.SignRecoverInit(_sessionHandle, _generation, SlotId, _slotGeneration, keyHandle, mechanism);
    }

    public void SignRecoverInit(Pkcs11ObjectSearchParameters keySearch, Pkcs11Mechanism mechanism)
    {
        ThrowIfDisposed();
        _module.SignRecoverInit(_sessionHandle, _generation, SlotId, _slotGeneration, ResolveRequiredObjectHandle(keySearch), mechanism);
    }

    public int GetSignRecoverOutputLength(ReadOnlySpan<byte> data)
    {
        ThrowIfDisposed();
        return _module.GetSignRecoverOutputLength(_sessionHandle, _generation, SlotId, _slotGeneration, data);
    }

    public bool TrySignRecover(ReadOnlySpan<byte> data, Span<byte> signature, out int written)
    {
        ThrowIfDisposed();
        return _module.TrySignRecover(_sessionHandle, _generation, SlotId, _slotGeneration, data, signature, out written);
    }

    public void VerifyInit(Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism)
    {
        ThrowIfDisposed();
        _module.VerifyInit(_sessionHandle, _generation, SlotId, _slotGeneration, keyHandle, mechanism);
    }

    public void VerifyInit(Pkcs11ObjectSearchParameters keySearch, Pkcs11Mechanism mechanism)
    {
        ThrowIfDisposed();
        _module.VerifyInit(_sessionHandle, _generation, SlotId, _slotGeneration, ResolveRequiredObjectHandle(keySearch), mechanism);
    }

    public void VerifyUpdate(ReadOnlySpan<byte> data)
    {
        ThrowIfDisposed();
        _module.VerifyUpdate(_sessionHandle, _generation, SlotId, _slotGeneration, data);
    }

    public bool VerifyFinal(ReadOnlySpan<byte> signature)
    {
        ThrowIfDisposed();
        return _module.VerifyFinal(_sessionHandle, _generation, SlotId, _slotGeneration, signature);
    }

    public void VerifyRecoverInit(Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism)
    {
        ThrowIfDisposed();
        _module.VerifyRecoverInit(_sessionHandle, _generation, SlotId, _slotGeneration, keyHandle, mechanism);
    }

    public void VerifyRecoverInit(Pkcs11ObjectSearchParameters keySearch, Pkcs11Mechanism mechanism)
    {
        ThrowIfDisposed();
        _module.VerifyRecoverInit(_sessionHandle, _generation, SlotId, _slotGeneration, ResolveRequiredObjectHandle(keySearch), mechanism);
    }

    public int GetVerifyRecoverOutputLength(ReadOnlySpan<byte> signature)
    {
        ThrowIfDisposed();
        return _module.GetVerifyRecoverOutputLength(_sessionHandle, _generation, SlotId, _slotGeneration, signature);
    }

    public bool TryVerifyRecover(ReadOnlySpan<byte> signature, Span<byte> data, out int written)
    {
        ThrowIfDisposed();
        return _module.TryVerifyRecover(_sessionHandle, _generation, SlotId, _slotGeneration, signature, data, out written);
    }

    public void EncryptInit(Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism)
    {
        ThrowIfDisposed();
        _module.EncryptInit(_sessionHandle, _generation, SlotId, _slotGeneration, keyHandle, mechanism);
    }

    public void DigestInit(Pkcs11Mechanism mechanism)
    {
        ThrowIfDisposed();
        _module.DigestInit(_sessionHandle, _generation, SlotId, _slotGeneration, mechanism);
    }

    public void EncryptInit(Pkcs11ObjectSearchParameters keySearch, Pkcs11Mechanism mechanism)
    {
        ThrowIfDisposed();
        _module.EncryptInit(_sessionHandle, _generation, SlotId, _slotGeneration, ResolveRequiredObjectHandle(keySearch), mechanism);
    }

    public bool TryEncryptUpdate(ReadOnlySpan<byte> input, Span<byte> output, out int written)
    {
        ThrowIfDisposed();
        return _module.TryEncryptUpdate(_sessionHandle, _generation, SlotId, _slotGeneration, input, output, out written);
    }

    public bool TryDigestEncryptUpdate(ReadOnlySpan<byte> input, Span<byte> output, out int written)
    {
        ThrowIfDisposed();
        return _module.TryDigestEncryptUpdate(_sessionHandle, _generation, SlotId, _slotGeneration, input, output, out written);
    }

    public bool TrySignEncryptUpdate(ReadOnlySpan<byte> input, Span<byte> output, out int written)
    {
        ThrowIfDisposed();
        return _module.TrySignEncryptUpdate(_sessionHandle, _generation, SlotId, _slotGeneration, input, output, out written);
    }

    public void DigestUpdate(ReadOnlySpan<byte> data)
    {
        ThrowIfDisposed();
        _module.DigestUpdate(_sessionHandle, _generation, SlotId, _slotGeneration, data);
    }

    public bool TryEncryptFinal(Span<byte> output, out int written)
    {
        ThrowIfDisposed();
        return _module.TryEncryptFinal(_sessionHandle, _generation, SlotId, _slotGeneration, output, out written);
    }

    public bool TryDigestFinal(Span<byte> digest, out int written)
    {
        ThrowIfDisposed();
        return _module.TryDigestFinal(_sessionHandle, _generation, SlotId, _slotGeneration, digest, out written);
    }

    public void DecryptInit(Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism)
    {
        ThrowIfDisposed();
        _module.DecryptInit(_sessionHandle, _generation, SlotId, _slotGeneration, keyHandle, mechanism);
    }

    public void DecryptInit(Pkcs11ObjectSearchParameters keySearch, Pkcs11Mechanism mechanism)
    {
        ThrowIfDisposed();
        _module.DecryptInit(_sessionHandle, _generation, SlotId, _slotGeneration, ResolveRequiredObjectHandle(keySearch), mechanism);
    }

    public bool TryDecryptUpdate(ReadOnlySpan<byte> input, Span<byte> output, out int written)
    {
        ThrowIfDisposed();
        return _module.TryDecryptUpdate(_sessionHandle, _generation, SlotId, _slotGeneration, input, output, out written);
    }

    public bool TryDecryptDigestUpdate(ReadOnlySpan<byte> input, Span<byte> output, out int written)
    {
        ThrowIfDisposed();
        return _module.TryDecryptDigestUpdate(_sessionHandle, _generation, SlotId, _slotGeneration, input, output, out written);
    }

    public bool TryDecryptVerifyUpdate(ReadOnlySpan<byte> input, Span<byte> output, out int written)
    {
        ThrowIfDisposed();
        return _module.TryDecryptVerifyUpdate(_sessionHandle, _generation, SlotId, _slotGeneration, input, output, out written);
    }

    public bool TryDecryptFinal(Span<byte> output, out int written)
    {
        ThrowIfDisposed();
        return _module.TryDecryptFinal(_sessionHandle, _generation, SlotId, _slotGeneration, output, out written);
    }

    public int GetOperationStateLength()
    {
        ThrowIfDisposed();
        return _module.GetOperationStateLength(_sessionHandle, _generation, SlotId, _slotGeneration);
    }

    public bool TryGetOperationState(Span<byte> destination, out int written)
    {
        ThrowIfDisposed();
        return _module.TryGetOperationState(_sessionHandle, _generation, SlotId, _slotGeneration, destination, out written);
    }

    public void SetOperationState(ReadOnlySpan<byte> state, Pkcs11ObjectHandle? encryptionKeyHandle = null, Pkcs11ObjectHandle? authenticationKeyHandle = null)
    {
        ThrowIfDisposed();
        _module.SetOperationState(_sessionHandle, _generation, SlotId, _slotGeneration, state, encryptionKeyHandle, authenticationKeyHandle);
    }

    public void GenerateRandom(Span<byte> destination)
    {
        ThrowIfDisposed();
        _module.GenerateRandom(_sessionHandle, _generation, SlotId, _slotGeneration, destination);
    }

    public void SeedRandom(ReadOnlySpan<byte> seed)
    {
        ThrowIfDisposed();
        _module.SeedRandom(_sessionHandle, _generation, SlotId, _slotGeneration, seed);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _module.CloseSession(_sessionHandle, _generation, SlotId, _slotGeneration);
    }

    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            throw new ObjectDisposedException(nameof(Pkcs11Session));
        }
    }

    private Pkcs11ObjectHandle ResolveRequiredObjectHandle(Pkcs11ObjectSearchParameters search)
    {
        if (TryFindObject(search, out Pkcs11ObjectHandle handle))
        {
            return handle;
        }

        throw new InvalidOperationException("No PKCS#11 object matched the provided search criteria.");
    }
}

[Flags]
public enum Pkcs11SessionFlags : ulong
{
    None = 0,
    ReadWrite = 0x00000002,
    SerialSession = 0x00000004,
}

public enum Pkcs11SessionState : ulong
{
    ReadOnlyPublic = 0,
    ReadOnlyUser = 1,
    ReadWritePublic = 2,
    ReadWriteUser = 3,
    ReadWriteSecurityOfficer = 4,
}

public enum Pkcs11UserType : ulong
{
    SecurityOfficer = 0,
    User = 1,
    ContextSpecific = 2,
}

public readonly record struct Pkcs11SessionInfo(
    Pkcs11SlotId SlotId,
    Pkcs11SessionState State,
    Pkcs11SessionFlags Flags,
    nuint DeviceError)
{
    internal static Pkcs11SessionInfo FromNative(CK_SESSION_INFO info) => new(
        new Pkcs11SlotId((nuint)info.SlotId.Value),
        (Pkcs11SessionState)(ulong)info.State.Value,
        (Pkcs11SessionFlags)(ulong)info.Flags.Value,
        (nuint)info.DeviceError.Value);
}

internal static class Pkcs11UserTypeExtensions
{
    public static CK_USER_TYPE ToNative(this Pkcs11UserType userType) => new((nuint)userType);
}
