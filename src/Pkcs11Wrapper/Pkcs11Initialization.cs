using System.Runtime.InteropServices;
using Pkcs11Wrapper.Native.Interop;

namespace Pkcs11Wrapper;

[Flags]
public enum Pkcs11InitializeFlags : ulong
{
    None = 0,
    LibraryCannotCreateOsThreads = 0x00000001,
    UseOperatingSystemLocking = 0x00000002
}

public readonly unsafe struct Pkcs11MutexCallbacks
{
    public Pkcs11MutexCallbacks(
        delegate* unmanaged[Cdecl]<void**, CK_RV> createMutex,
        delegate* unmanaged[Cdecl]<void*, CK_RV> destroyMutex,
        delegate* unmanaged[Cdecl]<void*, CK_RV> lockMutex,
        delegate* unmanaged[Cdecl]<void*, CK_RV> unlockMutex)
    {
        CreateMutex = createMutex;
        DestroyMutex = destroyMutex;
        LockMutex = lockMutex;
        UnlockMutex = unlockMutex;
    }

    public delegate* unmanaged[Cdecl]<void**, CK_RV> CreateMutex { get; }

    public delegate* unmanaged[Cdecl]<void*, CK_RV> DestroyMutex { get; }

    public delegate* unmanaged[Cdecl]<void*, CK_RV> LockMutex { get; }

    public delegate* unmanaged[Cdecl]<void*, CK_RV> UnlockMutex { get; }

    public bool IsEmpty =>
        CreateMutex == null &&
        DestroyMutex == null &&
        LockMutex == null &&
        UnlockMutex == null;

    public bool IsComplete =>
        CreateMutex != null &&
        DestroyMutex != null &&
        LockMutex != null &&
        UnlockMutex != null;
}

public readonly struct Pkcs11InitializeOptions
{
    public Pkcs11InitializeOptions(Pkcs11InitializeFlags flags = Pkcs11InitializeFlags.None, Pkcs11MutexCallbacks mutexCallbacks = default)
    {
        Flags = flags;
        MutexCallbacks = mutexCallbacks;
    }

    public Pkcs11InitializeFlags Flags { get; }

    public Pkcs11MutexCallbacks MutexCallbacks { get; }
}
