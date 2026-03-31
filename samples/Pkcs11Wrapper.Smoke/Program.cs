using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Pkcs11Wrapper;
using Pkcs11Wrapper.Native;

string? modulePath = ResolveModulePath(args);
if (modulePath is null)
{
    Console.Error.WriteLine("No PKCS#11 module path provided. Use the first argument or PKCS11_MODULE_PATH.");
    return 2;
}

Console.WriteLine($"Loading PKCS#11 module: {modulePath}");

try
{
    using var module = Pkcs11Module.Load(modulePath);
    module.Initialize();

    Pkcs11ModuleInfo info = module.GetInfo();
    int slotCount = module.GetSlotCount();

    Console.WriteLine($"Cryptoki version: {info.CryptokiVersion}");
    Console.WriteLine($"Manufacturer: {info.ManufacturerId}");
    Console.WriteLine($"Library: {info.LibraryDescription} {info.LibraryVersion}");
    Console.WriteLine($"Slot count: {slotCount}");

    if (slotCount == 0)
    {
        Console.WriteLine("No slots exposed by the module.");
        return 0;
    }

    Pkcs11SlotId[] slots = new Pkcs11SlotId[slotCount];
    if (!module.TryGetSlots(slots, out int written))
    {
        Console.Error.WriteLine($"Slot enumeration requires capacity {written}, but {slots.Length} was allocated.");
        return 5;
    }

    List<SlotCandidate> sessionCandidates = [];
    for (int i = 0; i < written; i++)
    {
        Pkcs11SlotId slotId = slots[i];
        Pkcs11SlotInfo slotInfo = module.GetSlotInfo(slotId);

        Console.WriteLine($"Slot {slotId.Value}: {slotInfo.SlotDescription} [{slotInfo.Flags}]");
        Console.WriteLine($"  Manufacturer: {slotInfo.ManufacturerId}");
        Console.WriteLine($"  Hardware/Firmware: {slotInfo.HardwareVersion} / {slotInfo.FirmwareVersion}");

        try
        {
            WriteMechanisms(module, slotId);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Mechanisms failed: {ex.GetType().Name}: {ex.Message}");
        }

        try
        {
            if (module.TryGetTokenInfo(slotId, out Pkcs11TokenInfo tokenInfo))
            {
                Console.WriteLine($"  Token: {tokenInfo.Label} ({tokenInfo.Model}, S/N {tokenInfo.SerialNumber}) [{tokenInfo.Flags}]");
                Console.WriteLine($"  Token manufacturer: {tokenInfo.ManufacturerId}");
                sessionCandidates.Add(new SlotCandidate(slotId, tokenInfo));
            }
            else
            {
                Console.WriteLine("  Token: not present");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"  Token info failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    if (!TrySelectSessionSlot(sessionCandidates, out Pkcs11SlotId sessionSlotId, out string selectionReason))
    {
        Console.WriteLine("No token-present slot available for session smoke.");
        return 0;
    }

    Console.WriteLine($"Selected slot {sessionSlotId.Value}: {selectionReason}");
    RunSessionFlow(module, sessionSlotId);
    return 0;
}
catch (DllNotFoundException ex)
{
    Console.Error.WriteLine($"Module not found: {ex.Message}");
    return 3;
}
catch (FileNotFoundException ex)
{
    Console.Error.WriteLine($"Module not found: {ex.Message}");
    return 3;
}
catch (BadImageFormatException ex)
{
    Console.Error.WriteLine($"Module load failed: {ex.Message}");
    return 4;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Smoke test failed: {ex}");
    return 1;
}

static string? ResolveModulePath(string[] args)
{
    if (args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
    {
        return args[0];
    }

    string? envPath = Environment.GetEnvironmentVariable("PKCS11_MODULE_PATH");
    if (!string.IsNullOrWhiteSpace(envPath))
    {
        return envPath;
    }

    return Pkcs11ModulePathDefaults.GetDefaultSoftHsmModulePath();
}

static bool TrySelectSessionSlot(List<SlotCandidate> candidates, out Pkcs11SlotId slotId, out string reason)
{
    if (candidates.Count == 0)
    {
        slotId = default;
        reason = string.Empty;
        return false;
    }

    string? labelFilter = NormalizeFilter(Environment.GetEnvironmentVariable("PKCS11_TOKEN_LABEL"));
    string? serialFilter = NormalizeFilter(Environment.GetEnvironmentVariable("PKCS11_TOKEN_SERIAL"));
    string? slotFilterText = NormalizeFilter(Environment.GetEnvironmentVariable("PKCS11_SLOT_ID"));
    bool hasExplicitFilter = labelFilter is not null || serialFilter is not null || slotFilterText is not null;
    Pkcs11SlotId? slotFilter = null;

    if (slotFilterText is not null)
    {
        if (TryParseNuint(slotFilterText, out nuint parsedSlotId))
        {
            slotFilter = new Pkcs11SlotId(parsedSlotId);
        }
        else
        {
            Console.WriteLine($"Ignoring invalid PKCS11_SLOT_ID value '{slotFilterText}'.");
        }
    }

    if (hasExplicitFilter)
    {
        foreach (SlotCandidate candidate in candidates.OrderBy(candidate => candidate.SlotId.Value))
        {
            if (MatchesTokenFilter(candidate, labelFilter, serialFilter, slotFilter))
            {
                slotId = candidate.SlotId;
                reason = $"explicit token filter match ({DescribeToken(candidate.TokenInfo)})";
                return true;
            }
        }

        Console.WriteLine("No token matched PKCS11_TOKEN_LABEL/PKCS11_TOKEN_SERIAL/PKCS11_SLOT_ID filters; falling back to token flags.");
    }

    foreach (SlotCandidate candidate in candidates.OrderBy(candidate => candidate.SlotId.Value))
    {
        if (candidate.TokenInfo.Flags.HasFlag(Pkcs11TokenFlags.TokenInitialized))
        {
            slotId = candidate.SlotId;
            reason = $"token is initialized ({DescribeToken(candidate.TokenInfo)})";
            return true;
        }
    }

    foreach (SlotCandidate candidate in candidates.OrderBy(candidate => candidate.SlotId.Value))
    {
        if (candidate.TokenInfo.Flags.HasFlag(Pkcs11TokenFlags.UserPinInitialized))
        {
            slotId = candidate.SlotId;
            reason = $"user PIN is initialized ({DescribeToken(candidate.TokenInfo)})";
            return true;
        }
    }

    SlotCandidate fallback = candidates.OrderBy(candidate => candidate.SlotId.Value).First();
    slotId = fallback.SlotId;
    reason = $"first token-present slot fallback ({DescribeToken(fallback.TokenInfo)})";
    return true;
}

static bool MatchesTokenFilter(SlotCandidate candidate, string? labelFilter, string? serialFilter, Pkcs11SlotId? slotFilter)
{
    if (labelFilter is not null && !string.Equals(candidate.TokenInfo.Label.Trim(), labelFilter, StringComparison.Ordinal))
    {
        return false;
    }

    if (serialFilter is not null && !string.Equals(candidate.TokenInfo.SerialNumber.Trim(), serialFilter, StringComparison.Ordinal))
    {
        return false;
    }

    if (slotFilter is not null && candidate.SlotId.Value != slotFilter.Value.Value)
    {
        return false;
    }

    return true;
}

static string? NormalizeFilter(string? value)
{
    return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

static string DescribeToken(Pkcs11TokenInfo tokenInfo)
{
    return $"label='{tokenInfo.Label.Trim()}', serial='{tokenInfo.SerialNumber.Trim()}'";
}

static void RunSessionFlow(Pkcs11Module module, Pkcs11SlotId slotId)
{
    Console.WriteLine($"Opening read-only session on slot {slotId.Value}.");

    using Pkcs11Session session = module.OpenSession(slotId);
    Pkcs11SessionInfo sessionInfo = session.GetInfo();

    Console.WriteLine($"  Session state: {sessionInfo.State}");
    Console.WriteLine($"  Session flags: {sessionInfo.Flags}");
    Console.WriteLine($"  Session device error: {sessionInfo.DeviceError}");

    Pkcs11ObjectSearchParameters searchCriteria = GetSearchParameters("PKCS11_");
    WriteSearchResults(session, "default", searchCriteria);

    string? pin = Environment.GetEnvironmentVariable("PKCS11_USER_PIN");
    if (string.IsNullOrEmpty(pin))
    {
        Console.WriteLine("  Login skipped: PKCS11_USER_PIN is not set.");
        return;
    }

    byte[] pinUtf8 = Encoding.UTF8.GetBytes(pin);
    try
    {
        LoginUser(session, pinUtf8);
        Console.WriteLine("  Login succeeded.");

        WriteSearchResults(session, "default", searchCriteria);
        TryRunEncryptDecryptSmoke(session, searchCriteria);
        TryRunMultipartSmoke(module, slotId, session, searchCriteria, pinUtf8);
        TryRunDigestSmoke(session);
        TryRunRandomSmoke(session);
        TryRunSignVerifySmoke(module, slotId, pinUtf8);
        TryRunObjectLifecycleSmoke(module, slotId, pinUtf8);
        TryRunGenerateKeySmoke(module, slotId, pinUtf8);
        TryRunWrapUnwrapSmoke(module, slotId, pinUtf8);
        TryRunDeriveKeySmoke(module, slotId, pinUtf8);

        session.Logout();
        Console.WriteLine("  Logout succeeded.");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  Login/logout failed: {ex.GetType().Name}: {ex.Message}");
    }
}

static void WriteMechanisms(Pkcs11Module module, Pkcs11SlotId slotId)
{
    int mechanismCount = module.GetMechanismCount(slotId);
    Console.WriteLine($"  Mechanism count: {mechanismCount}");

    if (mechanismCount == 0)
    {
        return;
    }

    Pkcs11MechanismType[] mechanisms = new Pkcs11MechanismType[mechanismCount];
    if (!module.TryGetMechanisms(slotId, mechanisms, out int written))
    {
        Console.WriteLine($"  Mechanism enumeration requires capacity {written}, but {mechanisms.Length} was allocated.");
        return;
    }

    for (int i = 0; i < written; i++)
    {
        Pkcs11MechanismType mechanism = mechanisms[i];
        Pkcs11MechanismInfo mechanismInfo = module.GetMechanismInfo(slotId, mechanism);
        Console.WriteLine($"    {mechanism}: minKey={mechanismInfo.MinKeySize}, maxKey={mechanismInfo.MaxKeySize}, flags={mechanismInfo.Flags}");
    }
}

static void WriteSearchResults(Pkcs11Session session, string name, Pkcs11ObjectSearchParameters criteria)
{
    Span<Pkcs11ObjectHandle> handles = stackalloc Pkcs11ObjectHandle[8];
    if (!session.TryFindObjects(criteria, handles, out int written, out bool hasMore))
    {
        Console.WriteLine($"  {name} object search filled {handles.Length} handles and has more results: {hasMore}.");
    }

    Console.WriteLine($"  {name} object search matched {written} handle(s); hasMore={hasMore}.");
    for (int i = 0; i < written; i++)
    {
        WriteObjectSummary(session, handles[i], i);
    }
}

static void WriteObjectSummary(Pkcs11Session session, Pkcs11ObjectHandle handle, int index)
{
    Console.WriteLine($"    Match {index}: handle={handle.Value}");

    if (session.TryGetAttributeNuint(handle, Pkcs11AttributeTypes.Class, out nuint objectClass, out _))
    {
        Console.WriteLine($"      class={objectClass}");
    }

    if (session.TryGetAttributeNuint(handle, Pkcs11AttributeTypes.KeyType, out nuint keyType, out _))
    {
        Console.WriteLine($"      keyType={keyType}");
    }

    if (session.TryGetAttributeBoolean(handle, Pkcs11AttributeTypes.Encrypt, out bool encrypt, out _))
    {
        Console.WriteLine($"      encrypt={encrypt}");
    }

    if (session.TryGetAttributeBoolean(handle, Pkcs11AttributeTypes.Decrypt, out bool decrypt, out _))
    {
        Console.WriteLine($"      decrypt={decrypt}");
    }

    if (session.TryGetAttributeBoolean(handle, Pkcs11AttributeTypes.Sign, out bool sign, out _))
    {
        Console.WriteLine($"      sign={sign}");
    }

    if (session.TryGetAttributeBoolean(handle, Pkcs11AttributeTypes.Verify, out bool verify, out _))
    {
        Console.WriteLine($"      verify={verify}");
    }

    byte[]? label = ReadAttributeBytes(session, handle, Pkcs11AttributeTypes.Label);
    if (label is not null)
    {
        Console.WriteLine($"      label={Encoding.UTF8.GetString(label)}");
    }

    byte[]? id = ReadAttributeBytes(session, handle, Pkcs11AttributeTypes.Id);
    if (id is not null)
    {
        Console.WriteLine($"      id={Convert.ToHexString(id)}");
    }
}

static byte[]? ReadAttributeBytes(Pkcs11Session session, Pkcs11ObjectHandle handle, Pkcs11AttributeType attributeType)
{
    Pkcs11AttributeReadResult info = session.GetAttributeValueInfo(handle, attributeType);
    if (!info.IsReadable || info.Length > int.MaxValue)
    {
        return null;
    }

    byte[] buffer = new byte[(int)info.Length];
    return session.TryGetAttributeValue(handle, attributeType, buffer, out int written, out _)
        ? buffer.AsSpan(0, written).ToArray()
        : null;
}

static byte[] GetRequiredAttributeBytes(Pkcs11Session session, Pkcs11ObjectHandle handle, Pkcs11AttributeType attributeType)
    => ReadAttributeBytes(session, handle, attributeType)
        ?? throw new InvalidOperationException($"Attribute {attributeType} is not readable on object {handle.Value}.");

static void TryRunEncryptDecryptSmoke(Pkcs11Session session, Pkcs11ObjectSearchParameters searchCriteria)
{
    string? mechanismText = Environment.GetEnvironmentVariable("PKCS11_MECHANISM");
    if (string.IsNullOrWhiteSpace(mechanismText))
    {
        Console.WriteLine("  Encrypt/decrypt skipped: PKCS11_MECHANISM is not set.");
        return;
    }

    if (!TryParseNuint(mechanismText, out nuint mechanismValue))
    {
        Console.WriteLine("  Encrypt/decrypt skipped: PKCS11_MECHANISM is invalid.");
        return;
    }

    if (!TryResolveKeyHandle(session, searchCriteria, "PKCS11_KEY_HANDLE", out Pkcs11ObjectHandle keyHandle))
    {
        Console.WriteLine("  Encrypt/decrypt skipped: no explicit or discovered key handle is available.");
        return;
    }

    byte[] mechanismParameter = ParseHex(Environment.GetEnvironmentVariable("PKCS11_MECHANISM_PARAM_HEX"));
    byte[] plaintext = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("PKCS11_SMOKE_PLAINTEXT") ?? "pkcs11-wrapper-smoke");
    Pkcs11Mechanism mechanism = new(new Pkcs11MechanismType(mechanismValue), mechanismParameter);

    try
    {
        byte[] ciphertext = new byte[session.GetEncryptOutputLength(keyHandle, mechanism, plaintext)];
        if (!session.TryEncrypt(keyHandle, mechanism, plaintext, ciphertext, out int ciphertextWritten))
        {
            Console.WriteLine($"  Encrypt failed: caller buffer too small, requires {ciphertextWritten} bytes.");
            return;
        }

        byte[] decrypted = new byte[session.GetDecryptOutputLength(keyHandle, mechanism, ciphertext.AsSpan(0, ciphertextWritten))];
        if (!session.TryDecrypt(keyHandle, mechanism, ciphertext.AsSpan(0, ciphertextWritten), decrypted, out int decryptedWritten))
        {
            Console.WriteLine($"  Decrypt failed: caller buffer too small, requires {decryptedWritten} bytes.");
            return;
        }

        bool roundTrip = plaintext.AsSpan().SequenceEqual(decrypted.AsSpan(0, decryptedWritten));
        Console.WriteLine($"  Encrypt/decrypt smoke: handle={keyHandle.Value}, ciphertext={ciphertextWritten} bytes, plaintext={decryptedWritten} bytes, roundTrip={roundTrip}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  Encrypt/decrypt failed: {ex.GetType().Name}: {ex.Message}");
    }
}

static void TryRunMultipartSmoke(Pkcs11Module module, Pkcs11SlotId slotId, Pkcs11Session session, Pkcs11ObjectSearchParameters searchCriteria, ReadOnlySpan<byte> pinUtf8)
{
    bool runMultipart = ParseBooleanFlag(Environment.GetEnvironmentVariable("PKCS11_MULTIPART"));
    bool runOperationState = ParseBooleanFlag(Environment.GetEnvironmentVariable("PKCS11_OPERATION_STATE"));
    if (!runMultipart && !runOperationState)
    {
        return;
    }

    if (!TryResolveKeyHandle(session, searchCriteria, "PKCS11_KEY_HANDLE", out Pkcs11ObjectHandle keyHandle))
    {
        Console.WriteLine("  Multipart skipped: no explicit or discovered key handle is available.");
        return;
    }

    byte[] iv = ParseHex(Environment.GetEnvironmentVariable("PKCS11_MULTIPART_IV_HEX") ?? "00112233445566778899AABBCCDDEEFF");
    if (iv.Length != 16)
    {
        Console.WriteLine("  Multipart skipped: PKCS11_MULTIPART_IV_HEX must be 16 bytes.");
        return;
    }

    byte[] plaintext = GetMultipartPlaintext();
    if (plaintext.Length == 0 || (plaintext.Length % 16) != 0)
    {
        Console.WriteLine("  Multipart skipped: plaintext must be a non-empty multiple of 16 bytes for AES-CBC.");
        return;
    }

    int chunkLength = plaintext.Length / 2;
    if ((chunkLength % 16) != 0)
    {
        Console.WriteLine("  Multipart skipped: plaintext midpoint must stay block aligned.");
        return;
    }

    Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.AesCbc, iv);

    try
    {
        byte[] baselineCiphertext = EncryptMultipart(session, keyHandle, mechanism, plaintext.AsSpan(0, chunkLength), plaintext.AsSpan(chunkLength));

        if (runOperationState)
        {
            using Pkcs11Session operationStateSession = module.OpenSession(slotId);
            LoginUser(operationStateSession, pinUtf8);
            operationStateSession.EncryptInit(keyHandle, mechanism);

            byte[] firstOutput = new byte[chunkLength];
            if (!operationStateSession.TryEncryptUpdate(plaintext.AsSpan(0, chunkLength), firstOutput, out int firstWritten))
            {
                Console.WriteLine($"  Operation-state smoke failed: first update needs {firstWritten} bytes.");
                return;
            }

            int stateLength;
            try
            {
                stateLength = operationStateSession.GetOperationStateLength();
            }
            catch (Pkcs11Exception ex) when (IsOperationStateUnavailable(ex))
            {
                Console.WriteLine("  Operation-state smoke skipped: module reports operation state as unavailable.");
                stateLength = -1;
            }

            if (stateLength >= 0)
            {
                byte[] state = new byte[stateLength];
                if (!operationStateSession.TryGetOperationState(state, out int stateWritten))
                {
                    Console.WriteLine($"  Operation-state smoke failed: state buffer needs {stateWritten} bytes.");
                    return;
                }

                using Pkcs11Session resumedSession = module.OpenSession(slotId);
                LoginUser(resumedSession, pinUtf8);
                resumedSession.SetOperationState(state.AsSpan(0, stateWritten), encryptionKeyHandle: keyHandle);

                byte[] resumedCiphertext = new byte[baselineCiphertext.Length];
                firstOutput.AsSpan(0, firstWritten).CopyTo(resumedCiphertext);
                if (!resumedSession.TryEncryptUpdate(plaintext.AsSpan(chunkLength), resumedCiphertext.AsSpan(firstWritten), out int secondWritten))
                {
                    Console.WriteLine($"  Operation-state smoke failed: second update needs {secondWritten} bytes.");
                    return;
                }

                if (!resumedSession.TryEncryptFinal(resumedCiphertext.AsSpan(firstWritten + secondWritten), out int finalWritten))
                {
                    Console.WriteLine($"  Operation-state smoke failed: final needs {finalWritten} bytes.");
                    return;
                }

                bool matchesBaseline = baselineCiphertext.AsSpan().SequenceEqual(resumedCiphertext.AsSpan(0, firstWritten + secondWritten + finalWritten));
                Console.WriteLine($"  Operation-state smoke: state={stateWritten} bytes, matchesBaseline={matchesBaseline}");
                resumedSession.Logout();
            }

            operationStateSession.Logout();
        }

        if (runMultipart)
        {
            byte[] decrypted = DecryptMultipart(session, keyHandle, mechanism, baselineCiphertext.AsSpan(0, chunkLength), baselineCiphertext.AsSpan(chunkLength));
            bool roundTrip = plaintext.AsSpan().SequenceEqual(decrypted);
            Console.WriteLine($"  Multipart smoke: handle={keyHandle.Value}, ciphertext={baselineCiphertext.Length} bytes, plaintext={decrypted.Length} bytes, roundTrip={roundTrip}");
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  Multipart/operation-state failed: {ex.GetType().Name}: {ex.Message}");
    }
}

static void TryRunSignVerifySmoke(Pkcs11Module module, Pkcs11SlotId slotId, ReadOnlySpan<byte> pinUtf8)
{
    string? mechanismText = Environment.GetEnvironmentVariable("PKCS11_SIGN_MECHANISM");
    if (string.IsNullOrWhiteSpace(mechanismText))
    {
        Console.WriteLine("  Sign/verify skipped: PKCS11_SIGN_MECHANISM is not set.");
        return;
    }

    if (!TryParseNuint(mechanismText, out nuint mechanismValue))
    {
        Console.WriteLine("  Sign/verify skipped: PKCS11_SIGN_MECHANISM is invalid.");
        return;
    }

    Pkcs11ObjectSearchParameters signSearch = GetSearchParameters("PKCS11_SIGN_");
    Pkcs11ObjectSearchParameters verifySearch = GetSearchParameters("PKCS11_VERIFY_");
    using Pkcs11Session session = module.OpenSession(slotId);
    LoginUser(session, pinUtf8);

    WriteSearchResults(session, "sign", signSearch);
    WriteSearchResults(session, "verify", verifySearch);

    if (!TryResolveKeyHandle(session, signSearch, "PKCS11_SIGN_KEY_HANDLE", out Pkcs11ObjectHandle signKeyHandle))
    {
        Console.WriteLine("  Sign/verify skipped: no signing key handle is available.");
        return;
    }

    if (!TryResolveKeyHandle(session, verifySearch, "PKCS11_VERIFY_KEY_HANDLE", out Pkcs11ObjectHandle verifyKeyHandle))
    {
        Console.WriteLine("  Sign/verify skipped: no verification key handle is available.");
        return;
    }

    byte[] mechanismParameter = ParseHex(Environment.GetEnvironmentVariable("PKCS11_SIGN_MECHANISM_PARAM_HEX"));
    byte[] data = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("PKCS11_SIGN_DATA") ?? "pkcs11-wrapper-sign-smoke");
    Pkcs11Mechanism mechanism = new(new Pkcs11MechanismType(mechanismValue), mechanismParameter);

    try
    {
        byte[] signature = new byte[session.GetSignOutputLength(signKeyHandle, mechanism, data)];
        if (!session.TrySign(signKeyHandle, mechanism, data, signature, out int signatureWritten))
        {
            Console.WriteLine($"  Sign failed: caller buffer too small, requires {signatureWritten} bytes.");
            return;
        }

        bool verified = session.Verify(verifyKeyHandle, mechanism, data, signature.AsSpan(0, signatureWritten));
        byte[] invalidSignature = signature.AsSpan(0, signatureWritten).ToArray();
        invalidSignature[0] ^= 0x5a;
        bool invalidVerified = session.Verify(verifyKeyHandle, mechanism, data, invalidSignature);

        string? multipartFlag = Environment.GetEnvironmentVariable("PKCS11_SIGN_MULTIPART");
        bool runMultipart = string.IsNullOrWhiteSpace(multipartFlag) || ParseBooleanFlag(multipartFlag);
        if (runMultipart)
        {
            int splitIndex = Math.Max(1, data.Length / 2);
            session.SignInit(signKeyHandle, mechanism);
            session.SignUpdate(data.AsSpan(0, splitIndex));
            session.SignUpdate(ReadOnlySpan<byte>.Empty);
            session.SignUpdate(data.AsSpan(splitIndex));

            byte[] multipartSignature = new byte[signatureWritten];
            if (!session.TrySignFinal(multipartSignature, out int multipartWritten))
            {
                Console.WriteLine($"  Multipart sign failed: caller buffer too small, requires {multipartWritten} bytes.");
                return;
            }

            session.VerifyInit(verifyKeyHandle, mechanism);
            session.VerifyUpdate(data.AsSpan(0, splitIndex));
            session.VerifyUpdate(ReadOnlySpan<byte>.Empty);
            session.VerifyUpdate(data.AsSpan(splitIndex));
            bool multipartVerified = session.VerifyFinal(multipartSignature.AsSpan(0, multipartWritten));

            bool signaturesMatch = signature.AsSpan(0, signatureWritten).SequenceEqual(multipartSignature.AsSpan(0, multipartWritten));

            multipartSignature[0] ^= 0x5a;
            session.VerifyInit(verifyKeyHandle, mechanism);
            session.VerifyUpdate(data.AsSpan(0, splitIndex));
            session.VerifyUpdate(data.AsSpan(splitIndex));
            bool multipartInvalidVerified = session.VerifyFinal(multipartSignature.AsSpan(0, multipartWritten));

            session.VerifyInit(verifyKeyHandle, mechanism);
            session.VerifyUpdate(data.AsSpan(0, splitIndex));
            session.VerifyUpdate(data.AsSpan(splitIndex));
            bool multipartShortVerified = session.VerifyFinal(signature.AsSpan(0, Math.Max(signatureWritten - 1, 0)));

            Console.WriteLine($"  Multipart sign/verify smoke: signature={multipartWritten} bytes, matchesSinglePart={signaturesMatch}, verified={multipartVerified}, invalidVerified={multipartInvalidVerified}, shortVerified={multipartShortVerified}");
        }

        Console.WriteLine($"  Sign/verify smoke: signHandle={signKeyHandle.Value}, verifyHandle={verifyKeyHandle.Value}, signature={signatureWritten} bytes, verified={verified}, invalidVerified={invalidVerified}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  Sign/verify failed: {ex.GetType().Name}: {ex.Message}");
    }
    finally
    {
        try
        {
            session.Logout();
        }
        catch
        {
        }
    }
}

static void TryRunDigestSmoke(Pkcs11Session session)
{
    string mechanismText = Environment.GetEnvironmentVariable("PKCS11_DIGEST_MECHANISM") ?? "0x250";
    if (!TryParseNuint(mechanismText, out nuint mechanismValue))
    {
        Console.WriteLine("  Digest skipped: PKCS11_DIGEST_MECHANISM is invalid.");
        return;
    }

    byte[] mechanismParameter = ParseHex(Environment.GetEnvironmentVariable("PKCS11_DIGEST_MECHANISM_PARAM_HEX"));
    byte[] data = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("PKCS11_DIGEST_DATA") ?? "pkcs11-wrapper-digest-smoke");
    Pkcs11Mechanism mechanism = new(new Pkcs11MechanismType(mechanismValue), mechanismParameter);

    try
    {
        byte[] singlePart = new byte[session.GetDigestOutputLength(mechanism, data)];
        if (!session.TryDigest(mechanism, data, singlePart, out int singlePartWritten))
        {
            Console.WriteLine($"  Digest failed: caller buffer too small, requires {singlePartWritten} bytes.");
            return;
        }

        int splitIndex = Math.Max(1, data.Length / 2);
        session.DigestInit(mechanism);
        session.DigestUpdate(data.AsSpan(0, splitIndex));
        session.DigestUpdate(ReadOnlySpan<byte>.Empty);
        session.DigestUpdate(data.AsSpan(splitIndex));

        byte[] multipart = new byte[singlePartWritten];
        if (!session.TryDigestFinal(multipart, out int multipartWritten))
        {
            Console.WriteLine($"  Digest final failed: caller buffer too small, requires {multipartWritten} bytes.");
            return;
        }

        bool matchesMultipart = singlePart.AsSpan(0, singlePartWritten).SequenceEqual(multipart.AsSpan(0, multipartWritten));
        bool? matchesManaged = TryComputeManagedDigest(new Pkcs11MechanismType(mechanismValue), data, out byte[]? managedDigest)
            ? managedDigest.AsSpan().SequenceEqual(singlePart.AsSpan(0, singlePartWritten))
            : null;

        string managedText = matchesManaged.HasValue ? matchesManaged.Value.ToString() : "n/a";
        Console.WriteLine($"  Digest smoke: mechanism=0x{mechanismValue:x}, digest={singlePartWritten} bytes, matchesMultipart={matchesMultipart}, matchesManaged={managedText}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  Digest failed: {ex.GetType().Name}: {ex.Message}");
    }
}

static void TryRunRandomSmoke(Pkcs11Session session)
{
    string randomLengthText = Environment.GetEnvironmentVariable("PKCS11_RANDOM_LENGTH") ?? "32";
    if (!int.TryParse(randomLengthText, out int randomLength) || randomLength < 0)
    {
        Console.WriteLine("  Random skipped: PKCS11_RANDOM_LENGTH is invalid.");
        return;
    }

    try
    {
        byte[] first = new byte[randomLength];
        byte[] second = new byte[randomLength];
        session.GenerateRandom(first);
        session.GenerateRandom(second);

        bool allZero = Array.TrueForAll(first, static value => value == 0) && Array.TrueForAll(second, static value => value == 0);
        bool distinct = !first.AsSpan().SequenceEqual(second);
        Console.WriteLine($"  Random smoke: length={randomLength}, allZero={allZero}, distinct={distinct}, first={Convert.ToHexString(first)}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  Random failed: {ex.GetType().Name}: {ex.Message}");
    }
}

static void TryRunObjectLifecycleSmoke(Pkcs11Module module, Pkcs11SlotId slotId, ReadOnlySpan<byte> pinUtf8)
{
    if (!ParseBooleanFlag(Environment.GetEnvironmentVariable("PKCS11_OBJECT_LIFECYCLE")))
    {
        return;
    }

    string label = Environment.GetEnvironmentVariable("PKCS11_OBJECT_LABEL") ?? $"pkcs11wrapper-smoke-{Guid.NewGuid():N}";
    string updatedLabel = label + "-updated";
    string application = Environment.GetEnvironmentVariable("PKCS11_OBJECT_APPLICATION") ?? "phase7";
    byte[] value = ParseHex(Environment.GetEnvironmentVariable("PKCS11_OBJECT_VALUE_HEX"));
    if (value.Length == 0)
    {
        value = [0x50, 0x37, 0x2D, 0x53];
    }

    byte[] labelUtf8 = Encoding.UTF8.GetBytes(label);
    byte[] updatedLabelUtf8 = Encoding.UTF8.GetBytes(updatedLabel);
    byte[] applicationUtf8 = Encoding.UTF8.GetBytes(application);

    using Pkcs11Session session = module.OpenSession(slotId, readWrite: true);
    LoginUser(session, pinUtf8);

    Pkcs11ObjectHandle handle = default;
    bool created = false;

    try
    {
        handle = session.CreateObject(
        [
            Pkcs11ObjectAttribute.ObjectClass(Pkcs11AttributeTypes.Class, Pkcs11ObjectClasses.Data),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Token, true),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Private, false),
            Pkcs11ObjectAttribute.Boolean(Pkcs11AttributeTypes.Modifiable, true),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, labelUtf8),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Application, applicationUtf8),
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Value, value)
        ]);

        created = true;
        bool foundAfterCreate = session.TryFindObject(new Pkcs11ObjectSearchParameters(label: labelUtf8, objectClass: Pkcs11ObjectClasses.Data), out Pkcs11ObjectHandle foundHandle);
        byte[]? readValue = ReadAttributeBytes(session, handle, Pkcs11AttributeTypes.Value);
        Console.WriteLine($"  Object lifecycle create: handle={handle.Value}, found={foundAfterCreate}, matchedHandle={foundHandle.Value == handle.Value}, size={session.GetObjectSize(handle)}");
        Console.WriteLine($"  Object lifecycle read: label='{ReadUtf8Attribute(session, handle, Pkcs11AttributeTypes.Label)}', application='{ReadUtf8Attribute(session, handle, Pkcs11AttributeTypes.Application)}', value={Convert.ToHexString(readValue ?? [])}");

        session.SetAttributeValue(handle,
        [
            Pkcs11ObjectAttribute.Bytes(Pkcs11AttributeTypes.Label, updatedLabelUtf8)
        ]);

        bool oldLabelFound = session.TryFindObject(new Pkcs11ObjectSearchParameters(label: labelUtf8, objectClass: Pkcs11ObjectClasses.Data), out _);
        bool newLabelFound = session.TryFindObject(new Pkcs11ObjectSearchParameters(label: updatedLabelUtf8, objectClass: Pkcs11ObjectClasses.Data), out Pkcs11ObjectHandle updatedHandle);
        Console.WriteLine($"  Object lifecycle update: oldLabelFound={oldLabelFound}, newLabelFound={newLabelFound}, matchedHandle={updatedHandle.Value == handle.Value}, updatedLabel='{ReadUtf8Attribute(session, handle, Pkcs11AttributeTypes.Label)}'");

        session.DestroyObject(handle);
        created = false;

        bool foundAfterDestroy = session.TryFindObject(new Pkcs11ObjectSearchParameters(label: updatedLabelUtf8, objectClass: Pkcs11ObjectClasses.Data), out _);
        Console.WriteLine($"  Object lifecycle destroy: foundAfterDestroy={foundAfterDestroy}");
        session.Logout();
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  Object lifecycle failed: {ex.GetType().Name}: {ex.Message}");
        try
        {
            if (created)
            {
                TryDestroyObject(session, handle);
                TryDestroyDataObjectByLabel(session, updatedLabelUtf8);
                TryDestroyDataObjectByLabel(session, labelUtf8);
            }
        }
        catch (Exception cleanupEx)
        {
            Console.WriteLine($"  Object lifecycle cleanup failed: {cleanupEx.GetType().Name}: {cleanupEx.Message}");
        }

        try
        {
            session.Logout();
        }
        catch
        {
        }
    }
}

static void TryRunGenerateKeySmoke(Pkcs11Module module, Pkcs11SlotId slotId, ReadOnlySpan<byte> pinUtf8)
{
    if (!ParseBooleanFlag(Environment.GetEnvironmentVariable("PKCS11_GENERATE_KEYS")))
    {
        return;
    }

    using Pkcs11Session session = module.OpenSession(slotId, readWrite: true);
    LoginUser(session, pinUtf8);

    try
    {
        RunGenerateAesSmoke(session);
        RunGenerateRsaSmoke(session);
        session.Logout();
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  Key generation smoke failed: {ex.GetType().Name}: {ex.Message}");

        try
        {
            session.Logout();
        }
        catch
        {
        }
    }
}

static void TryRunWrapUnwrapSmoke(Pkcs11Module module, Pkcs11SlotId slotId, ReadOnlySpan<byte> pinUtf8)
{
    if (!ParseBooleanFlag(Environment.GetEnvironmentVariable("PKCS11_WRAP_UNWRAP")))
    {
        return;
    }

    using Pkcs11Session session = module.OpenSession(slotId, readWrite: true);
    LoginUser(session, pinUtf8);

    byte[] wrappingLabel = GetUtf8Bytes(Environment.GetEnvironmentVariable("PKCS11_WRAP_KEY_LABEL") ?? "ci-aes");
    byte[] wrappingId = ParseHex(Environment.GetEnvironmentVariable("PKCS11_WRAP_KEY_ID_HEX") ?? "A1");
    Pkcs11ObjectSearchParameters wrappingSearch = new(
        label: wrappingLabel,
        id: wrappingId,
        objectClass: Pkcs11ObjectClasses.SecretKey,
        keyType: Pkcs11KeyTypes.Aes,
        requireWrap: true,
        requireUnwrap: true);

    if (!session.TryFindObject(wrappingSearch, out Pkcs11ObjectHandle wrappingKeyHandle))
    {
        Console.WriteLine("  Wrap/unwrap skipped: wrapping key was not found.");
        return;
    }

    Pkcs11Mechanism generationMechanism = new(Pkcs11MechanismTypes.AesKeyGen);
    Pkcs11Mechanism wrapMechanism = new(Pkcs11MechanismTypes.AesKeyWrapPad);
    byte[] iv = ParseHex(Environment.GetEnvironmentVariable("PKCS11_WRAP_UNWRAP_IV_HEX") ?? "00112233445566778899AABBCCDDEEFF");
    byte[] plaintext = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("PKCS11_WRAP_UNWRAP_PLAINTEXT") ?? "pkcs11-wrapper-wrap-unwrap-smoke");
    Pkcs11Mechanism cryptMechanism = new(Pkcs11MechanismTypes.AesCbcPad, iv);

    string sourceLabel = Environment.GetEnvironmentVariable("PKCS11_WRAP_SOURCE_LABEL") ?? $"pkcs11wrapper-wrap-src-{Guid.NewGuid():N}";
    byte[] sourceLabelUtf8 = Encoding.ASCII.GetBytes(sourceLabel);
    byte[] sourceId = ParseHex(Environment.GetEnvironmentVariable("PKCS11_WRAP_SOURCE_ID_HEX"));
    if (sourceId.Length == 0)
    {
        sourceId = Guid.NewGuid().ToByteArray();
    }

    string unwrappedLabel = $"pkcs11wrapper-wrap-dst-{Guid.NewGuid():N}";
    byte[] unwrappedLabelUtf8 = Encoding.ASCII.GetBytes(unwrappedLabel);
    byte[] unwrappedId = Guid.NewGuid().ToByteArray();

    Pkcs11ObjectSearchParameters sourceSearch = new(sourceLabelUtf8, sourceId, Pkcs11ObjectClasses.SecretKey, Pkcs11KeyTypes.Aes, true, true);
    Pkcs11ObjectHandle sourceKeyHandle = default;
    Pkcs11ObjectHandle unwrappedKeyHandle = default;
    bool sourceCreated = false;
    bool unwrappedCreated = false;

    try
    {
        if (!session.TryFindObject(sourceSearch, out sourceKeyHandle))
        {
            sourceKeyHandle = session.GenerateKey(
                generationMechanism,
                Pkcs11ProvisioningTemplates.CreateAesEncryptDecryptSecretKey(sourceLabelUtf8, sourceId, token: false, extractable: true, valueLength: 32));

            sourceCreated = true;
        }

        int wrappedLength = session.GetWrapOutputLength(wrappingKeyHandle, wrapMechanism, sourceKeyHandle);
        byte[] wrappedKey = new byte[wrappedLength];
        if (!session.TryWrapKey(wrappingKeyHandle, wrapMechanism, sourceKeyHandle, wrappedKey, out int wrappedWritten))
        {
            Console.WriteLine($"  Wrap/unwrap failed: wrap buffer too small, requires {wrappedWritten} bytes.");
            return;
        }

        unwrappedKeyHandle = session.UnwrapKey(
            wrappingKeyHandle,
            wrapMechanism,
            wrappedKey.AsSpan(0, wrappedWritten),
            Pkcs11ProvisioningTemplates.CreateAesUnwrapTargetSecretKey(unwrappedLabelUtf8, unwrappedId, token: false, extractable: false));

        unwrappedCreated = true;

        byte[] ciphertext = new byte[session.GetEncryptOutputLength(unwrappedKeyHandle, cryptMechanism, plaintext)];
        if (!session.TryEncrypt(unwrappedKeyHandle, cryptMechanism, plaintext, ciphertext, out int ciphertextWritten))
        {
            Console.WriteLine($"  Wrap/unwrap failed: encrypt buffer too small, requires {ciphertextWritten} bytes.");
            return;
        }

        byte[] decrypted = new byte[session.GetDecryptOutputLength(unwrappedKeyHandle, cryptMechanism, ciphertext.AsSpan(0, ciphertextWritten))];
        if (!session.TryDecrypt(unwrappedKeyHandle, cryptMechanism, ciphertext.AsSpan(0, ciphertextWritten), decrypted, out int decryptedWritten))
        {
            Console.WriteLine($"  Wrap/unwrap failed: decrypt buffer too small, requires {decryptedWritten} bytes.");
            return;
        }

        bool roundTrip = plaintext.AsSpan().SequenceEqual(decrypted.AsSpan(0, decryptedWritten));
        Console.WriteLine($"  Wrap/unwrap smoke: wrappingHandle={wrappingKeyHandle.Value}, sourceHandle={sourceKeyHandle.Value}, unwrappedHandle={unwrappedKeyHandle.Value}, wrapped={wrappedWritten} bytes, roundTrip={roundTrip}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  Wrap/unwrap failed: {ex.GetType().Name}: {ex.Message}");
    }
    finally
    {
        try
        {
            if (unwrappedCreated)
            {
                TryDestroyObject(session, unwrappedKeyHandle);
                TryDestroyObjectBySearch(session, new Pkcs11ObjectSearchParameters(unwrappedLabelUtf8, unwrappedId, Pkcs11ObjectClasses.SecretKey, Pkcs11KeyTypes.Aes));
            }

            if (sourceCreated)
            {
                TryDestroyObject(session, sourceKeyHandle);
                TryDestroyObjectBySearch(session, sourceSearch);
            }

            session.Logout();
        }
        catch
        {
        }
    }
}

static void TryRunDeriveKeySmoke(Pkcs11Module module, Pkcs11SlotId slotId, ReadOnlySpan<byte> pinUtf8)
{
    if (!ParseBooleanFlag(Environment.GetEnvironmentVariable("PKCS11_DERIVE_EC")))
    {
        return;
    }

    using Pkcs11Session session = module.OpenSession(slotId, readWrite: true);
    LoginUser(session, pinUtf8);

    try
    {
        RunDeriveEcSmoke(session);
        session.Logout();
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  Derive key smoke failed: {ex.GetType().Name}: {ex.Message}");

        try
        {
            session.Logout();
        }
        catch
        {
        }
    }
}

static void RunGenerateAesSmoke(Pkcs11Session session)
{
    string label = Environment.GetEnvironmentVariable("PKCS11_GENERATE_AES_LABEL") ?? $"pkcs11wrapper-generate-aes-{Guid.NewGuid():N}";
    byte[] labelUtf8 = Encoding.UTF8.GetBytes(label);
    byte[] id = ParseHex(Environment.GetEnvironmentVariable("PKCS11_GENERATE_AES_ID_HEX"));
    if (id.Length == 0)
    {
        id = Guid.NewGuid().ToByteArray();
    }

    byte[] iv = ParseHex(Environment.GetEnvironmentVariable("PKCS11_GENERATE_AES_IV_HEX") ?? "00112233445566778899AABBCCDDEEFF");
    byte[] plaintext = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("PKCS11_GENERATE_AES_PLAINTEXT") ?? "pkcs11-wrapper-generate-aes-smoke");
    Pkcs11ObjectSearchParameters search = new(labelUtf8, id, Pkcs11ObjectClasses.SecretKey, Pkcs11KeyTypes.Aes, true, true);
    Pkcs11ObjectHandle handle = default;
    bool created = false;

    try
    {
        handle = session.GenerateKey(
            new Pkcs11Mechanism(Pkcs11MechanismTypes.AesKeyGen),
            Pkcs11ProvisioningTemplates.CreateAesEncryptDecryptSecretKey(labelUtf8, id, token: true, extractable: false, valueLength: 32));

        created = true;
        bool found = session.TryFindObject(search, out Pkcs11ObjectHandle foundHandle);
        Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.AesCbcPad, iv);
        byte[] ciphertext = new byte[session.GetEncryptOutputLength(handle, mechanism, plaintext)];
        session.TryEncrypt(handle, mechanism, plaintext, ciphertext, out int ciphertextWritten);
        byte[] decrypted = new byte[session.GetDecryptOutputLength(handle, mechanism, ciphertext.AsSpan(0, ciphertextWritten))];
        session.TryDecrypt(handle, mechanism, ciphertext.AsSpan(0, ciphertextWritten), decrypted, out int decryptedWritten);
        bool roundTrip = plaintext.AsSpan().SequenceEqual(decrypted.AsSpan(0, decryptedWritten));

        Console.WriteLine($"  Generate key smoke: handle={handle.Value}, found={found}, matchedHandle={foundHandle.Value == handle.Value}, roundTrip={roundTrip}");

        session.DestroyObject(handle);
        created = false;
    }
    finally
    {
        if (created)
        {
            TryDestroyObject(session, handle);
            TryDestroyObjectBySearch(session, search);
        }
    }
}

static void RunGenerateRsaSmoke(Pkcs11Session session)
{
    string label = Environment.GetEnvironmentVariable("PKCS11_GENERATE_RSA_LABEL") ?? $"pkcs11wrapper-generate-rsa-{Guid.NewGuid():N}";
    byte[] labelUtf8 = Encoding.UTF8.GetBytes(label);
    byte[] id = ParseHex(Environment.GetEnvironmentVariable("PKCS11_GENERATE_RSA_ID_HEX"));
    if (id.Length == 0)
    {
        id = Guid.NewGuid().ToByteArray();
    }

    byte[] data = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("PKCS11_GENERATE_RSA_SIGN_DATA") ?? "pkcs11-wrapper-generate-rsa-smoke");
    Pkcs11ObjectSearchParameters publicSearch = new(labelUtf8, id, Pkcs11ObjectClasses.PublicKey, Pkcs11KeyTypes.Rsa, null, null, null, true);
    Pkcs11ObjectSearchParameters privateSearch = new(labelUtf8, id, Pkcs11ObjectClasses.PrivateKey, Pkcs11KeyTypes.Rsa, null, null, true, null);
    Pkcs11GeneratedKeyPair keyPair = default;
    bool created = false;

    try
    {
        Pkcs11KeyPairTemplate templates = Pkcs11ProvisioningTemplates.CreateRsaSignVerifyKeyPair(labelUtf8, id, token: true, modulusBits: 2048);
        keyPair = session.GenerateKeyPair(
            new Pkcs11Mechanism(Pkcs11MechanismTypes.RsaPkcsKeyPairGen),
            templates.PublicKeyAttributes,
            templates.PrivateKeyAttributes);

        created = true;
        bool publicFound = session.TryFindObject(publicSearch, out Pkcs11ObjectHandle foundPublic);
        bool privateFound = session.TryFindObject(privateSearch, out Pkcs11ObjectHandle foundPrivate);
        Pkcs11Mechanism mechanism = new(Pkcs11MechanismTypes.Sha256RsaPkcs);
        byte[] signature = new byte[session.GetSignOutputLength(keyPair.PrivateKeyHandle, mechanism, data)];
        session.TrySign(keyPair.PrivateKeyHandle, mechanism, data, signature, out int signatureWritten);
        bool verified = session.Verify(keyPair.PublicKeyHandle, mechanism, data, signature.AsSpan(0, signatureWritten));

        Console.WriteLine($"  Generate key pair smoke: publicFound={publicFound}, privateFound={privateFound}, publicMatch={foundPublic.Value == keyPair.PublicKeyHandle.Value}, privateMatch={foundPrivate.Value == keyPair.PrivateKeyHandle.Value}, verified={verified}");

        session.DestroyObject(keyPair.PrivateKeyHandle);
        session.DestroyObject(keyPair.PublicKeyHandle);
        created = false;
    }
    finally
    {
        if (created)
        {
            TryDestroyObject(session, keyPair.PrivateKeyHandle);
            TryDestroyObject(session, keyPair.PublicKeyHandle);
            TryDestroyObjectBySearch(session, privateSearch);
            TryDestroyObjectBySearch(session, publicSearch);
        }
    }
}

static void RunDeriveEcSmoke(Pkcs11Session session)
{
    string leftLabel = Environment.GetEnvironmentVariable("PKCS11_DERIVE_EC_LEFT_LABEL") ?? $"pkcs11wrapper-derive-left-{Guid.NewGuid():N}";
    string rightLabel = Environment.GetEnvironmentVariable("PKCS11_DERIVE_EC_RIGHT_LABEL") ?? $"pkcs11wrapper-derive-right-{Guid.NewGuid():N}";
    byte[] leftLabelUtf8 = Encoding.ASCII.GetBytes(leftLabel);
    byte[] rightLabelUtf8 = Encoding.ASCII.GetBytes(rightLabel);
    byte[] leftId = ParseHex(Environment.GetEnvironmentVariable("PKCS11_DERIVE_EC_LEFT_ID_HEX"));
    byte[] rightId = ParseHex(Environment.GetEnvironmentVariable("PKCS11_DERIVE_EC_RIGHT_ID_HEX"));
    if (leftId.Length == 0)
    {
        leftId = Guid.NewGuid().ToByteArray();
    }

    if (rightId.Length == 0)
    {
        rightId = Guid.NewGuid().ToByteArray();
    }

    byte[] leftDerivedLabel = Encoding.ASCII.GetBytes($"{leftLabel}-aes");
    byte[] rightDerivedLabel = Encoding.ASCII.GetBytes($"{rightLabel}-aes");
    byte[] leftDerivedId = Guid.NewGuid().ToByteArray();
    byte[] rightDerivedId = Guid.NewGuid().ToByteArray();
    byte[] iv = ParseHex(Environment.GetEnvironmentVariable("PKCS11_DERIVE_EC_IV_HEX") ?? "00112233445566778899AABBCCDDEEFF");
    byte[] plaintext = Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("PKCS11_DERIVE_EC_PLAINTEXT") ?? "pkcs11-wrapper-derive-ecdh-smoke");
    byte[] curveParameters = Pkcs11EcNamedCurves.Prime256v1Parameters;
    Pkcs11GeneratedKeyPair leftKeyPair = default;
    Pkcs11GeneratedKeyPair rightKeyPair = default;
    Pkcs11ObjectHandle leftDerivedHandle = default;
    Pkcs11ObjectHandle rightDerivedHandle = default;
    bool leftPairCreated = false;
    bool rightPairCreated = false;
    bool leftDerivedCreated = false;
    bool rightDerivedCreated = false;

    try
    {
        Pkcs11KeyPairTemplate leftTemplates = Pkcs11ProvisioningTemplates.CreateEcDeriveKeyPair(curveParameters, leftLabelUtf8, leftId, token: false);
        Pkcs11KeyPairTemplate rightTemplates = Pkcs11ProvisioningTemplates.CreateEcDeriveKeyPair(curveParameters, rightLabelUtf8, rightId, token: false);
        leftKeyPair = session.GenerateKeyPair(new Pkcs11Mechanism(Pkcs11MechanismTypes.EcKeyPairGen), leftTemplates.PublicKeyAttributes, leftTemplates.PrivateKeyAttributes);
        rightKeyPair = session.GenerateKeyPair(new Pkcs11Mechanism(Pkcs11MechanismTypes.EcKeyPairGen), rightTemplates.PublicKeyAttributes, rightTemplates.PrivateKeyAttributes);
        leftPairCreated = true;
        rightPairCreated = true;

        byte[] leftPublicPoint = Pkcs11EcNamedCurves.DecodeEcPointAttribute(GetRequiredAttributeBytes(session, leftKeyPair.PublicKeyHandle, Pkcs11AttributeTypes.EcPoint));
        byte[] rightPublicPoint = Pkcs11EcNamedCurves.DecodeEcPointAttribute(GetRequiredAttributeBytes(session, rightKeyPair.PublicKeyHandle, Pkcs11AttributeTypes.EcPoint));

        leftDerivedHandle = session.DeriveKey(
            leftKeyPair.PrivateKeyHandle,
            new Pkcs11Mechanism(Pkcs11MechanismTypes.Ecdh1Derive, Pkcs11MechanismParameters.Ecdh1Derive(rightPublicPoint)),
            Pkcs11ProvisioningTemplates.CreateAesEncryptDecryptSecretKey(leftDerivedLabel, leftDerivedId, token: false, extractable: false, valueLength: 32));
        leftDerivedCreated = true;

        rightDerivedHandle = session.DeriveKey(
            rightKeyPair.PrivateKeyHandle,
            new Pkcs11Mechanism(Pkcs11MechanismTypes.Ecdh1Derive, Pkcs11MechanismParameters.Ecdh1Derive(leftPublicPoint)),
            Pkcs11ProvisioningTemplates.CreateAesEncryptDecryptSecretKey(rightDerivedLabel, rightDerivedId, token: false, extractable: false, valueLength: 32));
        rightDerivedCreated = true;

        Pkcs11Mechanism cryptMechanism = new(Pkcs11MechanismTypes.AesCbcPad, iv);
        byte[] ciphertext = new byte[session.GetEncryptOutputLength(leftDerivedHandle, cryptMechanism, plaintext)];
        session.TryEncrypt(leftDerivedHandle, cryptMechanism, plaintext, ciphertext, out int ciphertextWritten);
        byte[] decrypted = new byte[session.GetDecryptOutputLength(rightDerivedHandle, cryptMechanism, ciphertext.AsSpan(0, ciphertextWritten))];
        session.TryDecrypt(rightDerivedHandle, cryptMechanism, ciphertext.AsSpan(0, ciphertextWritten), decrypted, out int decryptedWritten);
        bool roundTrip = plaintext.AsSpan().SequenceEqual(decrypted.AsSpan(0, decryptedWritten));

        Console.WriteLine($"  Derive key smoke: leftPublic={leftKeyPair.PublicKeyHandle.Value}, rightPublic={rightKeyPair.PublicKeyHandle.Value}, leftDerived={leftDerivedHandle.Value}, rightDerived={rightDerivedHandle.Value}, roundTrip={roundTrip}");
    }
    finally
    {
        if (rightDerivedCreated)
        {
            TryDestroyObject(session, rightDerivedHandle);
            TryDestroyObjectBySearch(session, new Pkcs11ObjectSearchParameters(rightDerivedLabel, rightDerivedId, Pkcs11ObjectClasses.SecretKey, Pkcs11KeyTypes.Aes));
        }

        if (leftDerivedCreated)
        {
            TryDestroyObject(session, leftDerivedHandle);
            TryDestroyObjectBySearch(session, new Pkcs11ObjectSearchParameters(leftDerivedLabel, leftDerivedId, Pkcs11ObjectClasses.SecretKey, Pkcs11KeyTypes.Aes));
        }

        if (rightPairCreated)
        {
            TryDestroyObject(session, rightKeyPair.PrivateKeyHandle);
            TryDestroyObject(session, rightKeyPair.PublicKeyHandle);
            TryDestroyObjectBySearch(session, new Pkcs11ObjectSearchParameters(rightLabelUtf8, rightId, Pkcs11ObjectClasses.PrivateKey, Pkcs11KeyTypes.Ec));
            TryDestroyObjectBySearch(session, new Pkcs11ObjectSearchParameters(rightLabelUtf8, rightId, Pkcs11ObjectClasses.PublicKey, Pkcs11KeyTypes.Ec));
        }

        if (leftPairCreated)
        {
            TryDestroyObject(session, leftKeyPair.PrivateKeyHandle);
            TryDestroyObject(session, leftKeyPair.PublicKeyHandle);
            TryDestroyObjectBySearch(session, new Pkcs11ObjectSearchParameters(leftLabelUtf8, leftId, Pkcs11ObjectClasses.PrivateKey, Pkcs11KeyTypes.Ec));
            TryDestroyObjectBySearch(session, new Pkcs11ObjectSearchParameters(leftLabelUtf8, leftId, Pkcs11ObjectClasses.PublicKey, Pkcs11KeyTypes.Ec));
        }
    }
}

static bool TryResolveKeyHandle(Pkcs11Session session, Pkcs11ObjectSearchParameters searchCriteria, string handleVariableName, out Pkcs11ObjectHandle handle)
{
    string? explicitHandle = Environment.GetEnvironmentVariable(handleVariableName);
    if (!string.IsNullOrWhiteSpace(explicitHandle))
    {
        if (TryParseNuint(explicitHandle, out nuint value))
        {
            handle = new Pkcs11ObjectHandle(value);
            return true;
        }

        Console.WriteLine($"  Explicit {handleVariableName} is invalid.");
    }

    return session.TryFindObject(searchCriteria, out handle);
}

static void LoginUser(Pkcs11Session session, ReadOnlySpan<byte> pinUtf8)
{
    try
    {
        session.Login(Pkcs11UserType.User, pinUtf8);
    }
    catch (Pkcs11Exception ex) when (ex.Result.Value is 0x000000a0u or 0x00000100u)
    {
    }
}

static bool IsOperationStateUnavailable(Pkcs11Exception exception)
    => exception.Result.Value == 0x00000054u;

static byte[] EncryptMultipart(Pkcs11Session session, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> chunk1, ReadOnlySpan<byte> chunk2)
{
    session.EncryptInit(keyHandle, mechanism);

    byte[] ciphertext = new byte[chunk1.Length + chunk2.Length + 32];
    if (!session.TryEncryptUpdate(chunk1, ciphertext, out int firstWritten))
    {
        throw new InvalidOperationException($"Multipart encrypt update requires {firstWritten} bytes for chunk 1.");
    }

    if (!session.TryEncryptUpdate(chunk2, ciphertext.AsSpan(firstWritten), out int secondWritten))
    {
        throw new InvalidOperationException($"Multipart encrypt update requires {secondWritten} bytes for chunk 2.");
    }

    if (!session.TryEncryptFinal(ciphertext.AsSpan(firstWritten + secondWritten), out int finalWritten))
    {
        throw new InvalidOperationException($"Multipart encrypt final requires {finalWritten} bytes.");
    }

    return ciphertext.AsSpan(0, firstWritten + secondWritten + finalWritten).ToArray();
}

static byte[] DecryptMultipart(Pkcs11Session session, Pkcs11ObjectHandle keyHandle, Pkcs11Mechanism mechanism, ReadOnlySpan<byte> chunk1, ReadOnlySpan<byte> chunk2)
{
    session.DecryptInit(keyHandle, mechanism);

    byte[] plaintext = new byte[chunk1.Length + chunk2.Length + 32];
    if (!session.TryDecryptUpdate(chunk1, plaintext, out int firstWritten))
    {
        throw new InvalidOperationException($"Multipart decrypt update requires {firstWritten} bytes for chunk 1.");
    }

    if (!session.TryDecryptUpdate(chunk2, plaintext.AsSpan(firstWritten), out int secondWritten))
    {
        throw new InvalidOperationException($"Multipart decrypt update requires {secondWritten} bytes for chunk 2.");
    }

    if (!session.TryDecryptFinal(plaintext.AsSpan(firstWritten + secondWritten), out int finalWritten))
    {
        throw new InvalidOperationException($"Multipart decrypt final requires {finalWritten} bytes.");
    }

    return plaintext.AsSpan(0, firstWritten + secondWritten + finalWritten).ToArray();
}

static bool ParseBooleanFlag(string? value)
{
    return value?.Trim().ToLowerInvariant() switch
    {
        "1" or "true" or "yes" or "y" => true,
        _ => false,
    };
}

static byte[] GetMultipartPlaintext()
{
    string? plaintextHex = Environment.GetEnvironmentVariable("PKCS11_MULTIPART_PLAINTEXT_HEX");
    if (!string.IsNullOrWhiteSpace(plaintextHex))
    {
        return ParseHex(plaintextHex);
    }

    string? plaintextText = Environment.GetEnvironmentVariable("PKCS11_SMOKE_PLAINTEXT");
    if (!string.IsNullOrEmpty(plaintextText))
    {
        return Encoding.UTF8.GetBytes(plaintextText);
    }

    return Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
}

static bool TryParseNuint(string text, out nuint value)
{
    if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
    {
        return nuint.TryParse(text.AsSpan(2), NumberStyles.HexNumber, null, out value);
    }

    return nuint.TryParse(text, out value);
}

static byte[] ParseHex(string? text)
{
    if (string.IsNullOrWhiteSpace(text))
    {
        return [];
    }

    string normalized = text.Replace(" ", string.Empty, StringComparison.Ordinal).Replace("-", string.Empty, StringComparison.Ordinal);
    return Convert.FromHexString(normalized);
}

static bool TryComputeManagedDigest(Pkcs11MechanismType mechanismType, byte[] data, out byte[]? digest)
{
    if (mechanismType == Pkcs11MechanismTypes.Sha1)
    {
        digest = SHA1.HashData(data);
        return true;
    }

    if (mechanismType == Pkcs11MechanismTypes.Sha256)
    {
        digest = SHA256.HashData(data);
        return true;
    }

    if (mechanismType == Pkcs11MechanismTypes.Sha384)
    {
        digest = SHA384.HashData(data);
        return true;
    }

    if (mechanismType == Pkcs11MechanismTypes.Sha512)
    {
        digest = SHA512.HashData(data);
        return true;
    }

    digest = null;
    return false;
}

static string? ReadUtf8Attribute(Pkcs11Session session, Pkcs11ObjectHandle handle, Pkcs11AttributeType attributeType)
{
    byte[]? bytes = ReadAttributeBytes(session, handle, attributeType);
    return bytes is null ? null : Encoding.UTF8.GetString(bytes);
}

static void TryDestroyDataObjectByLabel(Pkcs11Session session, byte[] labelUtf8)
{
    if (session.TryFindObject(new Pkcs11ObjectSearchParameters(label: labelUtf8, objectClass: Pkcs11ObjectClasses.Data), out Pkcs11ObjectHandle handle))
    {
        TryDestroyObject(session, handle);
    }
}

static void TryDestroyObjectBySearch(Pkcs11Session session, Pkcs11ObjectSearchParameters search)
{
    if (session.TryFindObject(search, out Pkcs11ObjectHandle handle))
    {
        TryDestroyObject(session, handle);
    }
}

static void TryDestroyObject(Pkcs11Session session, Pkcs11ObjectHandle handle)
{
    if (handle.Value == 0)
    {
        return;
    }

    try
    {
        session.DestroyObject(handle);
    }
    catch (Pkcs11Exception ex) when (ex.Result.Value == 0x00000082u)
    {
    }
}

static Pkcs11ObjectSearchParameters GetSearchParameters(string prefix)
{
    byte[] label = GetUtf8Bytes(Environment.GetEnvironmentVariable(prefix + "FIND_LABEL"));
    byte[] id = ParseHex(Environment.GetEnvironmentVariable(prefix + "FIND_ID_HEX"));
    Pkcs11ObjectClass? objectClass = TryParseObjectClass(Environment.GetEnvironmentVariable(prefix + "FIND_CLASS"), out Pkcs11ObjectClass parsedClass) ? parsedClass : null;
    Pkcs11KeyType? keyType = TryParseKeyType(Environment.GetEnvironmentVariable(prefix + "FIND_KEY_TYPE"), out Pkcs11KeyType parsedKeyType) ? parsedKeyType : null;

    return new Pkcs11ObjectSearchParameters(
        label,
        id,
        objectClass,
        keyType,
        TryParseOptionalBool(Environment.GetEnvironmentVariable(prefix + "REQUIRE_ENCRYPT")),
        TryParseOptionalBool(Environment.GetEnvironmentVariable(prefix + "REQUIRE_DECRYPT")),
        TryParseOptionalBool(Environment.GetEnvironmentVariable(prefix + "REQUIRE_SIGN")),
        TryParseOptionalBool(Environment.GetEnvironmentVariable(prefix + "REQUIRE_VERIFY")));
}

static byte[] GetUtf8Bytes(string? value)
    => string.IsNullOrEmpty(value) ? [] : Encoding.UTF8.GetBytes(value);

static bool TryParseObjectClass(string? text, out Pkcs11ObjectClass value)
{
    switch (text?.Trim().ToLowerInvariant())
    {
        case null:
        case "":
            value = default;
            return false;
        case "data":
            value = Pkcs11ObjectClasses.Data;
            return true;
        case "certificate":
        case "cert":
            value = Pkcs11ObjectClasses.Certificate;
            return true;
        case "public":
        case "publickey":
        case "public-key":
            value = Pkcs11ObjectClasses.PublicKey;
            return true;
        case "private":
        case "privatekey":
        case "private-key":
            value = Pkcs11ObjectClasses.PrivateKey;
            return true;
        case "secret":
        case "secretkey":
        case "secret-key":
            value = Pkcs11ObjectClasses.SecretKey;
            return true;
        default:
            if (TryParseNuint(text, out nuint rawValue))
            {
                value = new Pkcs11ObjectClass(rawValue);
                return true;
            }

            value = default;
            return false;
    }
}

static bool TryParseKeyType(string? text, out Pkcs11KeyType value)
{
    switch (text?.Trim().ToLowerInvariant())
    {
        case null:
        case "":
            value = default;
            return false;
        case "rsa":
            value = Pkcs11KeyTypes.Rsa;
            return true;
        case "dsa":
            value = Pkcs11KeyTypes.Dsa;
            return true;
        case "dh":
            value = Pkcs11KeyTypes.Dh;
            return true;
        case "ec":
        case "ecdsa":
        case "ecc":
            value = Pkcs11KeyTypes.Ec;
            return true;
        case "aes":
            value = Pkcs11KeyTypes.Aes;
            return true;
        case "generic-secret":
        case "genericsecret":
            value = Pkcs11KeyTypes.GenericSecret;
            return true;
        default:
            if (TryParseNuint(text, out nuint rawValue))
            {
                value = new Pkcs11KeyType(rawValue);
                return true;
            }

            value = default;
            return false;
    }
}

static bool? TryParseOptionalBool(string? text)
{
    if (string.IsNullOrWhiteSpace(text))
    {
        return null;
    }

    return text.Trim().ToLowerInvariant() switch
    {
        "1" or "true" or "yes" or "y" => true,
        "0" or "false" or "no" or "n" => false,
        _ => null,
    };
}

readonly record struct SlotCandidate(Pkcs11SlotId SlotId, Pkcs11TokenInfo TokenInfo);
