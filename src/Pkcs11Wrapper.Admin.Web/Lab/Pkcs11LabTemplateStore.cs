using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using Pkcs11Wrapper.Admin.Application.Models;
using Pkcs11Wrapper.Admin.Infrastructure;

namespace Pkcs11Wrapper.Admin.Web.Lab;

public sealed class Pkcs11LabTemplateStore(IOptions<AdminStorageOptions> options)
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private static readonly JsonSerializerOptions SerializerOptions = CreateSerializerOptions();

    public async Task<IReadOnlyList<Pkcs11LabSavedTemplate>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            return (await ReadUnsafeAsync(cancellationToken))
                .OrderByDescending(template => template.UpdatedUtc)
                .ThenBy(template => template.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<Pkcs11LabSavedTemplate> SaveAsync(string? name, string? notes, Pkcs11LabRequest request, CancellationToken cancellationToken = default)
    {
        string normalizedName = NormalizeName(name);
        await _gate.WaitAsync(cancellationToken);
        try
        {
            List<Pkcs11LabSavedTemplate> templates = await ReadUnsafeAsync(cancellationToken);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            int existingIndex = templates.FindIndex(template => string.Equals(template.Name, normalizedName, StringComparison.OrdinalIgnoreCase));
            Pkcs11LabSavedTemplate saved;
            if (existingIndex >= 0)
            {
                Pkcs11LabSavedTemplate current = templates[existingIndex];
                saved = current with
                {
                    Notes = NormalizeNotes(notes),
                    UpdatedUtc = now,
                    Request = SanitizeRequest(request)
                };
                templates[existingIndex] = saved;
            }
            else
            {
                saved = new Pkcs11LabSavedTemplate(
                    Guid.NewGuid(),
                    normalizedName,
                    NormalizeNotes(notes),
                    now,
                    now,
                    SanitizeRequest(request));
                templates.Add(saved);
            }

            await SaveUnsafeAsync(templates, cancellationToken);
            return saved;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            List<Pkcs11LabSavedTemplate> templates = await ReadUnsafeAsync(cancellationToken);
            templates.RemoveAll(template => template.Id == id);
            await SaveUnsafeAsync(templates, cancellationToken);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<List<Pkcs11LabSavedTemplate>> ReadUnsafeAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(TemplateFilePath))
        {
            return [];
        }

        await using FileStream stream = File.OpenRead(TemplateFilePath);
        Pkcs11LabSavedTemplate[]? templates = await JsonSerializer.DeserializeAsync<Pkcs11LabSavedTemplate[]>(stream, SerializerOptions, cancellationToken);
        return templates?.ToList() ?? [];
    }

    private async Task SaveUnsafeAsync(IReadOnlyList<Pkcs11LabSavedTemplate> templates, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(StorageRoot);
        await using FileStream stream = File.Create(TemplateFilePath);
        await JsonSerializer.SerializeAsync(stream, templates.ToArray(), SerializerOptions, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static string NormalizeName(string? name)
    {
        string normalized = name?.Trim() ?? string.Empty;
        if (string.IsNullOrWhiteSpace(normalized))
        {
            throw new InvalidOperationException("Template name is required.");
        }

        return normalized;
    }

    private static string? NormalizeNotes(string? notes)
        => string.IsNullOrWhiteSpace(notes) ? null : notes.Trim();

    private static Pkcs11LabRequest SanitizeRequest(Pkcs11LabRequest request)
        => new()
        {
            DeviceId = request.DeviceId,
            SlotId = request.SlotId,
            Operation = request.Operation,
            OpenReadWriteSession = request.OpenReadWriteSession,
            LoginUserIfPinProvided = request.LoginUserIfPinProvided,
            UserPin = null,
            MechanismTypeText = request.MechanismTypeText,
            AttributeTypeText = request.AttributeTypeText,
            MechanismParameterProfile = request.MechanismParameterProfile,
            MechanismIvHex = request.MechanismIvHex,
            MechanismAdditionalDataHex = request.MechanismAdditionalDataHex,
            MechanismCounterBits = request.MechanismCounterBits,
            MechanismTagBits = request.MechanismTagBits,
            RsaHashProfile = request.RsaHashProfile,
            RsaOaepSourceEncoding = request.RsaOaepSourceEncoding,
            RsaOaepSourceText = request.RsaOaepSourceText,
            RsaOaepSourceHex = request.RsaOaepSourceHex,
            PssSaltLength = request.PssSaltLength,
            KeyHandleText = request.KeyHandleText,
            KeyLabel = request.KeyLabel,
            KeyIdHex = request.KeyIdHex,
            KeyObjectClass = request.KeyObjectClass,
            KeyType = request.KeyType,
            SecondaryKeyHandleText = request.SecondaryKeyHandleText,
            SecondaryKeyLabel = request.SecondaryKeyLabel,
            SecondaryKeyIdHex = request.SecondaryKeyIdHex,
            SecondaryKeyObjectClass = request.SecondaryKeyObjectClass,
            SecondaryKeyType = request.SecondaryKeyType,
            DigestAlgorithm = request.DigestAlgorithm,
            PayloadEncoding = request.PayloadEncoding,
            TextInput = request.TextInput,
            DataHex = request.DataHex,
            SignatureHex = request.SignatureHex,
            UnwrapTargetLabel = request.UnwrapTargetLabel,
            UnwrapTargetIdHex = request.UnwrapTargetIdHex,
            UnwrapTokenObject = request.UnwrapTokenObject,
            UnwrapPrivateObject = request.UnwrapPrivateObject,
            UnwrapSensitive = request.UnwrapSensitive,
            UnwrapExtractable = request.UnwrapExtractable,
            UnwrapAllowEncrypt = request.UnwrapAllowEncrypt,
            UnwrapAllowDecrypt = request.UnwrapAllowDecrypt,
            LabelFilter = request.LabelFilter,
            IdHex = request.IdHex,
            ObjectClassFilter = request.ObjectClassFilter,
            RandomLength = request.RandomLength,
            MaxObjects = request.MaxObjects
        };

    private string StorageRoot => options.Value.DataRoot;

    private string TemplateFilePath => Path.Combine(StorageRoot, options.Value.LabTemplatesFileName);

    private static JsonSerializerOptions CreateSerializerOptions()
    {
        JsonSerializerOptions options = new()
        {
            WriteIndented = true
        };
        options.Converters.Add(new NUIntJsonConverter());
        return options;
    }

    private sealed class NUIntJsonConverter : JsonConverter<nuint>
    {
        public override nuint Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            => checked((nuint)reader.GetUInt64());

        public override void Write(Utf8JsonWriter writer, nuint value, JsonSerializerOptions options)
            => writer.WriteNumberValue((ulong)value);
    }
}
