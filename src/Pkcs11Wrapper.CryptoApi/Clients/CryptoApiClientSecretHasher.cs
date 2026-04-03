using System.Globalization;
using System.Security.Cryptography;

namespace Pkcs11Wrapper.CryptoApi.Clients;

public sealed class CryptoApiClientSecretHasher
{
    public const string Algorithm = "pbkdf2-sha256-v1";

    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int Iterations = 100_000;

    public string HashSecret(string secret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);

        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(secret, salt, Iterations, HashAlgorithmName.SHA256, HashSize);
        return string.Create(CultureInfo.InvariantCulture, $"{Algorithm}${Iterations}${Base64UrlEncode(salt)}${Base64UrlEncode(hash)}");
    }

    public bool VerifySecret(string secret, string storedHash)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);
        if (string.IsNullOrWhiteSpace(storedHash))
        {
            return false;
        }

        string[] parts = storedHash.Split('$', StringSplitOptions.None);
        if (parts.Length != 4 || !string.Equals(parts[0], Algorithm, StringComparison.Ordinal))
        {
            return false;
        }

        if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out int iterations) || iterations <= 0)
        {
            return false;
        }

        byte[] salt;
        byte[] expectedHash;
        try
        {
            salt = Base64UrlDecode(parts[2]);
            expectedHash = Base64UrlDecode(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        byte[] actualHash = Rfc2898DeriveBytes.Pbkdf2(secret, salt, iterations, HashAlgorithmName.SHA256, expectedHash.Length);
        return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
    }

    private static string Base64UrlEncode(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string value)
    {
        string padded = value.Replace('-', '+').Replace('_', '/');
        int mod = padded.Length % 4;
        if (mod > 0)
        {
            padded = padded.PadRight(padded.Length + (4 - mod), '=');
        }

        return Convert.FromBase64String(padded);
    }
}
