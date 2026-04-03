using System.Security.Cryptography;

namespace Pkcs11Wrapper.CryptoApi.Clients;

public sealed class CryptoApiClientSecretGenerator
{
    public string GenerateKeyIdentifier()
        => $"cak_{Base64UrlEncode(RandomNumberGenerator.GetBytes(9))}";

    public string GenerateSecret()
        => $"cas_{Base64UrlEncode(RandomNumberGenerator.GetBytes(24))}";

    public string BuildSecretHint(string secret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);
        if (secret.Length <= 10)
        {
            return "configured";
        }

        return $"{secret[..4]}...{secret[^4..]}";
    }

    private static string Base64UrlEncode(byte[] bytes)
        => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
