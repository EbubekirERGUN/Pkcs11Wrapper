using Microsoft.Extensions.Options;
using Npgsql;
using Pkcs11Wrapper.CryptoApi.Configuration;

namespace Pkcs11Wrapper.CryptoApi.Tests;

internal static class PostgresTestEnvironment
{
    public const string ConnectionStringEnvironmentVariable = "PKCS11WRAPPER_TEST_POSTGRES_CONNECTION_STRING";

    public static bool IsConfigured()
        => !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(ConnectionStringEnvironmentVariable));

    public static async Task<PostgresTestScope> CreateScopeAsync(CancellationToken cancellationToken = default)
    {
        string baseConnectionString = Environment.GetEnvironmentVariable(ConnectionStringEnvironmentVariable)
            ?? throw new InvalidOperationException($"Set {ConnectionStringEnvironmentVariable} to run PostgreSQL integration tests.");

        string schemaName = $"cryptoapi_test_{Guid.NewGuid():N}";

        await using (NpgsqlConnection connection = new(baseConnectionString))
        {
            await connection.OpenAsync(cancellationToken);
            await using NpgsqlCommand command = connection.CreateCommand();
            command.CommandText = $"CREATE SCHEMA IF NOT EXISTS \"{schemaName}\";";
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        NpgsqlConnectionStringBuilder builder = new(baseConnectionString)
        {
            SearchPath = schemaName
        };

        return new PostgresTestScope(schemaName, new CryptoApiSharedPersistenceOptions
        {
            Provider = CryptoApiSharedPersistenceDefaults.PostgresProvider,
            ConnectionString = builder.ConnectionString,
            AutoInitialize = true
        });
    }

    public sealed class PostgresTestScope(string schemaName, CryptoApiSharedPersistenceOptions options) : IAsyncDisposable
    {
        public string SchemaName { get; } = schemaName;

        public CryptoApiSharedPersistenceOptions Options { get; } = options;

        public IOptions<CryptoApiSharedPersistenceOptions> AsOptions()
            => Microsoft.Extensions.Options.Options.Create(Options);

        public async ValueTask DisposeAsync()
        {
            NpgsqlConnection.ClearAllPools();

            string baseConnectionString = Environment.GetEnvironmentVariable(ConnectionStringEnvironmentVariable)
                ?? throw new InvalidOperationException($"Set {ConnectionStringEnvironmentVariable} to run PostgreSQL integration tests.");

            await using NpgsqlConnection connection = new(baseConnectionString);
            await connection.OpenAsync();
            await using NpgsqlCommand command = connection.CreateCommand();
            command.CommandText = $"DROP SCHEMA IF EXISTS \"{SchemaName}\" CASCADE;";
            await command.ExecuteNonQueryAsync();
        }
    }
}

internal sealed class PostgresFactAttribute : FactAttribute
{
    public PostgresFactAttribute()
    {
        if (!PostgresTestEnvironment.IsConfigured())
        {
            Skip = $"Set {PostgresTestEnvironment.ConnectionStringEnvironmentVariable} to run PostgreSQL integration tests.";
        }
    }
}
