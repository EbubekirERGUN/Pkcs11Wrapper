using System.Collections.Concurrent;

namespace Pkcs11Wrapper.Admin.Web.Security;

public sealed class LocalAdminLoginThrottleService(LocalAdminLoginThrottleOptions? options = null, Func<DateTimeOffset>? clock = null)
{
    private readonly LocalAdminLoginThrottleOptions _options = options ?? new();
    private readonly Func<DateTimeOffset> _clock = clock ?? (() => DateTimeOffset.UtcNow);
    private readonly ConcurrentDictionary<string, FailureBucket> _buckets = new(StringComparer.OrdinalIgnoreCase);

    public LocalAdminLoginThrottleStatus GetStatus(string? userName, string? remoteIp)
    {
        DateTimeOffset now = _clock();
        FailureBucket userBucket = GetBucket($"user:{NormalizeUserName(userName)}");
        FailureBucket ipBucket = GetBucket($"ip:{NormalizeRemoteIp(remoteIp)}");
        CleanupExpired(userBucket, now);
        CleanupExpired(ipBucket, now);

        DateTimeOffset? lockedUntil = Max(userBucket.LockedUntilUtc, ipBucket.LockedUntilUtc);
        return new(lockedUntil is not null && lockedUntil > now, lockedUntil, userBucket.Failures.Count, ipBucket.Failures.Count);
    }

    public LocalAdminLoginThrottleStatus RecordFailure(string? userName, string? remoteIp)
    {
        DateTimeOffset now = _clock();
        FailureBucket userBucket = GetBucket($"user:{NormalizeUserName(userName)}");
        FailureBucket ipBucket = GetBucket($"ip:{NormalizeRemoteIp(remoteIp)}");

        DateTimeOffset? userLockedUntil = RecordFailure(userBucket, now);
        DateTimeOffset? ipLockedUntil = RecordFailure(ipBucket, now);
        DateTimeOffset? lockedUntil = Max(userLockedUntil, ipLockedUntil);

        return new(lockedUntil is not null && lockedUntil > now, lockedUntil, userBucket.Failures.Count, ipBucket.Failures.Count);
    }

    public void RecordSuccess(string? userName, string? remoteIp)
    {
        ResetBucket($"user:{NormalizeUserName(userName)}");
        ResetBucket($"ip:{NormalizeRemoteIp(remoteIp)}");
    }

    private DateTimeOffset? RecordFailure(FailureBucket bucket, DateTimeOffset now)
    {
        lock (bucket.Sync)
        {
            CleanupExpired(bucket, now);
            if (bucket.LockedUntilUtc is not null && bucket.LockedUntilUtc > now)
            {
                return bucket.LockedUntilUtc;
            }

            bucket.Failures.Enqueue(now);
            while (bucket.Failures.TryPeek(out DateTimeOffset failure) && failure < now - _options.FailureWindow)
            {
                bucket.Failures.TryDequeue(out _);
            }

            if (bucket.Failures.Count >= _options.MaxFailuresPerKey)
            {
                bucket.LockedUntilUtc = now + _options.LockoutDuration;
            }

            return bucket.LockedUntilUtc;
        }
    }

    private static DateTimeOffset? Max(DateTimeOffset? left, DateTimeOffset? right)
        => left switch
        {
            null => right,
            _ when right is null => left,
            _ => left >= right ? left : right
        };

    private FailureBucket GetBucket(string key)
        => _buckets.GetOrAdd(key, static _ => new FailureBucket());

    private void ResetBucket(string key)
    {
        if (_buckets.TryGetValue(key, out FailureBucket? bucket))
        {
            lock (bucket.Sync)
            {
                bucket.Failures.Clear();
                bucket.LockedUntilUtc = null;
            }
        }
    }

    private void CleanupExpired(FailureBucket bucket, DateTimeOffset now)
    {
        lock (bucket.Sync)
        {
            while (bucket.Failures.TryPeek(out DateTimeOffset failure) && failure < now - _options.FailureWindow)
            {
                bucket.Failures.TryDequeue(out _);
            }

            if (bucket.LockedUntilUtc is not null && bucket.LockedUntilUtc <= now)
            {
                bucket.LockedUntilUtc = null;
                bucket.Failures.Clear();
            }
        }
    }

    private static string NormalizeUserName(string? value)
        => string.IsNullOrWhiteSpace(value) ? "<empty>" : value.Trim();

    private static string NormalizeRemoteIp(string? value)
        => string.IsNullOrWhiteSpace(value) ? "<unknown>" : value.Trim();

    private sealed class FailureBucket
    {
        public object Sync { get; } = new();

        public Queue<DateTimeOffset> Failures { get; } = new();

        public DateTimeOffset? LockedUntilUtc { get; set; }
    }
}
