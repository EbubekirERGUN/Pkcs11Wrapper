# Admin panel ops and recovery guide

This guide captures the practical recovery/maintenance flow for the current local-host `Pkcs11Wrapper` admin deployment.

## Scope

This runbook assumes:

- Blazor Server admin app is running on a single host
- local cookie auth is enabled
- local users are file-backed
- Data Protection keys and protected PIN cache remain on the same host
- configuration transfer covers device profiles only

## 1. First-run hardening checklist

After the first startup:

1. sign in with the bootstrap admin credential
2. open `Users`
3. rotate the bootstrap password to a value you control
4. create at least one additional admin account for recovery
5. retire the plaintext bootstrap notice file
6. export the current device-profile bundle from `Configuration`

Do not leave the bootstrap notice file around longer than necessary.

## 2. Local user recovery

The `Users` page is the primary place to:

- create local viewer/operator/admin users
- rotate passwords
- update roles
- retire the bootstrap credential notice
- remove no-longer-needed local users

Operational guidance:

- keep at least two admin-capable users if the deployment matters
- avoid using the bootstrap account as the long-term daily operator identity
- rotate passwords after initial setup, incidents, or handover events

## 3. Configuration backup / restore

Use `Configuration` before risky changes or host migration.

### Export includes

- device profiles

### Export intentionally excludes

- admin users
- bootstrap credential files
- audit history
- protected PIN cache
- Data Protection keys

That means configuration export is safe for device-profile portability, but it is **not** a full host clone.

## 4. Tracked session recovery

Use the `Sessions` page when:

- a tracked session becomes invalidated
- `CloseAllSessions` was invoked and stale tracked rows remain visible
- a login/logout/cancel operation fails and you need to inspect the last known state

Recommended flow:

1. filter to the affected device or invalidated state
2. open session details
3. inspect the invalidation reason / last operation
4. close stale tracked entries
5. reopen fresh session context through the normal page flow if needed

If the session became invalid because the underlying token/module changed state, do not trust the stale tracked entry; close it and create a new one.

## 5. Audit integrity recovery

Use `Audit Logs` to monitor both recent events and chain integrity.

If integrity is reported as invalid:

1. stop assuming the recent audit trail is trustworthy
2. inspect the integrity failure summary and failure reason
3. preserve the host state before making additional write changes
4. review the affected log file and surrounding host operations
5. only resume normal administration after the cause is understood

In the current app shape, integrity warnings should be treated as operationally significant.

## 6. Protected PIN cache expectations

Protected PIN storage is designed for convenience on the same host, not as a centralized secret-management solution.

Important limits:

- cached PINs stay local to the host
- they are not included in configuration export/import
- they depend on local ASP.NET Core Data Protection material
- moving the app to another host does not carry this cache with it automatically

## 7. What this does not replace

Current admin hardening is strong for a local embedded deployment, but it does not replace:

- external IdP / IAM
- MFA
- centralized secret vaults / KMS-backed governance
- centralized audit collection / SIEM pipelines

If the deployment scope grows beyond a single trusted host, plan a stronger identity and secret-management layer around the app.
