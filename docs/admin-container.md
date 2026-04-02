# Admin panel container image

The admin panel now ships with a production-oriented multi-stage Docker build at `src/Pkcs11Wrapper.Admin.Web/Dockerfile`.

## Why this image looks the way it does

- it uses the official .NET `aspnet:10.0-noble` runtime image instead of Alpine so mounted PKCS#11 vendor libraries have a better chance of loading cleanly on glibc-based hosts
- it publishes only the admin web app into the final image
- it runs as a non-root UID by default
- runtime state is externalized to `/var/lib/pkcs11wrapper-admin` instead of relying on repo-local mutable `App_Data`

## Build the image

From the repository root:

```bash
docker build -f src/Pkcs11Wrapper.Admin.Web/Dockerfile -t pkcs11wrapper-admin .
```

## Default runtime contract

The image sets these defaults:

- `ASPNETCORE_URLS=http://+:8080`
- `AdminStorage__DataRoot=/var/lib/pkcs11wrapper-admin`
- `AdminRuntime__DisableHttpsRedirection=true`

Persist `/var/lib/pkcs11wrapper-admin` with a named volume or bind mount. The container runs as UID `64198` by default, so a host bind mount must be writable by that UID (or you can prefer a named volume).

## First-run bootstrap via environment variables

Supported externalized settings:

- `AdminStorage__DataRoot`
- `LocalAdminBootstrap__UserName`
- `LocalAdminBootstrap__Password`
- `AdminBootstrapDevice__Name`
- `AdminBootstrapDevice__ModulePath`
- `AdminBootstrapDevice__DefaultTokenLabel`
- `AdminBootstrapDevice__Notes`
- `AdminBootstrapDevice__VendorId`
- `AdminBootstrapDevice__VendorName`
- `AdminBootstrapDevice__VendorProfileId`
- `AdminBootstrapDevice__VendorProfileName`
- `AdminBootstrapDevice__IsEnabled`
- `AdminRuntime__DisableHttpsRedirection`

`AdminBootstrapDevice__ModulePath` is intended for first-run seeding when the storage root is empty. Once `device-profiles.json` already exists, the bootstrap device seed is ignored so persisted admin data is not overwritten on restart.

## Example: run with mounted PKCS#11 library and persistent state

```bash
docker run --rm \
  --name pkcs11wrapper-admin \
  -p 8080:8080 \
  -e LocalAdminBootstrap__UserName=admin \
  -e LocalAdminBootstrap__Password='ChangeMe!123456' \
  -e AdminBootstrapDevice__Name='SoftHSM demo' \
  -e AdminBootstrapDevice__ModulePath=/opt/pkcs11/lib/libsofthsm2.so \
  -e AdminBootstrapDevice__DefaultTokenLabel=dev-token \
  -v pkcs11wrapper-admin-data:/var/lib/pkcs11wrapper-admin \
  -v /usr/lib/softhsm:/opt/pkcs11/lib:ro \
  pkcs11wrapper-admin
```

After first startup:

1. open `http://localhost:8080`
2. sign in with the bootstrap credential
3. rotate the bootstrap password from the `Users` page
4. retire `bootstrap-admin.txt` from the mounted storage root

## Notes for host-provided PKCS#11 libraries

- mount the host directory or exact shared object into the container read-only
- set `AdminBootstrapDevice__ModulePath` or configure the device in the UI using the in-container path, not the host path
- if a vendor library depends on additional shared libraries, mount/install those dependencies so the dynamic loader can resolve them inside the container too
- keep the module mount read-only unless the vendor explicitly requires writable side files elsewhere

## Data kept under the storage root

The configured storage root contains the admin panel's mutable state, including:

- local admin users
- bootstrap notice file
- Data Protection keys
- device profiles
- audit log
- PKCS#11 telemetry retention files
- saved lab templates
- protected PIN cache

That makes the volume the main unit to back up, migrate, or mount into a replacement container.
