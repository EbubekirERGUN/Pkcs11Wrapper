# Runtime observability

This repository now ships a practical first observability slice for the runtime topology:

- `Pkcs11Wrapper.CryptoApi`
- `Pkcs11Wrapper.CryptoApi.Gateway`
- `Pkcs11Wrapper.Admin.Web`

The goal is intentionally narrow: expose the metrics operators need to understand request flow, shared-state pressure, PKCS#11 execution latency, ingress health, and basic admin activity without trying to build a full observability platform inside the app itself.

## Export model

Each web host now exposes an OpenTelemetry-backed Prometheus scraping endpoint.

Configuration lives under:

```json
"Observability": {
  "EnablePrometheusScrapingEndpoint": true,
  "MetricsPath": "/metrics"
}
```

Environment-variable equivalents:

```text
Observability__EnablePrometheusScrapingEndpoint=true
Observability__MetricsPath=/metrics
```

The endpoint is intentionally unauthenticated inside the app. Treat it as an operator-only surface:

- keep it on a private network
- or publish it only behind an authenticated reverse proxy / metrics gateway
- do not expose it directly on the public internet

## What gets emitted

## Common host metrics

All three hosts export the custom meters listed below plus the standard ASP.NET Core/Kestrel request metrics that OpenTelemetry can scrape from the running process.

## Crypto API host metrics

Custom Crypto API metrics focus on the hot path:

- `pkcs11wrapper_crypto_api_authentication_results_total`
  - labels: `result`, `source`
- `pkcs11wrapper_crypto_api_authorization_results_total`
  - labels: `result`, `source`
- `pkcs11wrapper_crypto_api_request_path_cache_lookups_total`
  - labels: `cache`, `layer`, `result`
- `pkcs11wrapper_crypto_api_distributed_cache_requests_total`
- `pkcs11wrapper_crypto_api_distributed_cache_request_duration_seconds`
  - labels: `operation`, `result`
- `pkcs11wrapper_crypto_api_shared_state_requests_total`
- `pkcs11wrapper_crypto_api_shared_state_request_duration_seconds`
  - labels: `operation`, `result`
- `pkcs11wrapper_crypto_api_shared_state_database_reads_total`
- `pkcs11wrapper_crypto_api_last_used_refresh_events_total`
  - labels: `path`, `stage`, `result`
- `pkcs11wrapper_crypto_api_rate_limit_rejections_total`
  - labels: `scope`
- `pkcs11wrapper_crypto_api_pkcs11_operations_total`
- `pkcs11wrapper_crypto_api_pkcs11_operation_duration_seconds`
  - labels: `operation`, `algorithm`, `backend`, `result`
- `pkcs11wrapper_crypto_api_pkcs11_session_leases_total`
- `pkcs11wrapper_crypto_api_pkcs11_session_returns_total`
  - labels: `backend`, `slot`, `result`
- `pkcs11wrapper_crypto_api_authentication_cache_entries`
- `pkcs11wrapper_crypto_api_authentication_cache_utilization_ratio`
- `pkcs11wrapper_crypto_api_authorization_cache_entries`
- `pkcs11wrapper_crypto_api_authorization_cache_utilization_ratio`
- `pkcs11wrapper_crypto_api_shared_state_pool_max_connections`
  - labels: `provider`
- `pkcs11wrapper_crypto_api_pkcs11_sessions_idle`
- `pkcs11wrapper_crypto_api_pkcs11_sessions_in_use`
- `pkcs11wrapper_crypto_api_pkcs11_sessions_max_retained`
  - labels: `backend`, `slot`

These cover the first slice requested for request rate/latency, sign/verify/random latency, auth/authz cache behavior, shared-state pressure, pool visibility, rate limits, and errors.

For the Redis-backed L2 hot-path layer, the most useful `operation` / `result` combinations are now:

- `connect`
  - `success`, `cooldown`, `error`
- `get_auth_state_revision`
  - `hit`, `miss`, `invalid`, `unavailable`, `error`
- `set_auth_state_revision`
  - `updated`, `preserved_newer`, `unavailable`, `error`
- `get_authenticated_client`, `set_authenticated_client`
- `get_authorized_operation`, `set_authorized_operation`
- `try_acquire_last_used_refresh_lease`

That means operators can answer a few practical questions directly from metrics instead of guesswork:

- Are instances actually using Redis, or staying on shared-state/database paths?
- Are reconnect attempts backing off cleanly during Redis outages?
- Are stale writers trying to republish an older auth-state revision hint?
- Is Redis helping coordinate `last_used_at_utc` throttling across nodes?

## Gateway metrics

Gateway-specific metrics focus on ingress health and operator-visible rejection behavior:

- `pkcs11wrapper_crypto_api_gateway_backend_readiness_probes_total`
- `pkcs11wrapper_crypto_api_gateway_backend_readiness_probe_duration_seconds`
  - labels: `cluster`, `result`
- `pkcs11wrapper_crypto_api_gateway_request_body_rejections_total`
- `pkcs11wrapper_crypto_api_gateway_healthy_destinations`
- `pkcs11wrapper_crypto_api_gateway_configured_destinations`
  - labels: `cluster`

## Admin metrics

Admin-specific metrics stay intentionally small:

- `pkcs11wrapper_admin_login_attempts_total`
  - labels: `result`
- `pkcs11wrapper_admin_logouts_total`
  - labels: `result`
- `pkcs11wrapper_admin_sessions`
  - labels: `status`

This gives operators a lightweight signal for login failures/throttling and current tracked-session health without turning the admin panel into a second telemetry system.

## Prometheus scrape example

```yaml
scrape_configs:
  - job_name: pkcs11wrapper-crypto-api
    static_configs:
      - targets:
          - crypto-api-a.internal:8080
          - crypto-api-b.internal:8080
    metrics_path: /metrics

  - job_name: pkcs11wrapper-crypto-api-gateway
    static_configs:
      - targets:
          - crypto-gateway.internal:8090
    metrics_path: /metrics

  - job_name: pkcs11wrapper-admin
    static_configs:
      - targets:
          - admin.internal:8080
    metrics_path: /metrics
```

## Grafana starter

A starter dashboard definition lives at:

- `docs/grafana/pkcs11wrapper-runtime-observability-dashboard.json`

It is intentionally a starting point, not a polished NOC wall. Expect to tune panel thresholds, labels, and datasource wiring for your environment.

Suggested first panels:

- authentication result rate by source
- request-path cache hit vs miss
- shared-state p95 latency by operation
- Redis hot-path cache p95 latency by operation
- PKCS#11 sign / verify / random p95 latency by backend
- rate-limit rejections
- PKCS#11 sessions in use vs idle per backend/slot
- gateway healthy destination count
- admin login failures over time

## Notes and limits

- This is a metrics-first slice only; it does not attempt to replace vendor-native HSM audit logs.
- The Prometheus exporter package in the OpenTelemetry stack is still a pragmatic app-level scrape choice here, not a promise that the repo is standardizing on one exporter forever.
- If you later need OTLP export, traces, or centralized exemplars, build on top of these meters rather than replacing the metric names casually.
