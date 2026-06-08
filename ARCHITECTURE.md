# Architecture

`prometheus-ssl-exporter` is a thin concrete exporter built on `prometheus-exporter-framework`.

## Package Layout

- `cmd`
  Minimal process entrypoint. The generated entrypoint file is
  `scaffold_main.go` and should stay scaffold-owned.
- `internal/exporter`
  Thin adapter that asks the feature package for a contract-backed feature and
  delegates bootstrap metadata to the framework. Files named `scaffold_*.go`
  are fully scaffold-owned.
- `internal/ssl`
  Concrete feature package. `scaffold_feature.go` owns the scaffold-compatible
  `featurekit.SnapshotFeatureExtension` assembly and wires config-file flags,
  feature config flag specs, runtime config, collector construction, metrics,
  snapshot status, and smoke behavior through SSL-specific hooks.
  `scaffold_snapshot_types.go` owns the scaffold-managed `Snapshot` alias from
  the feature package to `internal/sslcheck.Snapshot`.
  SSL-specific defaults and hook functions live in adjacent feature files:
  `feature_config_ext.go`, `feature_metrics_ext.go`,
  `feature_snapshotter_ext.go`, and `feature_smoke_ext.go`.
- `internal/sslcheck`
  Certificate file parsing, endpoint normalization, TLS connection checks, chain
  verification, and check result types.
- `smoke`
  Binary smoke tests that build the real executable and verify CLI, HTTP, and
  metric behavior. The scaffold-owned smoke test is `scaffold_binary_test.go`.

Concrete exporter logic belongs in non-`scaffold_*.go` files. Treat
`scaffold_*.go` files as generated contract glue and update them through the
scaffold sync flow only.

## Data Flow

1. `cmd/scaffold_main.go` delegates to `internal/exporter.Main()`, which runs `framework.MainFromInjectedProject(...)`.
2. `internal/exporter` creates the concrete feature through
   `internal/ssl.NewFeature(...)` and framework-injected feature metadata.
3. Framework `featurekit.Feature` registers common flags such as `--ssl.refresh-interval` and `--ssl.config-file`, then delegates SSL-specific behavior through the framework-owned feature contract:
   - `--ssl.target`
   - `--ssl.refresh-interval`
   - `--ssl.timeout`
   - `--ssl.max-concurrent-targets`
4. The SSL feature extension parses CLI targets and YAML config file targets into local file checks and normalized TLS endpoints, then builds a feature snapshotter and feature metrics.
5. `framework.SnapshotCollector` reads SSL data through the snapshotter and refreshes certificate data in a background worker every `--ssl.refresh-interval`; scrapes read the latest completed snapshot.
6. File sources are parsed as PEM first and DER second.
7. Remote targets are checked with bounded concurrency. Each target is connected with TLS, peer certificates are collected, and the leaf certificate is verified separately against system trust roots or the check-specific CA and hostname.
8. `server_name`/`sni` can override TLS SNI and hostname verification for remote targets while preserving the configured network address as the metric target.
9. The collector exports source health, certificate validity, chain verification, and collection health metrics.

## Failure Semantics

A failed file read, parse, or remote TLS connection sets:

- `ssl_check_success{source,target} = 0`
- `ssl_exporter_last_collection_success = 0`

Other configured sources can still produce certificate metrics in the same refresh.

For remote targets, trust or hostname verification failure does not make `ssl_check_success` fail if the TLS endpoint returned certificates.
Instead, it sets:

- `ssl_target_chain_verified{target} = 0`
- `ssl_certificate_chain_verified{source="target",target} = 0`

For local file checks with `ca=...`, CA verification failure also does not make `ssl_check_success` fail if the certificate file was parsed.
Instead, it sets:

- `ssl_certificate_chain_verified{source="file",target} = 0`
