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
  `snapshot_types.go` owns the feature aggregate `Snapshot`, which combines the
  `internal/sslcheck` result with aggregate file/target source-health data.
  SSL-specific defaults and hook functions live in adjacent feature files:
  `feature_config_ext.go`, `feature_metrics_ext.go`,
  `feature_snapshotter_ext.go`, `feature_smoke_ext.go`, and `metrics.go`.
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
9. The feature snapshotter wraps the SSL check snapshot with aggregate
   source-health state for `file` and `target`, such as `ssl_file_up`,
   `ssl_target_valid`, source error counters, and refresh duration.
10. The collector exports per-source check metrics, aggregate source-health
   metrics, certificate validity, chain verification, configured source counts,
   and framework collection health metrics.

## Failure Semantics

A failed file read, parse, or remote TLS connection sets:

- `ssl_check_success{source,target} = 0`
- `ssl_exporter_last_collection_success = 0`
- `ssl_file_up{source="file"} = 0` for file source failures
- `ssl_target_up{source="target"} = 0` for remote target source failures

Other configured sources can still produce certificate metrics in the same refresh.

For remote targets, trust or hostname verification failure does not make `ssl_check_success` fail if the TLS endpoint returned certificates.
Instead, it sets:

- `ssl_target_chain_verified{target} = 0`
- `ssl_certificate_chain_verified{source="target",target} = 0`
- `ssl_target_valid{source="target"} = 0`

For local file checks with `ca=...`, CA verification failure also does not make `ssl_check_success` fail if the certificate file was parsed.
Instead, it sets:

- `ssl_certificate_chain_verified{source="file",target} = 0`
- `ssl_file_valid{source="file"} = 0`

The `/healthz` endpoint remains `200 OK` while the process is alive even if the latest collection failed.

## Metric Namespaces

- SSL source and certificate metrics use the feature namespace `ssl`, for
  example `ssl_check_success` and `ssl_certificate_expires_in_seconds`.
- Aggregate source-health metrics also use the feature namespace, for example
  `ssl_file_up` and `ssl_target_valid`.
- Framework-owned exporter metrics use the metric namespace `ssl_exporter`, for
  example `ssl_exporter_last_collection_success` and
  `ssl_exporter_collection_duration_seconds`.

## Dashboard Shape

The bundled Grafana dashboard uses the Grafana v2 dashboard resource model. The
Overview tab contains:

- `Status`: exporter availability and collection age.
- `Main Metrics`: configured source stats, failed checks, chain failures,
  certificate expiry stats, certificate inventory, source health by type, and
  leaf certificate expiry views.
- `Source Health`: shared file/target source-health graphs powered by
  `ssl_file_*` and `ssl_target_*` metrics.
- `Historical Graph`: collapsed change graphs for checks, chain verification,
  and validity windows.
- `Exporter Collection`: collapsed framework collection metrics.

The Runtime and Scrape tabs contain Go/process runtime panels and
Prometheus-side scrape health.
