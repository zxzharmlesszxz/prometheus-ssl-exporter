# prometheus-ssl-exporter

`prometheus-ssl-exporter` checks SSL/TLS certificates from local certificate files and remote TLS endpoints.

It is built as a thin exporter on top of `prometheus-exporter-framework`.

## Inputs

The exporter supports two source types:

- local PEM or DER certificate files
- remote TLS endpoints, configured with `address` and optional `port`

Remote endpoint checks connect with TLS, collect the peer certificate chain, and then verify the leaf certificate against system trust roots and the configured hostname.
Certificate metrics are still exported when verification fails, as long as the TLS connection returns a certificate.
Use `ca=/path/to/ca.pem` on a target to verify against a custom CA bundle instead of the system trust roots.
Use `server_name=example.com` or `sni=example.com` on a remote target to override TLS SNI and hostname verification while still connecting to the configured address.
For remote targets, `port` defaults to `443`.

Remote targets may be written as `address=example.com,port=443` or as
`address=example.com:443` / `address=https://example.com:443`. Do not set both an
embedded port in `address` and a separate `port`.

## Local Run

Check a remote endpoint:

```bash
make build
./dist/prometheus-ssl-exporter \
  --web.listen-address=:9219 \
  --ssl.config-file=examples/prometheus-ssl-exporter.yml \
  --ssl.target=address=google.com,port=443
```

Check a local certificate file:

```bash
./dist/prometheus-ssl-exporter \
  --ssl.target=file=/etc/ssl/certs/example.pem
```

Targets can be repeated:

```bash
./dist/prometheus-ssl-exporter \
  --ssl.target=address=google.com,port=443 \
  --ssl.target=address=https://example.org:443 \
  --ssl.target=address=127.0.0.1,port=8443,server_name=example.org,ca=/etc/ssl/custom-ca.pem \
  --ssl.target=file=/etc/ssl/certs/example.pem,ca=/etc/ssl/custom-ca.pem
```

Targets can also be loaded from a YAML file:

```bash
./dist/prometheus-ssl-exporter \
  --ssl.config-file=examples/prometheus-ssl-exporter.yml
```

Example:

```yaml
targets:
  - address: google.com
    port: 443

  - address: https://example.org:443

  - address: 127.0.0.1
    port: 8443
    server_name: service.example.com
    ca: /etc/ssl/custom-ca.pem

  - file: /etc/ssl/certs/example.pem
    ca: /etc/ssl/custom-ca.pem
```

Useful flags:

```bash
--ssl.target
--ssl.config-file
--ssl.refresh-interval
--ssl.timeout
--ssl.max-concurrent-targets
--web.listen-address
--web.telemetry-path
--web.enable-pprof
--log.level
--log.format
```

By default, the exporter listens on `:9219`, refreshes certificate data every `1h`, uses a `5s` timeout per remote TLS target, and checks up to `8` remote targets concurrently.
If no `--ssl.config-file` value is provided, `/etc/prometheus/prometheus-ssl-exporter.yml` is loaded when it exists; if it is missing, defaults and flags are used.
The generated `examples/prometheus-ssl-exporter.yml` file lists every supported SSL config key with its default value.
Make, Compose, and smoke defaults use `FEATURE_CONFIG_FILE`, which defaults to `prometheus-ssl-exporter.yml`, and pass that path explicitly with `--ssl.config-file=...`.
Runtime config can always be overridden with another `--ssl.config-file=...` value.
Certificate refresh runs through the framework snapshot collector in a background worker; scrapes return the last collected snapshot.

## Configuration Example

The YAML config file accepts these SSL-specific top-level keys:

```yaml
targets:
  - address: google.com
    port: 443
    server_name: google.com

  - address: example.com:443

  - file: /etc/ssl/certs/example.pem

  - file: /etc/ssl/certs/internal.pem
    ca: /etc/ssl/certs/internal-ca.pem

timeout: 5s
max_concurrent_targets: 8
```

Remote target items support `address`, optional `port`, optional `server_name`
or `sni`, and optional `ca`. File target items support `file` and optional
`ca`.

## Metrics

`ssl_check_success` means that the exporter successfully collected data from the configured source.
For remote TLS targets this means that a TLS connection returned a certificate chain;
it does not mean that the certificate is trusted or valid for the hostname.
Use `ssl_certificate_chain_verified` / `ssl_target_chain_verified` for trust and hostname verification.

Example output:

```text
ssl_check_success{source="target",target="google.com:443"} 1
ssl_certificate_chain_verified{source="target",target="google.com:443"} 1
ssl_target_chain_verified{target="google.com:443"} 1
ssl_certificate_not_before_timestamp_seconds{source="target",target="google.com:443",chain_index="0",subject_cn="*.google.com",issuer_cn="WR2",serial_number="..."} 1.7635968e+09
ssl_certificate_not_after_timestamp_seconds{source="target",target="google.com:443",chain_index="0",subject_cn="*.google.com",issuer_cn="WR2",serial_number="..."} 1.77912e+09
ssl_certificate_expires_in_seconds{source="target",target="google.com:443",chain_index="0",subject_cn="*.google.com",issuer_cn="WR2",serial_number="..."} 4.2e+06
ssl_certificate_temporarily_valid{source="target",target="google.com:443",chain_index="0",subject_cn="*.google.com",issuer_cn="WR2",serial_number="..."} 1
ssl_file_up{source="file"} 1
ssl_file_valid{source="file"} 1
ssl_file_mtime_seconds{source="file"} 1.77912e+09
ssl_file_scrape_duration_seconds{source="file"} 0.381
ssl_file_read_errors_total{source="file"} 0
ssl_file_parse_errors_total{source="file"} 0
ssl_target_up{source="target"} 1
ssl_target_valid{source="target"} 1
ssl_target_mtime_seconds{source="target"} 1.77912e+09
ssl_target_scrape_duration_seconds{source="target"} 0.381
ssl_target_read_errors_total{source="target"} 0
ssl_target_parse_errors_total{source="target"} 0
ssl_exporter_configured_certificate_files 1
ssl_exporter_configured_targets 1
ssl_exporter_collection_duration_seconds_count 1
ssl_exporter_last_collection_success 1
ssl_exporter_last_collection_timestamp_seconds 1.77912e+09
ssl_exporter_last_successful_collection_timestamp_seconds 1.77912e+09
ssl_exporter_build_info{version="v0.1.0",revision="..."} 1
```

For remote endpoints, `chain_index="0"` is the leaf certificate.
SSL metrics use the `ssl` feature namespace. Framework-owned exporter
collection metrics use the `ssl_exporter` metric namespace. The full metric
contract lives in [`METRICS.md`](METRICS.md).

## Docker Compose

The repository includes [`docker-compose.yml`](docker-compose.yml) for local testing.
The Prometheus scrape config is embedded in Compose, while alerting rules live
under [`examples/prometheus`](examples/prometheus).
The bundled rules cover exporter availability, framework collection
failure/staleness, certificate validity/expiry/chain failures, and file/target
source health.
It starts:

- `exporter`
- `prometheus`
- `grafana`

The compose example checks `example.com:443` and `thisisnonexistent.com:443` through
[`docker-compose.override.yml`](docker-compose.override.yml).

```bash
make compose
```

Endpoints:

- `http://localhost:9219`
- `http://localhost:9219/metrics`
- `http://localhost:9219/healthz`
- `http://localhost:9090`
- `http://localhost:3000`

## Grafana

Docker Compose provisions Grafana with:

- Prometheus datasource `DS_PROMETHEUS`
- dashboards from [`examples/grafana`](examples/grafana)
- default login `admin` / `admin`

Open `http://localhost:3000` after `make compose`.
The main dashboard uses the Grafana v2 dashboard resource model and includes
certificate/source status stats, certificate inventory, source-health graphs,
historical changes, exporter collection health, Go runtime panels, and
Prometheus scrape health.

For a direct Docker build, run:

```bash
make docker-build
```

## Tests

```bash
make go-check
```

The repository includes the same maintenance target layout used by the concrete exporter repos:

```bash
make help
make go-check
make check
make docker-smoke
make full-check
```

`make go-check` runs Go-only checks. `make check` also validates the Prometheus and Docker Compose examples, so it requires Docker.

## Scaffold-Owned Go Files

Go files named `scaffold_*.go` are generated contract glue and should stay
identical to the scaffold output. Add exporter-specific behavior in adjacent
non-scaffold files such as `feature_config_ext.go`, `feature_metrics_ext.go`,
`feature_snapshotter_ext.go`, `feature_smoke_ext.go`, `metrics.go`, and the
SSL check package. The feature package `Snapshot` aggregate lives in
`snapshot_types.go`; the SSL check engine snapshot lives in
`internal/sslcheck`.

Build local release artifacts:

```bash
make build VERSION=v0.1.0
make release VERSION=v0.1.0
make release-smoke VERSION=v0.1.0
```

This writes binaries, `.tar.gz` release archives, and `checksums.txt` under `dist/`.
By default, `VERSION`, `BRANCH`, and `REVISION` are derived from Git metadata and fall back to `dev` outside a Git checkout.

Build and push a Docker image:

```bash
make docker-build VERSION=v0.1.0 DOCKER_IMAGE=prometheus-ssl-exporter:v0.1.0
make docker-push DOCKER_IMAGE=prometheus-ssl-exporter:v0.1.0
make docker-buildx-push VERSION=v0.1.0 DOCKER_IMAGE=registry.example.com/prometheus-ssl-exporter:v0.1.0
```

The GitLab CI file and GitHub Actions workflow both delegate to the same Makefile targets.
The GitHub Actions workflow runs the jobs in Alpine-based containers (`golang:1.27.0-alpine` and `docker:27` with `docker:27-dind`).
Tags build release archives and can publish a multi-platform Docker image to the GitLab registry or GitHub Container Registry.

Docker image publishing policy:

- branch and pull request pipelines build and smoke-test images but do not push them
- tag pipelines publish the matching release tag, for example `v0.1.0`
- GitHub Container Registry tag pipelines also publish `latest`
- images are published as multi-architecture `linux/amd64` and `linux/arm64`
- commit SHA tags are not published by default
- binary release archives remain the primary non-container distribution

## Architecture

The high-level design is documented in [`ARCHITECTURE.md`](ARCHITECTURE.md).

## License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE).
