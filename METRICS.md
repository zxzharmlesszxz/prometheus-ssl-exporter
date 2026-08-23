# Metrics

SSL-owned metrics use the `ssl` feature namespace.
Framework-owned exporter metrics use the `ssl_exporter` metric namespace.

## Check Results

`ssl_check_success`

Whether the last check for a configured certificate source succeeded.

Labels:

- `source`: `file` for local certificate files or `target` for remote TLS
  endpoints.
- `target`: local certificate file path or normalized remote endpoint.

For remote TLS targets, success means that the exporter connected and collected
the peer certificate chain. It does not mean that the certificate chain is
trusted or valid for the hostname.

`ssl_certificate_chain_verified`

Whether the certificate chain verifies against system trust roots or the
check-specific CA.

Labels:

- `source`
- `target`

This metric is emitted for every remote TLS target and for local certificate
file checks that configure `ca=...`.

`ssl_target_chain_verified`

Whether a remote TLS endpoint leaf certificate verifies against system trust
roots or the check-specific CA and the target hostname.

Labels:

- `target`

This metric is emitted only for remote TLS targets that returned a certificate
chain.

## Source Health

Source-health metrics follow the framework source-health naming contract so
shared Grafana panels can discover them with `ssl.*_(up|valid)` and related
source queries.

All source-health metrics use the label:

- `source`: `file` or `target`.

`ssl_file_up`

Whether all configured local certificate file checks succeeded during the latest
collection. This metric is emitted only when file checks are configured or file
source errors have been observed.

`ssl_file_valid`

Whether the local certificate file source produced valid data. This requires
successful file checks and, when a custom CA is configured, successful chain
verification.

`ssl_file_mtime_seconds`

Unix timestamp of the latest file source collection attempt. This is an
aggregate source refresh timestamp, not the modification time of a specific
certificate file.

`ssl_file_scrape_duration_seconds`

Duration in seconds of the latest SSL collection work for the file source.

`ssl_file_read_errors_total`

Total number of local file source read errors observed by the exporter. This
is a monotonically increasing counter and includes certificate file read errors
and custom CA file read errors.

`ssl_file_parse_errors_total`

Total number of local file source parse errors observed by the exporter. This
is a monotonically increasing counter and includes certificate file parse errors
and custom CA file parse errors.

`ssl_target_up`

Whether all configured remote TLS target checks succeeded during the latest
collection. This metric is emitted only when remote targets are configured or
target source errors have been observed.

`ssl_target_valid`

Whether the remote TLS target source produced valid data. This requires
successful target checks and successful chain/hostname verification for emitted
target chain results.

`ssl_target_mtime_seconds`

Unix timestamp of the latest target source collection attempt. This is an
aggregate source refresh timestamp.

`ssl_target_scrape_duration_seconds`

Duration in seconds of the latest SSL collection work for the target source.

`ssl_target_read_errors_total`

Total number of remote target source errors observed by the exporter. This
is a monotonically increasing counter and includes TLS connection failures,
missing peer certificates, and custom CA file read errors.

`ssl_target_parse_errors_total`

Total number of remote target source parse errors observed by the exporter. This
is a monotonically increasing counter and includes custom CA file parse errors
for remote targets.

## Certificate Validity

Certificate metrics use these labels:

- `source`
- `target`
- `chain_index`
- `subject_cn`
- `issuer_cn`
- `serial_number`

`subject_cn`, `issuer_cn`, and `serial_number` are certificate identity labels.
Certificate rotation can therefore create new time series.

For remote endpoints, `chain_index="0"` is the leaf certificate.

`ssl_certificate_not_before_timestamp_seconds`

Unix timestamp when the certificate becomes valid.

`ssl_certificate_not_after_timestamp_seconds`

Unix timestamp when the certificate expires.

`ssl_certificate_expires_in_seconds`

Seconds until certificate expiry. Negative values mean the certificate is
already expired.

`ssl_certificate_temporarily_valid`

Whether the certificate is currently within its `NotBefore` and `NotAfter`
validity window. This does not verify trust roots or hostname; use
`ssl_certificate_chain_verified` or `ssl_target_chain_verified` for chain and
hostname verification.

## Configured Source Counts

`ssl_exporter_configured_certificate_files`

Number of configured local certificate files.

`ssl_exporter_configured_targets`

Number of configured remote TLS targets.

## Exporter Collection Health

`ssl_exporter_last_collection_success`

Whether the last refresh succeeded for all configured certificate sources.

`ssl_exporter_last_collection_timestamp_seconds`

Unix timestamp of the last refresh attempt. The value is `0` before the first
collection attempt.

`ssl_exporter_last_successful_collection_timestamp_seconds`

Unix timestamp of the last fully successful refresh. The value is `0` until the
first fully successful refresh.

`ssl_exporter_collection_duration_seconds`

Histogram of framework collection refresh duration. It is emitted by the
framework collector and uses the standard Prometheus histogram series:

- `ssl_exporter_collection_duration_seconds_bucket`
- `ssl_exporter_collection_duration_seconds_sum`
- `ssl_exporter_collection_duration_seconds_count`

## Build Info

`ssl_exporter_build_info`

Build and runtime metadata exposed by the framework. Labels include version,
revision, branch, Go version, GOOS, and GOARCH. The metric value is always `1`.
