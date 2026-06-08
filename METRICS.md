# Metrics

## Source Health

`ssl_check_success{source,target}`

Whether the last check for a configured certificate source succeeded.

- `source="file"` means `target` is a local certificate file path.
- `source="target"` means `target` is the configured remote TLS endpoint.

For remote TLS targets, success means that the exporter connected and collected the peer certificate chain.
It does not mean that the certificate chain is trusted or valid for the hostname.

`ssl_certificate_chain_verified{source,target}`

Whether the certificate chain verifies against system trust roots or the check-specific CA.
This metric is emitted for every remote TLS target and for local certificate file checks that configure `ca=...`.

`ssl_target_chain_verified{target}`

Whether a remote TLS endpoint leaf certificate verifies against system trust roots or the check-specific CA and the target hostname.
This metric is emitted only for remote TLS targets that returned a certificate chain.

## Certificate Validity

All certificate metrics share these labels:

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

Seconds until certificate expiry.
Negative values mean the certificate is already expired.

`ssl_certificate_temporarily_valid`

Whether the certificate is currently within its `NotBefore` and `NotAfter` validity window.
This does not verify trust roots or hostname; use `ssl_certificate_chain_verified` for chain verification.

## Exporter Collection Health

`ssl_exporter_last_collection_success`

Whether the last refresh succeeded for all configured certificate sources.

`ssl_exporter_last_collection_timestamp_seconds`

Unix timestamp of the last refresh attempt.

`ssl_exporter_last_successful_collection_timestamp_seconds`

Unix timestamp of the last fully successful refresh.
The value is `0` until the first fully successful refresh.

`ssl_exporter_configured_certificate_files`

Number of configured local certificate files.

`ssl_exporter_configured_targets`

Number of configured remote TLS targets.
