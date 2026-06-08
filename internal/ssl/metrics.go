package ssl

import "github.com/zxzharmlesszxz/prometheus-exporter-framework/exporter/featurekit"

const (
	metricCheckSuccess                = "check_success"
	metricCertificateChainVerified    = "certificate_chain_verified"
	metricTargetChainVerified         = "target_chain_verified"
	metricCertificateNotBefore        = "certificate_not_before"
	metricCertificateNotAfter         = "certificate_not_after"
	metricCertificateExpiresIn        = "certificate_expires_in"
	metricCertificateTemporarilyValid = "certificate_temporarily_valid"
	metricConfiguredCertificateFiles  = "configured_certificate_files"
	metricConfiguredTargets           = "configured_targets"
)

var certificateLabels = []string{
	"source",
	"target",
	"chain_index",
	"subject_cn",
	"issuer_cn",
	"serial_number",
}

var featureMetricSpecs = []featurekit.FeatureMetricSpec{
	{
		ID:     metricCheckSuccess,
		Scope:  featurekit.MetricScopeFeature,
		Name:   "_check_success",
		Help:   "Whether the last SSL certificate source check succeeded",
		Labels: []string{"source", "target"},
	},
	{
		ID:     metricCertificateChainVerified,
		Scope:  featurekit.MetricScopeFeature,
		Name:   "_certificate_chain_verified",
		Help:   "Whether the certificate chain verifies against system trust roots or the check-specific CA",
		Labels: []string{"source", "target"},
	},
	{
		ID:     metricTargetChainVerified,
		Scope:  featurekit.MetricScopeFeature,
		Name:   "_target_chain_verified",
		Help:   "Whether the remote TLS endpoint leaf certificate verifies against system trust roots or the check-specific CA and the target hostname",
		Labels: []string{"target"},
	},
	{
		ID:     metricCertificateNotBefore,
		Scope:  featurekit.MetricScopeFeature,
		Name:   "_certificate_not_before_timestamp_seconds",
		Help:   "Unix timestamp when the SSL certificate becomes valid",
		Labels: certificateLabels,
	},
	{
		ID:     metricCertificateNotAfter,
		Scope:  featurekit.MetricScopeFeature,
		Name:   "_certificate_not_after_timestamp_seconds",
		Help:   "Unix timestamp when the SSL certificate expires",
		Labels: certificateLabels,
	},
	{
		ID:     metricCertificateExpiresIn,
		Scope:  featurekit.MetricScopeFeature,
		Name:   "_certificate_expires_in_seconds",
		Help:   "Seconds until SSL certificate expiry. Negative values mean the certificate is already expired",
		Labels: certificateLabels,
	},
	{
		ID:     metricCertificateTemporarilyValid,
		Scope:  featurekit.MetricScopeFeature,
		Name:   "_certificate_temporarily_valid",
		Help:   "Whether the SSL certificate is currently within its NotBefore and NotAfter validity window",
		Labels: certificateLabels,
	},
	{
		ID:    metricConfiguredCertificateFiles,
		Scope: featurekit.MetricScopeNamespace,
		Name:  "_configured_certificate_files",
		Help:  "Number of configured local certificate files",
	},
	{
		ID:    metricConfiguredTargets,
		Scope: featurekit.MetricScopeNamespace,
		Name:  "_configured_targets",
		Help:  "Number of configured remote TLS targets",
	},
}
