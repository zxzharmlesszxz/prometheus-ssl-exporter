package ssl

import (
	"log/slog"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	framework "github.com/zxzharmlesszxz/prometheus-exporter-framework/exporter"
	"github.com/zxzharmlesszxz/prometheus-exporter-framework/exporter/featurekit"

	"github.com/zxzharmlesszxz/prometheus-ssl-exporter/internal/sslcheck"
)

func NewFeatureMetricHandlers() featurekit.FeatureMetricHandlers[Snapshot] {
	return featurekit.FeatureMetricHandlers[Snapshot]{
		Collect:  CollectFeatureMetrics,
		LogError: LogFeatureSnapshotError,
	}
}

func CollectFeatureMetrics(ctx featurekit.FeatureMetricsContext[Snapshot], ch chan<- prometheus.Metric, snapshot Snapshot, now time.Time) {
	for _, status := range snapshot.ssl.Checks {
		ch <- prometheus.MustNewConstMetric(
			ctx.Descriptors.Get(metricCheckSuccess),
			prometheus.GaugeValue,
			framework.BoolFloat(status.Success),
			status.Source,
			status.Target,
		)
	}

	for _, chain := range snapshot.ssl.ChainResults {
		ch <- prometheus.MustNewConstMetric(
			ctx.Descriptors.Get(metricCertificateChainVerified),
			prometheus.GaugeValue,
			framework.BoolFloat(chain.ChainVerified),
			chain.Source,
			chain.Target,
		)
	}

	for _, target := range snapshot.ssl.TargetResults {
		ch <- prometheus.MustNewConstMetric(
			ctx.Descriptors.Get(metricTargetChainVerified),
			prometheus.GaugeValue,
			framework.BoolFloat(target.ChainVerified),
			target.Target,
		)
	}

	for _, cert := range snapshot.ssl.Certificates {
		labels := certificateLabelValues(cert)
		ch <- prometheus.MustNewConstMetric(
			ctx.Descriptors.Get(metricCertificateNotBefore),
			prometheus.GaugeValue,
			float64(cert.NotBefore.Unix()),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			ctx.Descriptors.Get(metricCertificateNotAfter),
			prometheus.GaugeValue,
			float64(cert.NotAfter.Unix()),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			ctx.Descriptors.Get(metricCertificateExpiresIn),
			prometheus.GaugeValue,
			cert.NotAfter.Sub(now).Seconds(),
			labels...,
		)
		ch <- prometheus.MustNewConstMetric(
			ctx.Descriptors.Get(metricCertificateTemporarilyValid),
			prometheus.GaugeValue,
			framework.BoolFloat(cert.TemporarilyValidNow),
			labels...,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		ctx.Descriptors.Get(metricConfiguredCertificateFiles),
		prometheus.GaugeValue,
		float64(snapshot.ssl.ConfiguredCertificateFiles),
	)
	ch <- prometheus.MustNewConstMetric(
		ctx.Descriptors.Get(metricConfiguredTargets),
		prometheus.GaugeValue,
		float64(snapshot.ssl.ConfiguredTargets),
	)
}

func LogFeatureSnapshotError(ctx featurekit.FeatureMetricsContext[Snapshot], logger *slog.Logger, snapshot Snapshot) {
	logged := false
	for _, checkError := range snapshot.ssl.Errors {
		logger.Error(
			ctx.FeatureName+" certificate check failed",
			"source", checkError.Source,
			"target", checkError.Target,
			"err", checkError.Err,
		)
		logged = true
	}
	if !snapshot.ssl.Success && !logged {
		logger.Error(ctx.FeatureName + " certificate check failed")
	}
}

func certificateLabelValues(cert sslcheck.Certificate) []string {
	return []string{
		cert.Source,
		cert.Target,
		strconv.Itoa(cert.ChainIndex),
		cert.SubjectCommonName,
		cert.IssuerCommonName,
		cert.SerialNumber,
	}
}
