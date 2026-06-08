package ssl

import "github.com/zxzharmlesszxz/prometheus-exporter-framework/exporter/featurekit"

var DefaultFeatureConfigPath = "../examples/" + DefaultFeatureConfigFileName

func FeatureSmoke(ctx featurekit.SmokeContext[Config]) featurekit.SmokeSpec {
	checkSuccess := featurekit.FeatureMetricName(ctx.FeatureName, "", metricCheckSuccess, featureMetricSpecs) +
		`{source="file",target="testdata/smoke-cert.pem"}`

	return featurekit.SmokeSpec{
		ServerArgs: []string{
			"--" + ctx.FeatureName + ".config-file=" + DefaultFeatureConfigPath,
			"--" + ctx.FeatureName + ".target=file=testdata/smoke-cert.pem",
			"--" + ctx.FeatureName + ".max-concurrent-targets=2",
		},
		WantMetrics: []string{
			checkSuccess + " 1",
			featurekit.FeatureMetricName(ctx.FeatureName, "", metricCertificateTemporarilyValid, featureMetricSpecs) + `{`,
		},
		RejectMetrics: []string{
			checkSuccess + " 0",
		},
	}
}
