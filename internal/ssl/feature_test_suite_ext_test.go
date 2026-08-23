package ssl

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	framework "github.com/zxzharmlesszxz/prometheus-exporter-framework/exporter"
	"github.com/zxzharmlesszxz/prometheus-exporter-framework/exporter/exportertest"
	"github.com/zxzharmlesszxz/prometheus-exporter-framework/exporter/exportertest/featuretest"
	"github.com/zxzharmlesszxz/prometheus-exporter-framework/exporter/featurekit"

	"github.com/zxzharmlesszxz/prometheus-ssl-exporter/internal/sslcheck"
)

func TestFeatureContract(t *testing.T) {
	suite := NewFeatureTestSuite(NewFeatureTestSpec())
	RegisterFeatureTests(suite)
	suite.RunTests(t)
}

func NewFeatureTestSpec() FeatureTestSpec {
	return FeatureTestSpec{
		// SSL does not emit the standard last_collection_success metric in the namespaced
		// scope because per-source check results (ssl_check_success) carry more granular state.
		// The contract suite normally asserts last_collection_success exists; skip that check.
		SkipContractLastCollectionSuccessMetric: true,
		SuccessfulSnapshot: func(at time.Time) Snapshot {
			return Snapshot{
				ssl: sslcheck.Snapshot{
					AttemptTime: at,
					Success:     true,
				},
			}
		},
		FailedSnapshot: func(at time.Time, err error) Snapshot {
			return Snapshot{
				ssl: sslcheck.Snapshot{
					AttemptTime: at,
					Success:     false,
					Errors: []sslcheck.CheckError{
						{Err: err},
					},
				},
			}
		},
		ContractFlagArgs: []string{
			"--" + testFeatureName + ".target=address=example.com,port=443",
			"--" + testFeatureName + ".target=file=/tmp/cert.pem",
			"--" + testFeatureName + ".timeout=2s",
			"--" + testFeatureName + ".max-concurrent-targets=3",
		},
		ContractRuntimeConfig: map[string]any{
			"targets":                []string{"address=example.com,port=443", "file=/tmp/cert.pem"},
			"timeout":                2 * time.Second,
			"max_concurrent_targets": 3,
		},
		DefaultRuntimeConfig: map[string]any{
			"timeout":                DefaultTimeout,
			"max_concurrent_targets": DefaultMaxConcurrentTargets,
		},
		CheckDefaultSnapshotter: true,
	}
}

func RegisterFeatureTests(suite *FeatureTestSuite) {
	suite.Register("collector_exports_certificate_and_collection_metrics", func(t *testing.T) { testCollectorExportsCertificateAndCollectionMetrics(t, suite) })
	suite.Register("collector_classifies_file_parse_errors", func(t *testing.T) { testCollectorClassifiesFileParseErrors(t, suite) })
	suite.Register("collector_classifies_target_ca_parse_errors", func(t *testing.T) { testCollectorClassifiesTargetCAParseErrors(t, suite) })
	suite.Register("snapshot_engine_accumulates_source_error_counters", func(t *testing.T) { testSnapshotEngineAccumulatesSourceErrorCounters(t) })
	suite.Register("collector_uses_provided_snapshotter", func(t *testing.T) { testCollectorUsesProvidedSnapshotter(t, suite) })
	suite.Register("collector_caches_snapshot_until_refresh_interval", func(t *testing.T) { testCollectorCachesSnapshotUntilRefreshInterval(t, suite) })
	suite.Register("collector_last_successful_collection_is_zero_before_success", func(t *testing.T) { testCollectorLastSuccessfulCollectionIsZeroBeforeSuccess(t, suite) })
	suite.Register("exporter_registers_collector_for_configured_targets", func(t *testing.T) { testExporterRegistersCollectorForConfiguredTargets(t, suite) })
	suite.Register("exporter_registers_collector_for_config_file_targets", func(t *testing.T) { testExporterRegistersCollectorForConfigFileTargets(t, suite) })
	suite.Register("exporter_merges_cli_and_config_file_targets", func(t *testing.T) { testExporterMergesCliAndConfigFileTargets(t, suite) })
	suite.Register("exporter_registers_default_collectors", func(t *testing.T) { testExporterRegistersDefaultCollectors(t, suite) })
	suite.Register("exporter_rejects_invalid_targets", func(t *testing.T) { testExporterRejectsInvalidTargets(t, suite) })
	suite.Register("exporter_runtime_config_normalizes_values", func(t *testing.T) { testExporterRuntimeConfigNormalizesValues(t, suite) })
	suite.Register("smoke_spec_includes_ssl_args", func(t *testing.T) { testSmokeSpecIncludesSSLArgs(t, suite) })
}

func TestSourceHealthyConsidersSourceErrors(t *testing.T) {
	t.Parallel()

	snapshot := sslcheck.Snapshot{
		Errors: []sslcheck.CheckError{{Source: "file", Target: "file checks", Kind: sslcheck.CheckErrorRead, Err: context.Canceled}},
	}

	if sourceHealthy(snapshot, "file", 1, false) {
		t.Fatal("sourceHealthy() = true, want false")
	}
}

func testCollectorExportsCertificateAndCollectionMetrics(t *testing.T, suite *FeatureTestSuite) {
	now := time.Unix(1_700_000_000, 0)
	certPath := writeTestCertificate(t, "file.example", now.Add(-time.Hour), now.Add(time.Hour))

	collector := suite.NewCollectorWithNow(testFeatureName, testMetricNamespace, slog.New(slog.NewTextHandler(io.Discard, nil)), testChecker(
		[]sslcheck.FileCheck{{Path: certPath}},
		nil,
	), testRefreshInterval, func() time.Time { return now })

	registry := prometheus.NewRegistry()
	exportertest.Register(t, registry, collector)
	families := exportertest.Gather(t, registry)

	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", metricCheckSuccess), nil, 1)
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", metricCertificateNotAfter), map[string]string{
		"source":        "file",
		"target":        certPath,
		"chain_index":   "0",
		"subject_cn":    "file.example",
		"issuer_cn":     "file.example",
		"serial_number": "63",
	}, float64(now.Add(time.Hour).Unix()))
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", metricCertificateTemporarilyValid), nil, 1)
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", metricCertificateExpiresIn), nil, 3600)
	exportertest.AssertMetricValue(t, families, testLastSuccess, nil, 1)
	exportertest.AssertMetricValue(t, families, testLastTimestamp, nil, float64(now.Unix()))
	exportertest.AssertMetricValue(t, families, testLastSuccessfulTS, nil, float64(now.Unix()))
	exportertest.AssertMetricValue(t, families, suite.MetricName("", testMetricNamespace, metricConfiguredCertificateFiles), nil, 1)
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", fileMetricIDs.Up), map[string]string{"source": "file"}, 1)
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", fileMetricIDs.Valid), map[string]string{"source": "file"}, 1)
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", fileMetricIDs.ReadErrorsTotal), map[string]string{"source": "file"}, 0)
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", fileMetricIDs.ParseErrorsTotal), map[string]string{"source": "file"}, 0)
}

func testCollectorClassifiesFileParseErrors(t *testing.T, suite *FeatureTestSuite) {
	path := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}

	collector := suite.NewCollector(testFeatureName, testMetricNamespace, testChecker(
		[]sslcheck.FileCheck{{Path: path}},
		nil,
	), testRefreshInterval)

	families := exportertest.RegisterAndGather(t, collector)
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", fileMetricIDs.Up), map[string]string{"source": "file"}, 0)
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", fileMetricIDs.Valid), map[string]string{"source": "file"}, 0)
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", fileMetricIDs.ReadErrorsTotal), map[string]string{"source": "file"}, 0)
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", fileMetricIDs.ParseErrorsTotal), map[string]string{"source": "file"}, 1)
}

func testCollectorClassifiesTargetCAParseErrors(t *testing.T, suite *FeatureTestSuite) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	endpoint, err := sslcheck.ParseEndpoint(server.URL)
	if err != nil {
		t.Fatalf("ParseEndpoint(%q) error = %v", server.URL, err)
	}
	caPath := filepath.Join(t.TempDir(), "invalid-ca.pem")
	if err := os.WriteFile(caPath, []byte("not a certificate"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", caPath, err)
	}

	collector := suite.NewCollector(testFeatureName, testMetricNamespace, testChecker(
		nil,
		[]sslcheck.TargetCheck{{Endpoint: endpoint, CAFile: caPath}},
	), testRefreshInterval)

	families := exportertest.RegisterAndGather(t, collector)
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", targetMetricIDs.Up), map[string]string{"source": "target"}, 0)
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", targetMetricIDs.Valid), map[string]string{"source": "target"}, 0)
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", targetMetricIDs.ReadErrorsTotal), map[string]string{"source": "target"}, 0)
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", targetMetricIDs.ParseErrorsTotal), map[string]string{"source": "target"}, 1)
}

func testSnapshotEngineAccumulatesSourceErrorCounters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(path, []byte("not a certificate"), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}

	engine, err := newSnapshotEngine(Config{
		fileChecks:           []sslcheck.FileCheck{{Path: path}},
		Timeout:              DefaultTimeout,
		MaxConcurrentTargets: DefaultMaxConcurrentTargets,
	})
	if err != nil {
		t.Fatalf("newSnapshotEngine() error = %v", err)
	}

	first := engine.Snapshot(context.Background(), time.Unix(1_700_000_000, 0))
	if first.FileResult.ParseErrorsTotal != 1 {
		t.Fatalf("first FileResult.ParseErrorsTotal = %d, want 1", first.FileResult.ParseErrorsTotal)
	}

	second := engine.Snapshot(context.Background(), time.Unix(1_700_000_001, 0))
	if second.FileResult.ParseErrorsTotal != 2 {
		t.Fatalf("second FileResult.ParseErrorsTotal = %d, want 2", second.FileResult.ParseErrorsTotal)
	}
}

func testCollectorUsesProvidedSnapshotter(t *testing.T, suite *FeatureTestSuite) {
	now := time.Unix(1_700_000_000, 0)
	snapshotter := suite.NewFakeSnapshotter(Snapshot{})
	snapshotter.Set(Snapshot{
		ssl: sslcheck.Snapshot{
			AttemptTime: now,
			Success:     true,
			Checks: []sslcheck.CheckStatus{
				{Source: "target", Target: "example.com:443", Success: true},
			},
		},
	})
	collector := suite.NewCollectorWithNow(testFeatureName, testMetricNamespace, slog.New(slog.NewTextHandler(io.Discard, nil)), snapshotter, testRefreshInterval, func() time.Time {
		return now
	})

	families := exportertest.RegisterAndGather(t, collector)
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", metricCheckSuccess), map[string]string{
		"source": "target",
		"target": "example.com:443",
	}, 1)
	exportertest.AssertMetricValue(t, families, testLastSuccess, nil, 1)
}

func testCollectorCachesSnapshotUntilRefreshInterval(t *testing.T, suite *FeatureTestSuite) {
	start := time.Unix(1_700_000_000, 0)
	now := start
	certPath := writeTestCertificate(t, "file.example", start.Add(-time.Hour), start.Add(time.Hour))

	collector := suite.NewCollectorWithNow(testFeatureName, testMetricNamespace, slog.New(slog.NewTextHandler(io.Discard, nil)), testChecker(
		[]sslcheck.FileCheck{{Path: certPath}},
		nil,
	), time.Hour, func() time.Time { return now })

	registry := prometheus.NewRegistry()
	exportertest.Register(t, registry, collector)

	families := exportertest.Gather(t, registry)
	exportertest.AssertMetricValue(t, families, testLastSuccess, nil, 1)
	exportertest.AssertMetricValue(t, families, testLastTimestamp, nil, float64(start.Unix()))
	exportertest.AssertMetricValue(t, families, testLastSuccessfulTS, nil, float64(start.Unix()))

	if err := os.Remove(certPath); err != nil {
		t.Fatalf("Remove(%q) error = %v", certPath, err)
	}

	now = start.Add(30 * time.Minute)
	families = exportertest.Gather(t, registry)
	exportertest.AssertMetricValue(t, families, testLastSuccess, nil, 1)
	exportertest.AssertMetricValue(t, families, testLastTimestamp, nil, float64(start.Unix()))
	exportertest.AssertMetricValue(t, families, testLastSuccessfulTS, nil, float64(start.Unix()))

	now = start.Add(2 * time.Hour)
	families = exportertest.Gather(t, registry)
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", metricCheckSuccess), nil, 0)
	exportertest.AssertMetricValue(t, families, testLastSuccess, nil, 0)
	exportertest.AssertMetricValue(t, families, testLastTimestamp, nil, float64(now.Unix()))
	exportertest.AssertMetricValue(t, families, testLastSuccessfulTS, nil, float64(start.Unix()))
}

func testCollectorLastSuccessfulCollectionIsZeroBeforeSuccess(t *testing.T, suite *FeatureTestSuite) {
	collector := suite.NewCollector(testFeatureName, testMetricNamespace, testChecker(
		[]sslcheck.FileCheck{{Path: filepath.Join(t.TempDir(), "missing.pem")}},
		nil,
	), testRefreshInterval)

	registry := prometheus.NewRegistry()
	exportertest.Register(t, registry, collector)

	families := exportertest.Gather(t, registry)
	exportertest.AssertMetricValue(t, families, testLastSuccess, nil, 0)
	exportertest.AssertMetricValue(t, families, testLastSuccessfulTS, nil, 0)
}

func testExporterRegistersCollectorForConfiguredTargets(t *testing.T, suite *FeatureTestSuite) {
	now := time.Unix(1_700_000_000, 0)
	certPath := writeTestCertificate(t, "file.example", now.Add(-time.Hour), now.Add(time.Hour))

	exporter := suite.NewNamedFeature()
	suite.ParseFeatureFlags(t, exporter, []string{"--" + testFeatureName + ".target=file=" + certPath})

	registry := suite.RegisterFeatureCollectors(t, exporter)
	families := exportertest.Gather(t, registry)
	exportertest.AssertMetricValue(t, families, suite.MetricName("", testMetricNamespace, metricConfiguredCertificateFiles), nil, 1)
	exportertest.AssertMetricValue(t, families, suite.MetricName("", testMetricNamespace, metricConfiguredTargets), nil, 0)
}

func testExporterRegistersCollectorForConfigFileTargets(t *testing.T, suite *FeatureTestSuite) {
	now := time.Unix(1_700_000_000, 0)
	certPath := writeTestCertificate(t, "file.example", now.Add(-time.Hour), now.Add(time.Hour))
	configPath := suite.WriteConfig(t, "targets:\n  - file: "+certPath+"\n")

	exporter := suite.NewNamedFeature()
	suite.ParseFeatureFlags(t, exporter, []string{"--" + testFeatureName + ".config-file=" + configPath})

	registry := suite.RegisterFeatureCollectors(t, exporter)
	families := exportertest.Gather(t, registry)
	exportertest.AssertMetricValue(t, families, suite.MetricName("", testMetricNamespace, metricConfiguredCertificateFiles), nil, 1)
}

func testExporterMergesCliAndConfigFileTargets(t *testing.T, suite *FeatureTestSuite) {
	now := time.Unix(1_700_000_000, 0)
	certPathA := writeTestCertificate(t, "file-a.example", now.Add(-time.Hour), now.Add(time.Hour))
	certPathB := writeTestCertificate(t, "file-b.example", now.Add(-time.Hour), now.Add(time.Hour))

	configPath := suite.WriteConfig(t, "targets:\n  - file: "+certPathA+"\n")

	exporter := suite.NewNamedFeature()
	suite.ParseFeatureFlags(t, exporter, []string{
		"--" + testFeatureName + ".config-file=" + configPath,
		"--" + testFeatureName + ".target=file=" + certPathB,
	})

	registry := suite.RegisterFeatureCollectors(t, exporter)
	exportertest.WaitForMetricValue(t, registry, testLastSuccess, nil, 1)
	families := exportertest.Gather(t, registry)

	exportertest.AssertMetricValue(t, families, suite.MetricName("", testMetricNamespace, metricConfiguredCertificateFiles), nil, 2)
	exportertest.AssertMetricValue(t, families, suite.MetricName("", testMetricNamespace, metricConfiguredTargets), nil, 0)

	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", metricCheckSuccess), map[string]string{
		"source": "file",
		"target": certPathA,
	}, 1)
	exportertest.AssertMetricValue(t, families, suite.MetricName(testFeatureName, "", metricCheckSuccess), map[string]string{
		"source": "file",
		"target": certPathB,
	}, 1)
}

func testExporterRegistersDefaultCollectors(t *testing.T, suite *FeatureTestSuite) {
	exporter := suite.NewNamedFeature()

	registry := suite.RegisterFeatureCollectors(t, exporter)
	exportertest.WaitForMetricValue(t, registry, testLastSuccess, nil, 1)
	families := exportertest.Gather(t, registry)
	exportertest.AssertMetricValue(t, families, suite.MetricName("", testMetricNamespace, metricConfiguredCertificateFiles), nil, 0)
	exportertest.AssertMetricValue(t, families, suite.MetricName("", testMetricNamespace, metricConfiguredTargets), nil, 0)
}

func testExporterRejectsInvalidTargets(t *testing.T, suite *FeatureTestSuite) {
	exporter := suite.NewNamedFeature()
	suite.ParseFeatureFlags(t, exporter, []string{"--" + testFeatureName + ".target=address=example.com,file=/tmp/cert.pem"})

	err := exporter.RegisterCollectors(suite.FeatureContext(), prometheus.NewRegistry())
	if err == nil {
		t.Fatal("RegisterCollectors() error = nil, want error")
	}
}

func testExporterRuntimeConfigNormalizesValues(t *testing.T, suite *FeatureTestSuite) {
	exporter := suite.NewNamedFeature()
	suite.ParseFeatureFlags(t, exporter, []string{
		"--" + testFeatureName + ".target=address=example.com",
		"--" + testFeatureName + ".config-file=/tmp/ssl-targets.yml",
		"--" + testFeatureName + ".refresh-interval=0s",
		"--" + testFeatureName + ".timeout=0s",
		"--" + testFeatureName + ".max-concurrent-targets=0",
	})

	config := exporter.RuntimeConfig()
	if got := exportertest.RuntimeConfigValue(t, config, "refresh_interval"); got != DefaultRefreshInterval {
		t.Fatalf("refresh_interval = %v, want %v", got, DefaultRefreshInterval)
	}
	if got := exportertest.RuntimeConfigValue(t, config, "timeout"); got != DefaultTimeout {
		t.Fatalf("timeout = %v, want %v", got, DefaultTimeout)
	}
	if got := exportertest.RuntimeConfigValue(t, config, "max_concurrent_targets"); got != DefaultMaxConcurrentTargets {
		t.Fatalf("max_concurrent_targets = %v, want %v", got, DefaultMaxConcurrentTargets)
	}
	if got := exportertest.RuntimeConfigValue(t, config, "config_file"); got != "/tmp/ssl-targets.yml" {
		t.Fatalf("config_file = %q, want /tmp/ssl-targets.yml", got)
	}
	if got := exportertest.RuntimeConfigValue(t, config, "config_file_loaded"); got != false {
		t.Fatalf("config_file_loaded = %v, want false", got)
	}
}

func testSmokeSpecIncludesSSLArgs(t *testing.T, suite *FeatureTestSuite) {
	spec := suite.NewNamedFeature().SmokeSpec()
	wantConfigFile := "--" + testFeatureName + ".config-file=" + DefaultFeatureConfigPath
	wantTarget := "--" + testFeatureName + ".target=file=testdata/smoke-cert.pem"
	wantConcurrency := "--" + testFeatureName + ".max-concurrent-targets=2"
	if !featuretest.HasString(spec.ServerArgs, wantConfigFile) {
		t.Fatalf("SmokeSpec().ServerArgs = %v, want %q", spec.ServerArgs, wantConfigFile)
	}
	if !featuretest.HasString(spec.ServerArgs, wantTarget) {
		t.Fatalf("SmokeSpec().ServerArgs = %v, want %q", spec.ServerArgs, wantTarget)
	}
	if !featuretest.HasString(spec.ServerArgs, wantConcurrency) {
		t.Fatalf("SmokeSpec().ServerArgs = %v, want %q", spec.ServerArgs, wantConcurrency)
	}
	checkSuccess := suite.MetricName(testFeatureName, "", metricCheckSuccess) + `{source="file",target="testdata/smoke-cert.pem"}`
	if !featuretest.HasString(spec.WantMetrics, checkSuccess+" 1") {
		t.Fatalf("SmokeSpec().WantMetrics = %v, want %q", spec.WantMetrics, checkSuccess+" 1")
	}
	if !featuretest.HasString(spec.WantMetrics, suite.MetricName(testFeatureName, "", metricCertificateTemporarilyValid)+`{`) {
		t.Fatalf("SmokeSpec().WantMetrics = %v, want certificate validity metric", spec.WantMetrics)
	}
	if !featuretest.HasString(spec.RejectMetrics, checkSuccess+" 0") {
		t.Fatalf("SmokeSpec().RejectMetrics = %v, want %q", spec.RejectMetrics, checkSuccess+" 0")
	}
}

func writeTestCertificate(t *testing.T, commonName string, notBefore time.Time, notAfter time.Time) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}

	path := filepath.Join(t.TempDir(), "cert.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func testChecker(files []sslcheck.FileCheck, targets []sslcheck.TargetCheck) framework.Snapshotter[Snapshot] {
	c := sslcheck.NewChecker(files, targets, DefaultTimeout, DefaultMaxConcurrentTargets)
	return featurekit.SnapshotEngineFunc[Snapshot](func(ctx context.Context, now time.Time) Snapshot {
		sslSnapshot := c.Check(ctx, now)
		errorCounts := countSourceErrors(sslSnapshot)
		return Snapshot{
			ssl:          sslSnapshot,
			FileResult:   sourceHealthResult(sslSnapshot, "file", sslSnapshot.ConfiguredCertificateFiles, errorCounts.fileRead, errorCounts.fileParse, now, 0.25),
			TargetResult: sourceHealthResult(sslSnapshot, "target", sslSnapshot.ConfiguredTargets, errorCounts.targetRead, errorCounts.targetParse, now, 0.25),
		}
	})
}
