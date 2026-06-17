package ssl

import (
	"context"
	"sync/atomic"
	"time"

	framework "github.com/zxzharmlesszxz/prometheus-exporter-framework/exporter"
	"github.com/zxzharmlesszxz/prometheus-exporter-framework/exporter/featurekit"

	"github.com/zxzharmlesszxz/prometheus-ssl-exporter/internal/sslcheck"
)

func NewDefaultSnapshotEngine() featurekit.SnapshotEngine[Snapshot] {
	engine, err := newSnapshotEngine(NewDefaultConfig())
	if err != nil {
		panic(err)
	}
	return engine
}

func NewSnapshotEngine(ctx featurekit.CollectorContext[Config]) (featurekit.SnapshotEngine[Snapshot], error) {
	config, _, _, err := ResolveFeatureConfig(ctx.FeatureName, ctx.Config)
	if err != nil {
		return nil, err
	}
	return newSnapshotEngine(config)
}

func FeatureSnapshotStatus(snapshot Snapshot) framework.SnapshotStatus {
	return framework.SnapshotStatus{
		AttemptTime: snapshot.ssl.AttemptTime,
		Success:     snapshot.ssl.Success,
	}
}

func newSnapshotEngine(config Config) (featurekit.SnapshotEngine[Snapshot], error) {
	files, targets, err := sslcheck.ParseTargets(config.Targets)
	if err != nil {
		return nil, err
	}
	files = append(config.fileChecks, files...)
	targets = append(config.targetChecks, targets...)

	checker := sslcheck.NewChecker(
		files,
		targets,
		config.Timeout,
		config.MaxConcurrentTargets,
	)
	var fileErrors atomic.Uint64
	var targetErrors atomic.Uint64

	return featurekit.SnapshotEngineFunc[Snapshot](func(ctx context.Context, now time.Time) Snapshot {
		start := time.Now()
		sslSnapshot := checker.Check(ctx, now)
		fileErrorCount, targetErrorCount := countSourceErrors(sslSnapshot)
		if fileErrorCount > 0 {
			fileErrors.Add(fileErrorCount)
		}
		if targetErrorCount > 0 {
			targetErrors.Add(targetErrorCount)
		}

		duration := time.Since(start).Seconds()
		return Snapshot{
			ssl:          sslSnapshot,
			FileResult:   sourceHealthResult(sslSnapshot, "file", sslSnapshot.ConfiguredCertificateFiles, fileErrors.Load(), now, duration),
			TargetResult: sourceHealthResult(sslSnapshot, "target", sslSnapshot.ConfiguredTargets, targetErrors.Load(), now, duration),
		}
	}), nil
}

func sourceHealthResult(snapshot sslcheck.Snapshot, source string, configured int, readErrors uint64, now time.Time, duration float64) framework.FileScrapeResult {
	if configured == 0 && readErrors == 0 {
		return framework.FileScrapeResult{}
	}
	return framework.FileScrapeResult{
		Path:                  source,
		Up:                    sourceChecksUp(snapshot, source, configured),
		MTimeSeconds:          float64(now.Unix()),
		ReadErrorsTotal:       readErrors,
		ParseErrorsTotal:      0,
		ScrapeDurationSeconds: duration,
	}
}

func countSourceErrors(snapshot sslcheck.Snapshot) (uint64, uint64) {
	var fileErrors uint64
	var targetErrors uint64
	for _, checkError := range snapshot.Errors {
		switch checkError.Source {
		case "file":
			fileErrors++
		case "target":
			targetErrors++
		}
	}
	return fileErrors, targetErrors
}

func sourceChecksUp(snapshot sslcheck.Snapshot, source string, configured int) bool {
	if configured == 0 {
		return false
	}
	for _, status := range snapshot.Checks {
		if status.Source == source && !status.Success {
			return false
		}
	}
	return true
}
