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
	return newSnapshotEngine(ctx.Config)
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
	var fileParseErrors atomic.Uint64
	var targetErrors atomic.Uint64
	var targetParseErrors atomic.Uint64

	return featurekit.SnapshotEngineFunc[Snapshot](func(ctx context.Context, now time.Time) Snapshot {
		start := time.Now()
		sslSnapshot := checker.Check(ctx, now)
		errorCounts := countSourceErrors(sslSnapshot)
		if errorCounts.fileRead > 0 {
			fileErrors.Add(errorCounts.fileRead)
		}
		if errorCounts.fileParse > 0 {
			fileParseErrors.Add(errorCounts.fileParse)
		}
		if errorCounts.targetRead > 0 {
			targetErrors.Add(errorCounts.targetRead)
		}
		if errorCounts.targetParse > 0 {
			targetParseErrors.Add(errorCounts.targetParse)
		}

		duration := time.Since(start).Seconds()
		return Snapshot{
			ssl:          sslSnapshot,
			FileResult:   sourceHealthResult(sslSnapshot, "file", sslSnapshot.ConfiguredCertificateFiles, fileErrors.Load(), fileParseErrors.Load(), now, duration),
			TargetResult: sourceHealthResult(sslSnapshot, "target", sslSnapshot.ConfiguredTargets, targetErrors.Load(), targetParseErrors.Load(), now, duration),
		}
	}), nil
}

func sourceHealthResult(snapshot sslcheck.Snapshot, source string, configured int, readErrors uint64, parseErrors uint64, now time.Time, duration float64) framework.FileScrapeResult {
	if configured == 0 && readErrors == 0 && parseErrors == 0 {
		return framework.FileScrapeResult{}
	}
	return framework.FileScrapeResult{
		Path:                  source,
		Up:                    sourceHealthy(snapshot, source, configured, false),
		MTimeSeconds:          float64(now.Unix()),
		ReadErrorsTotal:       readErrors,
		ParseErrorsTotal:      parseErrors,
		ScrapeDurationSeconds: duration,
	}
}

type sourceErrorCounts struct {
	fileRead    uint64
	fileParse   uint64
	targetRead  uint64
	targetParse uint64
}

func countSourceErrors(snapshot sslcheck.Snapshot) sourceErrorCounts {
	var counts sourceErrorCounts
	for _, checkError := range snapshot.Errors {
		switch checkError.Source {
		case "file":
			if checkError.Kind == sslcheck.CheckErrorParse {
				counts.fileParse++
			} else {
				counts.fileRead++
			}
		case "target":
			if checkError.Kind == sslcheck.CheckErrorParse {
				counts.targetParse++
			} else {
				counts.targetRead++
			}
		}
	}
	return counts
}

func sourceHealthy(snapshot sslcheck.Snapshot, source string, configured int, includeChain bool) bool {
	if configured == 0 {
		return false
	}
	for _, status := range snapshot.Checks {
		if status.Source == source && !status.Success {
			return false
		}
	}
	for _, checkError := range snapshot.Errors {
		if checkError.Source == source {
			return false
		}
	}
	if includeChain {
		for _, chain := range snapshot.ChainResults {
			if chain.Source == source && !chain.ChainVerified {
				return false
			}
		}
	}
	return true
}
