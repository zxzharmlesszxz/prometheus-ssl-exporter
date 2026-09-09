package ssl

import (
	"time"

	framework "github.com/zxzharmlesszxz/prometheus-exporter-framework/exporter"

	"github.com/zxzharmlesszxz/prometheus-ssl-exporter/internal/sslcheck"
)

type Snapshot struct {
	ssl          sslcheck.Snapshot
	FileResult   framework.FileScrapeResult
	TargetResult framework.FileScrapeResult
	TargetStates []TargetState
}

type TargetState struct {
	Target              string
	ConsecutiveFailures int
	UsingStaleResult    bool
	LastSuccess         time.Time
}
