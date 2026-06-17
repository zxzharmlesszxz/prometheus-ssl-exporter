package ssl

import (
	framework "github.com/zxzharmlesszxz/prometheus-exporter-framework/exporter"

	"github.com/zxzharmlesszxz/prometheus-ssl-exporter/internal/sslcheck"
)

type Snapshot struct {
	ssl          sslcheck.Snapshot
	FileResult   framework.FileScrapeResult
	TargetResult framework.FileScrapeResult
}
