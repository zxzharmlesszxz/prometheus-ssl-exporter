package ssl

import "github.com/zxzharmlesszxz/prometheus-ssl-exporter/internal/sslcheck"

type Snapshot struct {
	ssl sslcheck.Snapshot
}
