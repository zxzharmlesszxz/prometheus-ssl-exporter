package ssl

import (
	"time"

	"github.com/zxzharmlesszxz/prometheus-exporter-framework/exporter/featurekit"

	"github.com/zxzharmlesszxz/prometheus-ssl-exporter/internal/sslcheck"
)

type staleTargetSmoother struct {
	maxFailures int
	targets     *featurekit.LastKnownGood[string, staleTargetValue]
}

type staleTargetValue struct {
	chainResults  []sslcheck.ChainResult
	targetResults []sslcheck.TargetResult
	certificates  []sslcheck.Certificate
}

func newStaleTargetSmoother(maxFailures int) *staleTargetSmoother {
	if maxFailures < 0 {
		maxFailures = DefaultMaxStaleTargetFailures
	}
	return &staleTargetSmoother{
		maxFailures: maxFailures,
		targets:     featurekit.NewLastKnownGood[string, staleTargetValue](0),
	}
}

func (s *staleTargetSmoother) Apply(snapshot *sslcheck.Snapshot, targets []sslcheck.TargetCheck, now time.Time) []TargetState {
	if len(targets) == 0 {
		return nil
	}

	checks := targetChecksByName(snapshot.Checks)
	readFailures := targetReadFailures(snapshot.Errors)
	tolerated := make(map[string]bool)
	states := make([]TargetState, 0, len(targets))

	for _, target := range targets {
		name := target.Endpoint.Raw
		check, hasCheck := checks[name]

		if hasCheck && check.Success {
			s.targets.Success(name, staleTargetValue{
				chainResults:  copyChainResultsForTarget(snapshot.ChainResults, name),
				targetResults: copyTargetResultsForTarget(snapshot.TargetResults, name),
				certificates:  copyCertificatesForTarget(snapshot.Certificates, name, now),
			}, now)
		} else if hasCheck && readFailures[name] {
			s.targets.Failure(name, now)
			result := s.targets.Get(name, now)
			if s.canUseStale(result) {
				appendLastKnownGood(snapshot, name, result.Value, now)
				tolerated[name] = true
			}
		}

		result := s.targets.Get(name, now)
		states = append(states, TargetState{
			Target:              name,
			ConsecutiveFailures: consecutiveFailuresInt(result.ConsecutiveFailures),
			UsingStaleResult:    tolerated[name],
			LastSuccess:         result.LastSuccess,
		})
	}

	if len(tolerated) > 0 {
		snapshot.Success = collectionSuccessWithToleratedTargetFailures(*snapshot, tolerated)
	}

	return states
}

func (s *staleTargetSmoother) canUseStale(result featurekit.LastKnownGoodResult[staleTargetValue]) bool {
	return s.maxFailures > 0 && result.Available && result.ConsecutiveFailures <= uint64(s.maxFailures) && len(result.Value.certificates) > 0
}

func consecutiveFailuresInt(value uint64) int {
	maxInt := int(^uint(0) >> 1)
	if value > uint64(maxInt) {
		return maxInt
	}
	return int(value)
}

func targetChecksByName(checks []sslcheck.CheckStatus) map[string]sslcheck.CheckStatus {
	result := make(map[string]sslcheck.CheckStatus)
	for _, check := range checks {
		if check.Source == metricTargetSource {
			result[check.Target] = check
		}
	}
	return result
}

func targetReadFailures(errors []sslcheck.CheckError) map[string]bool {
	result := make(map[string]bool)
	for _, checkError := range errors {
		if checkError.Source == metricTargetSource && checkError.Kind == sslcheck.CheckErrorRead {
			result[checkError.Target] = true
		}
	}
	return result
}

func appendLastKnownGood(snapshot *sslcheck.Snapshot, target string, value staleTargetValue, now time.Time) {
	snapshot.ChainResults = append(snapshot.ChainResults, copyChainResultsForTarget(value.chainResults, target)...)
	snapshot.TargetResults = append(snapshot.TargetResults, copyTargetResultsForTarget(value.targetResults, target)...)
	snapshot.Certificates = append(snapshot.Certificates, copyCertificatesForTarget(value.certificates, target, now)...)
}

func collectionSuccessWithToleratedTargetFailures(snapshot sslcheck.Snapshot, tolerated map[string]bool) bool {
	for _, check := range snapshot.Checks {
		if check.Success {
			continue
		}
		if check.Source == metricTargetSource && tolerated[check.Target] {
			continue
		}
		return false
	}
	for _, checkError := range snapshot.Errors {
		if checkError.Source == metricTargetSource && checkError.Kind == sslcheck.CheckErrorRead && tolerated[checkError.Target] {
			continue
		}
		return false
	}
	return true
}

func copyChainResultsForTarget(values []sslcheck.ChainResult, target string) []sslcheck.ChainResult {
	result := make([]sslcheck.ChainResult, 0, len(values))
	for _, value := range values {
		if value.Source == metricTargetSource && value.Target == target {
			result = append(result, value)
		}
	}
	return result
}

func copyTargetResultsForTarget(values []sslcheck.TargetResult, target string) []sslcheck.TargetResult {
	result := make([]sslcheck.TargetResult, 0, len(values))
	for _, value := range values {
		if value.Target == target {
			result = append(result, value)
		}
	}
	return result
}

func copyCertificatesForTarget(values []sslcheck.Certificate, target string, now time.Time) []sslcheck.Certificate {
	result := make([]sslcheck.Certificate, 0, len(values))
	for _, value := range values {
		if value.Source != metricTargetSource || value.Target != target {
			continue
		}
		value.TemporarilyValidNow = !now.Before(value.NotBefore) && now.Before(value.NotAfter)
		result = append(result, value)
	}
	return result
}
