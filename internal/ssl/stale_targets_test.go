package ssl

import (
	"errors"
	"testing"
	"time"

	"github.com/zxzharmlesszxz/prometheus-ssl-exporter/internal/sslcheck"
)

func TestStaleTargetSmootherKeepsLastKnownGoodDuringToleratedReadFailures(t *testing.T) {
	t.Parallel()

	target := testTargetCheck(t, "example.com", "443")
	now := time.Unix(1_700_000_000, 0)
	smoother := newStaleTargetSmoother(1)

	success := sslcheck.Snapshot{
		AttemptTime:       now,
		Success:           true,
		Checks:            []sslcheck.CheckStatus{{Source: "target", Target: target.Endpoint.Raw, Success: true}},
		ChainResults:      []sslcheck.ChainResult{{Source: "target", Target: target.Endpoint.Raw, ChainVerified: true}},
		TargetResults:     []sslcheck.TargetResult{{Target: target.Endpoint.Raw, ChainVerified: true}},
		Certificates:      []sslcheck.Certificate{{Source: "target", Target: target.Endpoint.Raw, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}},
		ConfiguredTargets: 1,
	}

	states := smoother.Apply(&success, []sslcheck.TargetCheck{target}, now)
	if !success.Success {
		t.Fatal("success.Success = false, want true")
	}
	assertTargetState(t, states, target.Endpoint.Raw, 0, false, now)

	firstFailureTime := now.Add(time.Minute)
	firstFailure := targetReadFailureSnapshot(target.Endpoint.Raw, firstFailureTime)
	states = smoother.Apply(&firstFailure, []sslcheck.TargetCheck{target}, firstFailureTime)

	if !firstFailure.Success {
		t.Fatal("firstFailure.Success = false, want true for tolerated stale target result")
	}
	if len(firstFailure.Certificates) != 1 {
		t.Fatalf("len(firstFailure.Certificates) = %d, want 1 stale certificate", len(firstFailure.Certificates))
	}
	if len(firstFailure.ChainResults) != 1 {
		t.Fatalf("len(firstFailure.ChainResults) = %d, want 1 stale chain result", len(firstFailure.ChainResults))
	}
	assertTargetState(t, states, target.Endpoint.Raw, 1, true, now)

	secondFailureTime := now.Add(2 * time.Minute)
	secondFailure := targetReadFailureSnapshot(target.Endpoint.Raw, secondFailureTime)
	states = smoother.Apply(&secondFailure, []sslcheck.TargetCheck{target}, secondFailureTime)

	if secondFailure.Success {
		t.Fatal("secondFailure.Success = true, want false after stale target failure limit")
	}
	if len(secondFailure.Certificates) != 0 {
		t.Fatalf("len(secondFailure.Certificates) = %d, want 0 stale certificates after limit", len(secondFailure.Certificates))
	}
	assertTargetState(t, states, target.Endpoint.Raw, 2, false, now)
}

func TestStaleTargetSmootherDoesNotTolerateTargetParseFailures(t *testing.T) {
	t.Parallel()

	target := testTargetCheck(t, "example.com", "443")
	now := time.Unix(1_700_000_000, 0)
	smoother := newStaleTargetSmoother(DefaultMaxStaleTargetFailures)

	success := sslcheck.Snapshot{
		AttemptTime:       now,
		Success:           true,
		Checks:            []sslcheck.CheckStatus{{Source: "target", Target: target.Endpoint.Raw, Success: true}},
		Certificates:      []sslcheck.Certificate{{Source: "target", Target: target.Endpoint.Raw, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}},
		ConfiguredTargets: 1,
	}
	smoother.Apply(&success, []sslcheck.TargetCheck{target}, now)

	failure := sslcheck.Snapshot{
		AttemptTime:       now.Add(time.Minute),
		Success:           false,
		Checks:            []sslcheck.CheckStatus{{Source: "target", Target: target.Endpoint.Raw, Success: false}},
		Errors:            []sslcheck.CheckError{{Source: "target", Target: target.Endpoint.Raw, Kind: sslcheck.CheckErrorParse, Err: errors.New("parse failed")}},
		ConfiguredTargets: 1,
	}
	states := smoother.Apply(&failure, []sslcheck.TargetCheck{target}, failure.AttemptTime)

	if failure.Success {
		t.Fatal("failure.Success = true, want false for parse failure")
	}
	if len(failure.Certificates) != 0 {
		t.Fatalf("len(failure.Certificates) = %d, want 0 stale certificates for parse failure", len(failure.Certificates))
	}
	assertTargetState(t, states, target.Endpoint.Raw, 0, false, now)
}

func targetReadFailureSnapshot(target string, now time.Time) sslcheck.Snapshot {
	return sslcheck.Snapshot{
		AttemptTime:       now,
		Success:           false,
		Checks:            []sslcheck.CheckStatus{{Source: "target", Target: target, Success: false}},
		Errors:            []sslcheck.CheckError{{Source: "target", Target: target, Kind: sslcheck.CheckErrorRead, Err: errors.New("connect failed")}},
		ConfiguredTargets: 1,
	}
}

func testTargetCheck(t *testing.T, host string, port string) sslcheck.TargetCheck {
	t.Helper()

	endpoint, err := sslcheck.EndpointFromAddress(host, port)
	if err != nil {
		t.Fatalf("EndpointFromAddress() error = %v", err)
	}
	return sslcheck.TargetCheck{Endpoint: endpoint}
}

func assertTargetState(t *testing.T, states []TargetState, target string, failures int, usingStale bool, lastSuccess time.Time) {
	t.Helper()

	if len(states) != 1 {
		t.Fatalf("len(states) = %d, want 1", len(states))
	}
	if states[0].Target != target {
		t.Fatalf("states[0].Target = %q, want %q", states[0].Target, target)
	}
	if states[0].ConsecutiveFailures != failures {
		t.Fatalf("states[0].ConsecutiveFailures = %d, want %d", states[0].ConsecutiveFailures, failures)
	}
	if states[0].UsingStaleResult != usingStale {
		t.Fatalf("states[0].UsingStaleResult = %v, want %v", states[0].UsingStaleResult, usingStale)
	}
	if !states[0].LastSuccess.Equal(lastSuccess) {
		t.Fatalf("states[0].LastSuccess = %v, want %v", states[0].LastSuccess, lastSuccess)
	}
}
