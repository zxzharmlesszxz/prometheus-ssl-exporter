package sslcheck

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestCheckerChecksFilesAndTargets(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	certBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: testCertificateDER(t, "file.example", now.Add(-time.Hour), now.Add(time.Hour)),
	})
	if err := os.WriteFile(certPath, certBytes, 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	endpoint, err := ParseEndpoint(server.URL)
	if err != nil {
		t.Fatalf("ParseEndpoint(%q) error = %v", server.URL, err)
	}

	snapshot := Checker{
		Files:   []FileCheck{{Path: certPath}},
		Targets: []TargetCheck{{Endpoint: endpoint}},
		Timeout: time.Second,
	}.Check(context.Background(), now)

	if !snapshot.Success {
		t.Fatalf("snapshot.Success = false, errors = %#v", snapshot.Errors)
	}
	if len(snapshot.Checks) != 2 {
		t.Fatalf("len(snapshot.Checks) = %d, want 2", len(snapshot.Checks))
	}
	if len(snapshot.Certificates) < 2 {
		t.Fatalf("len(snapshot.Certificates) = %d, want at least 2", len(snapshot.Certificates))
	}
	if len(snapshot.TargetResults) != 1 {
		t.Fatalf("len(snapshot.TargetResults) = %d, want 1", len(snapshot.TargetResults))
	}
	if len(snapshot.ChainResults) != 1 {
		t.Fatalf("len(snapshot.ChainResults) = %d, want 1", len(snapshot.ChainResults))
	}
	if snapshot.TargetResults[0].ChainVerified {
		t.Fatal("TargetResults[0].ChainVerified = true, want false for httptest self-signed certificate")
	}
}

func TestNewCheckerSetsDefaults(t *testing.T) {
	t.Parallel()

	endpoint, err := ParseEndpoint("example.com:443")
	if err != nil {
		t.Fatalf("ParseEndpoint() error = %v, want nil", err)
	}

	checker := NewChecker(
		[]FileCheck{{Path: "/tmp/cert.pem"}},
		[]TargetCheck{{Endpoint: endpoint}},
		0,
		0,
	)

	if checker.Timeout != DefaultTimeout {
		t.Fatalf("NewChecker().Timeout = %v, want %v", checker.Timeout, DefaultTimeout)
	}
	if checker.MaxConcurrentTargets != DefaultMaxConcurrentTargets {
		t.Fatalf("NewChecker().MaxConcurrentTargets = %d, want %d", checker.MaxConcurrentTargets, DefaultMaxConcurrentTargets)
	}
	if got := checker.ConfiguredCertificateFiles(); got != 1 {
		t.Fatalf("ConfiguredCertificateFiles() = %d, want 1", got)
	}
	if got := checker.ConfiguredTargets(); got != 1 {
		t.Fatalf("ConfiguredTargets() = %d, want 1", got)
	}
}

func TestCheckerSnapshotAndConfiguredCounts(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	snapshot := Checker{}.Snapshot(context.Background(), now)
	if !snapshot.Success {
		t.Fatalf("snapshot.Success = false, errors = %#v", snapshot.Errors)
	}
	if !snapshot.AttemptTime.Equal(now) {
		t.Fatalf("snapshot.AttemptTime = %v, want %v", snapshot.AttemptTime, now)
	}

	checker := Checker{
		Files:   []FileCheck{{Path: "one.pem"}, {Path: "two.pem"}},
		Targets: []TargetCheck{{}, {}, {}},
	}
	if got := checker.ConfiguredCertificateFiles(); got != 2 {
		t.Fatalf("ConfiguredCertificateFiles() = %d, want 2", got)
	}
	if got := checker.ConfiguredTargets(); got != 3 {
		t.Fatalf("ConfiguredTargets() = %d, want 3", got)
	}
}

func TestSerialNumber(t *testing.T) {
	t.Parallel()

	if got := serialNumber(nil); got != "" {
		t.Fatalf("serialNumber(nil) = %q, want empty string", got)
	}
	if got := serialNumber(big.NewInt(0x1af)); got != "1AF" {
		t.Fatalf("serialNumber(0x1af) = %q, want %q", got, "1AF")
	}
}

func TestCheckErrorKind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want CheckErrorKind
	}{
		{
			name: "read certificate file error",
			err:  &CertificateFileError{Kind: CheckErrorRead, Path: "ca.pem", Err: errors.New("read failed")},
			want: CheckErrorRead,
		},
		{
			name: "parse certificate file error",
			err:  &CertificateFileError{Kind: CheckErrorParse, Path: "ca.pem", Err: errors.New("parse failed")},
			want: CheckErrorParse,
		},
		{
			name: "wrapped parse certificate file error",
			err:  fmt.Errorf("read CA file: %w", &CertificateFileError{Kind: CheckErrorParse, Path: "ca.pem", Err: errors.New("parse failed")}),
			want: CheckErrorParse,
		},
		{
			name: "plain error defaults to read",
			err:  errors.New("connect failed"),
			want: CheckErrorRead,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := checkErrorKind(tc.err); got != tc.want {
				t.Fatalf("checkErrorKind() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCheckerRecordsFailures(t *testing.T) {
	t.Parallel()

	snapshot := Checker{
		Files: []FileCheck{{Path: "/path/does/not/exist"}},
	}.Check(context.Background(), time.Unix(1_700_000_000, 0))

	assertFailedSnapshot(t, snapshot, 1, 1)
}

func TestCheckerRecordsTargetFailures(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("listener.Close() error = %v", err)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q) error = %v", address, err)
	}
	endpoint, err := EndpointFromAddress(host, port)
	if err != nil {
		t.Fatalf("EndpointFromAddress() error = %v", err)
	}

	snapshot := Checker{
		Targets:              []TargetCheck{{Endpoint: endpoint}},
		Timeout:              100 * time.Millisecond,
		MaxConcurrentTargets: 1,
	}.Check(context.Background(), time.Unix(1_700_000_000, 0))

	assertFailedSnapshot(t, snapshot, 1, 1)
	if len(snapshot.ChainResults) != 0 {
		t.Fatalf("len(snapshot.ChainResults) = %d, want 0", len(snapshot.ChainResults))
	}
	if len(snapshot.TargetResults) != 0 {
		t.Fatalf("len(snapshot.TargetResults) = %d, want 0", len(snapshot.TargetResults))
	}
}

func TestCheckerVerifiesFileWithConfiguredCA(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	caCert, caKey := testCA(t, "Test Root CA", now.Add(-time.Hour), now.Add(time.Hour))
	leafDER := testLeafCertificateDER(t, "file.example", caCert, caKey, now.Add(-time.Hour), now.Add(time.Hour))

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	writePEMCertificate(t, certPath, leafDER)
	caPath := filepath.Join(dir, "ca.pem")
	writePEMCertificate(t, caPath, caCert.Raw)

	snapshot := Checker{
		Files: []FileCheck{{Path: certPath, CAFile: caPath}},
	}.Check(context.Background(), now)

	assertSuccessfulSnapshot(t, snapshot)
	assertChainVerified(t, snapshot, true)
}

func TestCheckerVerifiesFileWithConfiguredCAAndIntermediate(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	rootCert, rootKey := testCA(t, "Test Root CA", now.Add(-time.Hour), now.Add(time.Hour))
	intermediateCert, intermediateKey := testIntermediateCA(t, "Test Intermediate CA", rootCert, rootKey, now.Add(-time.Hour), now.Add(time.Hour))
	leafDER := testLeafCertificateDER(t, "file.example", intermediateCert, intermediateKey, now.Add(-time.Hour), now.Add(time.Hour))

	dir := t.TempDir()
	certPath := filepath.Join(dir, "chain.pem")
	writePEMCertificates(t, certPath, leafDER, intermediateCert.Raw)
	caPath := filepath.Join(dir, "root-ca.pem")
	writePEMCertificate(t, caPath, rootCert.Raw)

	snapshot := Checker{
		Files: []FileCheck{{Path: certPath, CAFile: caPath}},
	}.Check(context.Background(), now)

	assertSuccessfulSnapshot(t, snapshot)
	assertChainVerified(t, snapshot, true)
}

func TestCheckerVerifiesTargetWithConfiguredCA(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	caCert, caKey := testCA(t, "Test Root CA", now.Add(-time.Hour), now.Add(time.Hour))
	serverCert := testTLSServerCertificate(t, caCert, caKey, net.ParseIP("127.0.0.1"), now.Add(-time.Hour), now.Add(time.Hour))

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	server.StartTLS()
	t.Cleanup(server.Close)

	endpoint := endpointFromServerURL(t, server.URL)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	writePEMCertificate(t, caPath, caCert.Raw)

	snapshot := Checker{
		Targets: []TargetCheck{{Endpoint: endpoint, CAFile: caPath}},
		Timeout: time.Second,
	}.Check(context.Background(), now)

	assertSuccessfulSnapshot(t, snapshot)
	assertChainVerified(t, snapshot, true)
	assertTargetVerified(t, snapshot, true)
}

func TestCheckerVerifiesTargetWithConfiguredCAAndIntermediate(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	rootCert, rootKey := testCA(t, "Test Root CA", now.Add(-time.Hour), now.Add(time.Hour))
	intermediateCert, intermediateKey := testIntermediateCA(t, "Test Intermediate CA", rootCert, rootKey, now.Add(-time.Hour), now.Add(time.Hour))
	serverCert := testTLSServerCertificateChain(t, intermediateCert, intermediateKey, net.ParseIP("127.0.0.1"), now.Add(-time.Hour), now.Add(time.Hour), intermediateCert.Raw)

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	server.StartTLS()
	t.Cleanup(server.Close)

	endpoint := endpointFromServerURL(t, server.URL)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "root-ca.pem")
	writePEMCertificate(t, caPath, rootCert.Raw)

	snapshot := Checker{
		Targets: []TargetCheck{{Endpoint: endpoint, CAFile: caPath}},
		Timeout: time.Second,
	}.Check(context.Background(), now)

	assertSuccessfulSnapshot(t, snapshot)
	assertTargetVerified(t, snapshot, true)
}

func TestCheckerVerifiesTargetWithServerNameOverride(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	caCert, caKey := testCA(t, "Test Root CA", now.Add(-time.Hour), now.Add(time.Hour))
	serverCert := testTLSServerDNSCertificate(t, caCert, caKey, "service.example", now.Add(-time.Hour), now.Add(time.Hour))

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}}
	server.StartTLS()
	t.Cleanup(server.Close)

	endpoint := endpointFromServerURL(t, server.URL)
	endpoint.ServerName = "service.example"

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	writePEMCertificate(t, caPath, caCert.Raw)

	snapshot := Checker{
		Targets: []TargetCheck{{Endpoint: endpoint, CAFile: caPath}},
		Timeout: time.Second,
	}.Check(context.Background(), now)

	assertSuccessfulSnapshot(t, snapshot)
	assertTargetVerified(t, snapshot, true)
}

func TestCheckerKeepsFileCheckSuccessfulWhenConfiguredCARejectsCertificate(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	caCert, caKey := testCA(t, "Test Root CA", now.Add(-time.Hour), now.Add(time.Hour))
	wrongCACert, _ := testCA(t, "Wrong Root CA", now.Add(-time.Hour), now.Add(time.Hour))
	leafDER := testLeafCertificateDER(t, "file.example", caCert, caKey, now.Add(-time.Hour), now.Add(time.Hour))

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	writePEMCertificate(t, certPath, leafDER)
	caPath := filepath.Join(dir, "wrong-ca.pem")
	writePEMCertificate(t, caPath, wrongCACert.Raw)

	snapshot := Checker{
		Files: []FileCheck{{Path: certPath, CAFile: caPath}},
	}.Check(context.Background(), now)

	assertSuccessfulSnapshot(t, snapshot)
	assertChainVerified(t, snapshot, false)
	if len(snapshot.Errors) != 0 {
		t.Fatalf("len(snapshot.Errors) = %d, want 0", len(snapshot.Errors))
	}
}

func TestCheckerChecksTargetsConcurrently(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	enteredHandshake := make(chan struct{}, 2)
	releaseHandshake := make(chan struct{})
	var closeRelease sync.Once
	defer func() {
		closeRelease.Do(func() {
			close(releaseHandshake)
		})
	}()

	targets := blockingTLSTargets(t, now, 2, enteredHandshake, releaseHandshake)

	done := make(chan Snapshot, 1)
	go func() {
		done <- Checker{
			Targets:              targets,
			Timeout:              2 * time.Second,
			MaxConcurrentTargets: 2,
		}.Check(context.Background(), now)
	}()

	for range targets {
		select {
		case <-enteredHandshake:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for target checks to run concurrently")
		}
	}
	closeRelease.Do(func() {
		close(releaseHandshake)
	})

	waitForCheckerSnapshot(t, done, len(targets))
}

func TestCheckerHonorsMaxConcurrentTargets(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_700_000_000, 0)
	enteredHandshake := make(chan struct{}, 2)
	releaseHandshake := make(chan struct{})
	var closeRelease sync.Once
	defer func() {
		closeRelease.Do(func() {
			close(releaseHandshake)
		})
	}()

	targets := blockingTLSTargets(t, now, 2, enteredHandshake, releaseHandshake)

	done := make(chan Snapshot, 1)
	go func() {
		done <- Checker{
			Targets:              targets,
			Timeout:              2 * time.Second,
			MaxConcurrentTargets: 1,
		}.Check(context.Background(), now)
	}()

	select {
	case <-enteredHandshake:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first target check")
	}

	select {
	case <-enteredHandshake:
		t.Fatal("second target check started before first was released")
	case <-time.After(100 * time.Millisecond):
	}

	closeRelease.Do(func() {
		close(releaseHandshake)
	})

	waitForCheckerSnapshot(t, done, len(targets))
}

func TestCheckerSkipsUndispatchedTargetsWhenContextIsCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	snapshot := Checker{
		Targets: []TargetCheck{
			{Endpoint: Endpoint{Raw: "first.example:443", Address: "first.example:443", ServerName: "first.example"}},
			{Endpoint: Endpoint{Raw: "second.example:443", Address: "second.example:443", ServerName: "second.example"}},
		},
		Timeout:              time.Second,
		MaxConcurrentTargets: 1,
	}.Check(ctx, time.Unix(1_700_000_000, 0))

	for _, check := range snapshot.Checks {
		if check.Source == "" || check.Target == "" {
			t.Fatalf("snapshot.Checks contains empty labels: %#v", snapshot.Checks)
		}
	}
}

func TestCheckerStopsFileChecksWhenContextIsCanceled(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	snapshot := Checker{
		Files: []FileCheck{
			{Path: "/path/does/not/exist"},
		},
	}.Check(ctx, time.Unix(1_700_000_000, 0))

	if snapshot.Success {
		t.Fatal("snapshot.Success = true, want false")
	}
	if len(snapshot.Checks) != 0 {
		t.Fatalf("len(snapshot.Checks) = %d, want 0", len(snapshot.Checks))
	}
	if len(snapshot.Errors) != 1 {
		t.Fatalf("len(snapshot.Errors) = %d, want 1", len(snapshot.Errors))
	}
	if snapshot.Errors[0].Source != "file" {
		t.Fatalf("snapshot.Errors[0].Source = %q, want file", snapshot.Errors[0].Source)
	}
	if snapshot.Errors[0].Kind != CheckErrorRead {
		t.Fatalf("snapshot.Errors[0].Kind = %q, want %q", snapshot.Errors[0].Kind, CheckErrorRead)
	}
}

func blockingTLSTargets(t *testing.T, now time.Time, count int, entered chan<- struct{}, release <-chan struct{}) []TargetCheck {
	t.Helper()

	caCert, caKey := testCA(t, "Test Root CA", now.Add(-time.Hour), now.Add(time.Hour))
	targets := make([]TargetCheck, 0, count)
	for range count {
		serverCert := testTLSServerCertificate(t, caCert, caKey, net.ParseIP("127.0.0.1"), now.Add(-time.Hour), now.Add(time.Hour))
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		server.TLS = &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				entered <- struct{}{}
				<-release
				return nil, nil
			},
		}
		server.StartTLS()
		t.Cleanup(server.Close)

		endpoint := endpointFromServerURL(t, server.URL)
		targets = append(targets, TargetCheck{Endpoint: endpoint})
	}
	return targets
}

func assertSuccessfulSnapshot(t *testing.T, snapshot Snapshot) {
	t.Helper()

	if !snapshot.Success {
		t.Fatalf("snapshot.Success = false, errors = %#v", snapshot.Errors)
	}
}

func assertFailedSnapshot(t *testing.T, snapshot Snapshot, wantChecks int, wantErrors int) {
	t.Helper()

	if snapshot.Success {
		t.Fatal("snapshot.Success = true, want false")
	}
	if len(snapshot.Checks) != wantChecks {
		t.Fatalf("len(snapshot.Checks) = %d, want %d", len(snapshot.Checks), wantChecks)
	}
	if wantChecks > 0 && snapshot.Checks[0].Success {
		t.Fatal("snapshot.Checks[0].Success = true, want false")
	}
	if len(snapshot.Errors) != wantErrors {
		t.Fatalf("len(snapshot.Errors) = %d, want %d", len(snapshot.Errors), wantErrors)
	}
}

func assertChainVerified(t *testing.T, snapshot Snapshot, want bool) {
	t.Helper()

	if len(snapshot.ChainResults) != 1 {
		t.Fatalf("len(snapshot.ChainResults) = %d, want 1", len(snapshot.ChainResults))
	}
	if snapshot.ChainResults[0].ChainVerified != want {
		t.Fatalf("ChainResults[0].ChainVerified = %t, want %t", snapshot.ChainResults[0].ChainVerified, want)
	}
}

func assertTargetVerified(t *testing.T, snapshot Snapshot, want bool) {
	t.Helper()

	if len(snapshot.TargetResults) != 1 {
		t.Fatalf("len(snapshot.TargetResults) = %d, want 1", len(snapshot.TargetResults))
	}
	if snapshot.TargetResults[0].ChainVerified != want {
		t.Fatalf("TargetResults[0].ChainVerified = %t, want %t", snapshot.TargetResults[0].ChainVerified, want)
	}
}

func endpointFromServerURL(t *testing.T, rawURL string) Endpoint {
	t.Helper()

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", rawURL, err)
	}
	host, port, err := net.SplitHostPort(parsedURL.Host)
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q) error = %v", parsedURL.Host, err)
	}
	endpoint, err := EndpointFromAddress(host, port)
	if err != nil {
		t.Fatalf("EndpointFromAddress() error = %v", err)
	}
	return endpoint
}

func waitForCheckerSnapshot(t *testing.T, done <-chan Snapshot, wantChecks int) Snapshot {
	t.Helper()

	select {
	case snapshot := <-done:
		assertSuccessfulSnapshot(t, snapshot)
		if len(snapshot.Checks) != wantChecks {
			t.Fatalf("len(snapshot.Checks) = %d, want %d", len(snapshot.Checks), wantChecks)
		}
		return snapshot
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for checker to finish")
		return Snapshot{}
	}
}

func testCA(t *testing.T, commonName string, notBefore time.Time, notAfter time.Time) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() CA error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() CA error = %v", err)
	}
	return cert, key
}

func testIntermediateCA(t *testing.T, commonName string, issuer *x509.Certificate, issuerKey *rsa.PrivateKey, notBefore time.Time, notAfter time.Time) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("CreateCertificate() intermediate CA error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() intermediate CA error = %v", err)
	}
	return cert, key
}

func testLeafCertificateDER(t *testing.T, commonName string, caCert *x509.Certificate, caKey *rsa.PrivateKey, notBefore time.Time, notAfter time.Time) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate() leaf error = %v", err)
	}
	return der
}

func testTLSServerCertificate(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, ip net.IP, notBefore time.Time, notAfter time.Time) tls.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: ip.String(),
		},
		IPAddresses:           []net.IP{ip},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	return testTLSServerCertificateFromTemplate(t, template, caCert, caKey)
}

func testTLSServerCertificateChain(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, ip net.IP, notBefore time.Time, notAfter time.Time, chain ...[]byte) tls.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: ip.String(),
		},
		IPAddresses:           []net.IP{ip},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	return testTLSServerCertificateFromTemplate(t, template, caCert, caKey, chain...)
}

func testTLSServerDNSCertificate(t *testing.T, caCert *x509.Certificate, caKey *rsa.PrivateKey, dnsName string, notBefore time.Time, notAfter time.Time) tls.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: dnsName,
		},
		DNSNames:              []string{dnsName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	return testTLSServerCertificateFromTemplate(t, template, caCert, caKey)
}

func testTLSServerCertificateFromTemplate(t *testing.T, template *x509.Certificate, caCert *x509.Certificate, caKey *rsa.PrivateKey, chain ...[]byte) tls.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CreateCertificate() TLS server error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() TLS server error = %v", err)
	}
	certificate := append([][]byte{der}, chain...)
	return tls.Certificate{
		Certificate: certificate,
		PrivateKey:  key,
		Leaf:        cert,
	}
}

func writePEMCertificate(t *testing.T, path string, der []byte) {
	t.Helper()

	writePEMCertificates(t, path, der)
}

func writePEMCertificates(t *testing.T, path string, certs ...[]byte) {
	t.Helper()

	var data []byte
	for _, der := range certs {
		data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
}
