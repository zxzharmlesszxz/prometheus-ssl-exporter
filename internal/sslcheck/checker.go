package sslcheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	DefaultTimeout              = 5 * time.Second
	DefaultMaxConcurrentTargets = 8
)

type Checker struct {
	Files                []FileCheck
	Targets              []TargetCheck
	Timeout              time.Duration
	MaxConcurrentTargets int
}

func NewChecker(files []FileCheck, targets []TargetCheck, timeout time.Duration, maxConcurrentTargets int) Checker {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if maxConcurrentTargets <= 0 {
		maxConcurrentTargets = DefaultMaxConcurrentTargets
	}
	return Checker{
		Files:                files,
		Targets:              targets,
		Timeout:              timeout,
		MaxConcurrentTargets: maxConcurrentTargets,
	}
}

func (c Checker) Snapshot(ctx context.Context, now time.Time) Snapshot {
	return c.Check(ctx, now)
}

func (c Checker) ConfiguredCertificateFiles() int {
	return len(c.Files)
}

func (c Checker) ConfiguredTargets() int {
	return len(c.Targets)
}

func (c Checker) Check(ctx context.Context, now time.Time) Snapshot {
	snapshot := Snapshot{
		AttemptTime: now,
		Success:     true,
	}

	for _, file := range c.Files {
		path := strings.TrimSpace(file.Path)
		if path == "" {
			continue
		}

		certs, err := ReadCertificateFile(path)
		if err != nil {
			snapshot.addFailure("file", path, err)
			continue
		}

		checkSucceeded := true
		if caFile := strings.TrimSpace(file.CAFile); caFile != "" {
			roots, err := readCertificatePool(caFile)
			if err != nil {
				checkSucceeded = false
				snapshot.Errors = append(snapshot.Errors, CheckError{Source: "file", Target: path, Err: err})
			} else {
				snapshot.ChainResults = append(snapshot.ChainResults, ChainResult{
					Source:        "file",
					Target:        path,
					ChainVerified: verifyCertificateChain(certs, "", roots, now) == nil,
				})
			}
		}

		if !checkSucceeded {
			snapshot.Success = false
		}
		snapshot.Checks = append(snapshot.Checks, CheckStatus{Source: "file", Target: path, Success: checkSucceeded})
		snapshot.Certificates = append(snapshot.Certificates, certificatesFromX509("file", path, certs, now)...)
	}

	for _, result := range c.checkTargets(ctx, now) {
		if !result.Check.Success {
			snapshot.Success = false
		}
		snapshot.Checks = append(snapshot.Checks, result.Check)
		snapshot.ChainResults = append(snapshot.ChainResults, result.ChainResults...)
		snapshot.TargetResults = append(snapshot.TargetResults, result.TargetResults...)
		snapshot.Certificates = append(snapshot.Certificates, result.Certificates...)
		snapshot.Errors = append(snapshot.Errors, result.Errors...)
	}

	snapshot.ConfiguredCertificateFiles = len(c.Files)
	snapshot.ConfiguredTargets = len(c.Targets)
	return snapshot
}

type targetCheckResult struct {
	Check         CheckStatus
	ChainResults  []ChainResult
	TargetResults []TargetResult
	Certificates  []Certificate
	Errors        []CheckError
}

func (c Checker) checkTargets(ctx context.Context, now time.Time) []targetCheckResult {
	if len(c.Targets) == 0 {
		return nil
	}

	maxConcurrent := c.MaxConcurrentTargets
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrentTargets
	}
	if maxConcurrent > len(c.Targets) {
		maxConcurrent = len(c.Targets)
	}

	results := make([]targetCheckResult, len(c.Targets))
	jobs := make(chan targetCheckJob)
	var wg sync.WaitGroup
	for i := 0; i < maxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				results[job.Index] = c.checkTarget(ctx, job.Target, now)
			}
		}()
	}

sendLoop:
	for i, target := range c.Targets {
		select {
		case jobs <- targetCheckJob{Index: i, Target: target}:
		case <-ctx.Done():
			break sendLoop
		}
	}
	close(jobs)
	wg.Wait()

	return results
}

type targetCheckJob struct {
	Index  int
	Target TargetCheck
}

func (c Checker) checkTarget(ctx context.Context, target TargetCheck, now time.Time) targetCheckResult {
	certs, err := fetchEndpointCertificates(ctx, target.Endpoint, c.Timeout)
	if err != nil {
		return targetFailure(target.Endpoint.Raw, err)
	}

	checkSucceeded := true
	var errors []CheckError
	roots, err := targetRoots(target.CAFile)
	if err != nil {
		checkSucceeded = false
		errors = append(errors, CheckError{Source: "target", Target: target.Endpoint.Raw, Err: err})
	}

	verified := false
	if err == nil {
		verified = verifyCertificateChain(certs, target.Endpoint.ServerName, roots, now) == nil
	}

	return targetCheckResult{
		Check:         CheckStatus{Source: "target", Target: target.Endpoint.Raw, Success: checkSucceeded},
		ChainResults:  []ChainResult{{Source: "target", Target: target.Endpoint.Raw, ChainVerified: verified}},
		TargetResults: []TargetResult{{Target: target.Endpoint.Raw, ChainVerified: verified}},
		Certificates:  certificatesFromX509("target", target.Endpoint.Raw, certs, now),
		Errors:        errors,
	}
}

func targetFailure(target string, err error) targetCheckResult {
	return targetCheckResult{
		Check:  CheckStatus{Source: "target", Target: target, Success: false},
		Errors: []CheckError{{Source: "target", Target: target, Err: err}},
	}
}

func (s *Snapshot) addFailure(source string, target string, err error) {
	s.Success = false
	s.Checks = append(s.Checks, CheckStatus{Source: source, Target: target, Success: false})
	s.Errors = append(s.Errors, CheckError{Source: source, Target: target, Err: err})
}

func certificatesFromX509(source string, target string, certs []*x509.Certificate, now time.Time) []Certificate {
	result := make([]Certificate, 0, len(certs))
	for i, cert := range certs {
		result = append(result, Certificate{
			Source:              source,
			Target:              target,
			ChainIndex:          i,
			SubjectCommonName:   cert.Subject.CommonName,
			IssuerCommonName:    cert.Issuer.CommonName,
			SerialNumber:        serialNumber(cert.SerialNumber),
			NotBefore:           cert.NotBefore,
			NotAfter:            cert.NotAfter,
			TemporarilyValidNow: !now.Before(cert.NotBefore) && now.Before(cert.NotAfter),
		})
	}
	return result
}

func fetchEndpointCertificates(ctx context.Context, endpoint Endpoint, timeout time.Duration) ([]*x509.Certificate, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			ServerName:         endpoint.ServerName,
			InsecureSkipVerify: true,
		},
	}

	targetCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialer.DialContext(targetCtx, "tcp", endpoint.Address)
	if err != nil {
		return nil, fmt.Errorf("connect TLS endpoint %q: %w", endpoint.Raw, err)
	}
	defer func() {
		_ = conn.Close()
	}()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("connect TLS endpoint %q: connection is not TLS", endpoint.Raw)
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("connect TLS endpoint %q: peer sent no certificates", endpoint.Raw)
	}

	return state.PeerCertificates, nil
}

func verifyCertificateChain(certs []*x509.Certificate, serverName string, roots *x509.CertPool, now time.Time) error {
	if len(certs) == 0 {
		return fmt.Errorf("certificate chain is empty")
	}

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	_, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		DNSName:       serverName,
		Intermediates: intermediates,
		CurrentTime:   now,
	})
	return err
}

func targetRoots(caFile string) (*x509.CertPool, error) {
	caFile = strings.TrimSpace(caFile)
	if caFile == "" {
		return nil, nil
	}
	return readCertificatePool(caFile)
}

func readCertificatePool(path string) (*x509.CertPool, error) {
	certs, err := ReadCertificateFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA file %q: %w", path, err)
	}

	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool, nil
}

func serialNumber(value *big.Int) string {
	if value == nil {
		return ""
	}
	return strings.ToUpper(value.Text(16))
}
