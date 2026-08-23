package sslcheck

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type CertificateFileError struct {
	Kind CheckErrorKind
	Path string
	Err  error
}

func (e *CertificateFileError) Error() string {
	return e.Err.Error()
}

func (e *CertificateFileError) Unwrap() error {
	return e.Err
}

func ReadCertificateFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &CertificateFileError{
			Kind: CheckErrorRead,
			Path: path,
			Err:  fmt.Errorf("read certificate file %q: %w", path, err),
		}
	}

	var certs []*x509.Certificate
	sawPEM := false
	remaining := data
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		sawPEM = true
		remaining = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, &CertificateFileError{
				Kind: CheckErrorParse,
				Path: path,
				Err:  fmt.Errorf("parse PEM certificate in %q: %w", path, err),
			}
		}
		certs = append(certs, cert)
	}
	if len(certs) > 0 {
		return certs, nil
	}
	if sawPEM {
		return nil, &CertificateFileError{
			Kind: CheckErrorParse,
			Path: path,
			Err:  fmt.Errorf("parse PEM certificate in %q: no CERTIFICATE blocks found", path),
		}
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, &CertificateFileError{
			Kind: CheckErrorParse,
			Path: path,
			Err:  fmt.Errorf("parse DER certificate in %q: %w", path, err),
		}
	}
	return []*x509.Certificate{cert}, nil
}
