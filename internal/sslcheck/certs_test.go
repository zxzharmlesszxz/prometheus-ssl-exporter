package sslcheck

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadCertificateFileReadsPEMAndDER(t *testing.T) {
	t.Parallel()

	der := testCertificateDER(t, "file.example", time.Unix(1_700_000_000, 0), time.Unix(1_700_086_400, 0))
	dir := t.TempDir()

	pemPath := filepath.Join(dir, "cert.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(pemPath, pemBytes, 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", pemPath, err)
	}

	derPath := filepath.Join(dir, "cert.der")
	if err := os.WriteFile(derPath, der, 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", derPath, err)
	}

	for _, path := range []string{pemPath, derPath} {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()

			certs, err := ReadCertificateFile(path)
			if err != nil {
				t.Fatalf("ReadCertificateFile() error = %v", err)
			}
			if len(certs) != 1 {
				t.Fatalf("len(certs) = %d, want 1", len(certs))
			}
			if certs[0].Subject.CommonName != "file.example" {
				t.Fatalf("Subject.CommonName = %q, want %q", certs[0].Subject.CommonName, "file.example")
			}
		})
	}
}

func testCertificateDER(t *testing.T, commonName string, notBefore time.Time, notAfter time.Time) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	return der
}
