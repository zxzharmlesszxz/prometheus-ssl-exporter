package sslcheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseConfigFile(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, `
targets:
  - address: 127.0.0.1
    port: 8443
    server_name: service.example
    ca: /etc/ssl/custom-ca.pem
  - file: /etc/ssl/certs/example.pem
    ca: /etc/ssl/file-ca.pem
`)

	files, targets, err := ParseConfigFile(path)
	if err != nil {
		t.Fatalf("ParseConfigFile() error = %v", err)
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].Endpoint.Address != "127.0.0.1:8443" {
		t.Fatalf("targets[0].Endpoint.Address = %q, want %q", targets[0].Endpoint.Address, "127.0.0.1:8443")
	}
	if targets[0].Endpoint.ServerName != "service.example" {
		t.Fatalf("targets[0].Endpoint.ServerName = %q, want %q", targets[0].Endpoint.ServerName, "service.example")
	}
	if targets[0].CAFile != "/etc/ssl/custom-ca.pem" {
		t.Fatalf("targets[0].CAFile = %q, want %q", targets[0].CAFile, "/etc/ssl/custom-ca.pem")
	}

	if len(files) != 1 {
		t.Fatalf("len(files) = %d, want 1", len(files))
	}
	if files[0].Path != "/etc/ssl/certs/example.pem" {
		t.Fatalf("files[0].Path = %q, want %q", files[0].Path, "/etc/ssl/certs/example.pem")
	}
	if files[0].CAFile != "/etc/ssl/file-ca.pem" {
		t.Fatalf("files[0].CAFile = %q, want %q", files[0].CAFile, "/etc/ssl/file-ca.pem")
	}
}

func TestParseConfigFileAcceptsNumericPort(t *testing.T) {
	t.Parallel()

	files, targets, err := ParseConfigFile(writeConfigFile(t, `
targets:
  - address: 127.0.0.1
    port: 8443
`))
	if err != nil {
		t.Fatalf("ParseConfigFile() error = %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("len(files) = %d, want 0", len(files))
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].Endpoint.Address != "127.0.0.1:8443" {
		t.Fatalf("targets[0].Endpoint.Address = %q, want %q", targets[0].Endpoint.Address, "127.0.0.1:8443")
	}
}

func TestConfigPortString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value any
		want  string
	}{
		{name: "string", value: "8443", want: "8443"},
		{name: "integer", value: 8443, want: "8443"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := configPortString(tc.value)
			if err != nil {
				t.Fatalf("configPortString() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("configPortString() = %q, want %q", got, tc.want)
			}
		})
	}

	if _, err := configPortString(true); err == nil {
		t.Fatal("configPortString(bool) error = nil, want error")
	}
}

func TestParseConfigFileAcceptsEndpointInAddress(t *testing.T) {
	t.Parallel()

	files, targets, err := ParseConfigFile(writeConfigFile(t, `
targets:
  - address: https://example.org:9443
`))
	if err != nil {
		t.Fatalf("ParseConfigFile() error = %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("len(files) = %d, want 0", len(files))
	}
	if len(targets) != 1 {
		t.Fatalf("len(targets) = %d, want 1", len(targets))
	}
	if targets[0].Endpoint.Raw != "https://example.org:9443" {
		t.Fatalf("targets[0].Endpoint.Raw = %q, want %q", targets[0].Endpoint.Raw, "https://example.org:9443")
	}
	if targets[0].Endpoint.Address != "example.org:9443" {
		t.Fatalf("targets[0].Endpoint.Address = %q, want %q", targets[0].Endpoint.Address, "example.org:9443")
	}
	if targets[0].Endpoint.ServerName != "example.org" {
		t.Fatalf("targets[0].Endpoint.ServerName = %q, want %q", targets[0].Endpoint.ServerName, "example.org")
	}
}

func TestParseConfigFileRejectsInvalidTargets(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"unsupported key": `
targets:
  - address: example.com
    unsupported: value
`,
		"empty server name": `
targets:
  - address: example.com
    server_name: ""
`,
		"file server name": `
targets:
  - file: /tmp/cert.pem
    server_name: example.com
`,
		"non-string address": `
targets:
  - address: 127
    port: 443
`,
		"non-string file": `
targets:
  - file: true
`,
		"float port": `
targets:
  - address: example.com
    port: 443.5
`,
		"null ca": `
targets:
  - address: example.com
    ca:
`,
	}

	for name, content := range tests {
		name, content := name, content
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, _, err := ParseConfigFile(writeConfigFile(t, content)); err == nil {
				t.Fatal("ParseConfigFile() error = nil, want error")
			}
		})
	}
}

func writeConfigFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ssl-targets.yml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", path, err)
	}
	return path
}
