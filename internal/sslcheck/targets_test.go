package sslcheck

import "testing"

func TestParseTargets(t *testing.T) {
	t.Parallel()

	files, targets, err := ParseTargets([]string{
		"address=google.com,port=443",
		"address=https://example.org:9443",
		"address=example.com,port=8443,ca=/etc/ssl/custom-ca.pem,server_name=service.example.com",
		"file=/path/to/file.pem,ca=/etc/ssl/file-ca.pem",
	})
	if err != nil {
		t.Fatalf("ParseTargets() error = %v", err)
	}

	if len(targets) != 3 {
		t.Fatalf("len(targets) = %d, want 3", len(targets))
	}
	if targets[0].Endpoint.Address != "google.com:443" {
		t.Fatalf("targets[0].Endpoint.Address = %q, want %q", targets[0].Endpoint.Address, "google.com:443")
	}
	if targets[0].CAFile != "" {
		t.Fatalf("targets[0].CAFile = %q, want empty", targets[0].CAFile)
	}
	if targets[1].Endpoint.Address != "example.org:9443" {
		t.Fatalf("targets[1].Endpoint.Address = %q, want %q", targets[1].Endpoint.Address, "example.org:9443")
	}
	if targets[1].Endpoint.ServerName != "example.org" {
		t.Fatalf("targets[1].Endpoint.ServerName = %q, want %q", targets[1].Endpoint.ServerName, "example.org")
	}
	if targets[2].Endpoint.Address != "example.com:8443" {
		t.Fatalf("targets[2].Endpoint.Address = %q, want %q", targets[2].Endpoint.Address, "example.com:8443")
	}
	if targets[2].CAFile != "/etc/ssl/custom-ca.pem" {
		t.Fatalf("targets[2].CAFile = %q, want %q", targets[2].CAFile, "/etc/ssl/custom-ca.pem")
	}
	if targets[2].Endpoint.ServerName != "service.example.com" {
		t.Fatalf("targets[2].Endpoint.ServerName = %q, want %q", targets[2].Endpoint.ServerName, "service.example.com")
	}

	if len(files) != 1 {
		t.Fatalf("len(files) = %d, want 1", len(files))
	}
	if files[0].Path != "/path/to/file.pem" {
		t.Fatalf("files[0].Path = %q, want %q", files[0].Path, "/path/to/file.pem")
	}
	if files[0].CAFile != "/etc/ssl/file-ca.pem" {
		t.Fatalf("files[0].CAFile = %q, want %q", files[0].CAFile, "/etc/ssl/file-ca.pem")
	}
}

func TestParseTargetsRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []string{
		"",
		"address=google.com,file=/path/to/file.pem",
		"address=google.com,port=0",
		"address=google.com,port=65536",
		"address=google.com,ca=",
		"address=google.com,server_name=",
		"address=google.com,server_name=example.com,sni=example.org",
		"file=/path/to/file.pem,port=443",
		"file=/path/to/file.pem,server_name=example.com",
		"file=",
		"target=google.com",
		"address=google.com,address=example.com",
		"address=https://google.com,port=443",
	}

	for _, raw := range tests {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			if _, _, err := ParseTargets([]string{raw}); err == nil {
				t.Fatal("ParseTargets() error = nil, want error")
			}
		})
	}
}
