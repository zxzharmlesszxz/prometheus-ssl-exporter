package sslcheck

import "testing"

func TestParseEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		raw        string
		address    string
		serverName string
	}{
		{
			name:       "https URL with port",
			raw:        "https://google.com:443",
			address:    "google.com:443",
			serverName: "google.com",
		},
		{
			name:       "host and port",
			raw:        "example.org:8443",
			address:    "example.org:8443",
			serverName: "example.org",
		},
		{
			name:       "host without port defaults to 443",
			raw:        "example.org",
			address:    "example.org:443",
			serverName: "example.org",
		},
		{
			name:       "IPv6 with port",
			raw:        "[::1]:9443",
			address:    "[::1]:9443",
			serverName: "::1",
		},
		{
			name:       "IPv6 without port defaults to 443",
			raw:        "::1",
			address:    "[::1]:443",
			serverName: "::1",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseEndpoint(tc.raw)
			if err != nil {
				t.Fatalf("ParseEndpoint() error = %v", err)
			}
			if got.Raw != tc.raw {
				t.Fatalf("Raw = %q, want %q", got.Raw, tc.raw)
			}
			if got.Address != tc.address {
				t.Fatalf("Address = %q, want %q", got.Address, tc.address)
			}
			if got.ServerName != tc.serverName {
				t.Fatalf("ServerName = %q, want %q", got.ServerName, tc.serverName)
			}
		})
	}
}

func TestParseEndpointRejectsUnsupportedValues(t *testing.T) {
	t.Parallel()

	tests := []string{
		"",
		"http://example.org:80",
		"https://example.org:443/path",
	}

	for _, raw := range tests {
		raw := raw
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			if _, err := ParseEndpoint(raw); err == nil {
				t.Fatal("ParseEndpoint() error = nil, want error")
			}
		})
	}
}

func TestParseEndpoints(t *testing.T) {
	t.Parallel()

	endpoints, err := ParseEndpoints([]string{"example.org", "https://google.com:443"})
	if err != nil {
		t.Fatalf("ParseEndpoints() error = %v", err)
	}
	if len(endpoints) != 2 {
		t.Fatalf("len(endpoints) = %d, want 2", len(endpoints))
	}
	if endpoints[0].Address != "example.org:443" {
		t.Fatalf("endpoints[0].Address = %q, want %q", endpoints[0].Address, "example.org:443")
	}
	if endpoints[1].Address != "google.com:443" {
		t.Fatalf("endpoints[1].Address = %q, want %q", endpoints[1].Address, "google.com:443")
	}
}

func TestParseEndpointsReturnsFirstError(t *testing.T) {
	t.Parallel()

	if _, err := ParseEndpoints([]string{"example.org", "http://example.org"}); err == nil {
		t.Fatal("ParseEndpoints() error = nil, want error")
	}
}

func TestEndpointFromAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		address    string
		port       string
		wantRaw    string
		wantAddr   string
		serverName string
	}{
		{
			name:       "host default port",
			address:    " example.org ",
			wantRaw:    "example.org:443",
			wantAddr:   "example.org:443",
			serverName: "example.org",
		},
		{
			name:       "IPv4 custom port",
			address:    "127.0.0.1",
			port:       " 8443 ",
			wantRaw:    "127.0.0.1:8443",
			wantAddr:   "127.0.0.1:8443",
			serverName: "127.0.0.1",
		},
		{
			name:       "bracketed IPv6",
			address:    "[::1]",
			port:       "9443",
			wantRaw:    "[::1]:9443",
			wantAddr:   "[::1]:9443",
			serverName: "::1",
		},
		{
			name:       "bare IPv6",
			address:    "::1",
			port:       "9443",
			wantRaw:    "[::1]:9443",
			wantAddr:   "[::1]:9443",
			serverName: "::1",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := EndpointFromAddress(tc.address, tc.port)
			if err != nil {
				t.Fatalf("EndpointFromAddress() error = %v", err)
			}
			if got.Raw != tc.wantRaw {
				t.Fatalf("Raw = %q, want %q", got.Raw, tc.wantRaw)
			}
			if got.Address != tc.wantAddr {
				t.Fatalf("Address = %q, want %q", got.Address, tc.wantAddr)
			}
			if got.ServerName != tc.serverName {
				t.Fatalf("ServerName = %q, want %q", got.ServerName, tc.serverName)
			}
		})
	}
}

func TestEndpointFromAddressRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		address string
		port    string
	}{
		{name: "empty address", address: " "},
		{name: "url scheme", address: "https://example.org"},
		{name: "path", address: "example.org/path"},
		{name: "port in address", address: "example.org:443"},
		{name: "non numeric port", address: "example.org", port: "https"},
		{name: "out of range port", address: "example.org", port: "70000"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := EndpointFromAddress(tc.address, tc.port); err == nil {
				t.Fatal("EndpointFromAddress() error = nil, want error")
			}
		})
	}
}
