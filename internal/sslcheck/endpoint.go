package sslcheck

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Endpoint struct {
	Raw        string
	Address    string
	ServerName string
}

func ParseEndpoint(raw string) (Endpoint, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return Endpoint{}, fmt.Errorf("endpoint is empty")
	}

	hostPort := value
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil {
			return Endpoint{}, fmt.Errorf("parse endpoint URL %q: %w", value, err)
		}
		switch parsed.Scheme {
		case "https", "tls", "ssl":
		default:
			return Endpoint{}, fmt.Errorf("unsupported endpoint scheme %q", parsed.Scheme)
		}
		if parsed.Host == "" {
			return Endpoint{}, fmt.Errorf("endpoint URL %q has no host", value)
		}
		if parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
			return Endpoint{}, fmt.Errorf("endpoint URL %q must not contain path, query, or fragment", value)
		}
		hostPort = parsed.Host
	}

	host, port, err := splitHostPort(hostPort, "443")
	if err != nil {
		return Endpoint{}, err
	}
	port, err = normalizePort(port)
	if err != nil {
		return Endpoint{}, err
	}
	serverName := strings.Trim(host, "[]")
	if serverName == "" {
		return Endpoint{}, fmt.Errorf("endpoint %q has no host", value)
	}

	return Endpoint{
		Raw:        value,
		Address:    net.JoinHostPort(serverName, port),
		ServerName: serverName,
	}, nil
}

func ParseEndpoints(values []string) ([]Endpoint, error) {
	endpoints := make([]Endpoint, 0, len(values))
	for _, value := range values {
		endpoint, err := ParseEndpoint(value)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	return endpoints, nil
}

func EndpointFromAddress(address string, port string) (Endpoint, error) {
	value := strings.TrimSpace(address)
	if value == "" {
		return Endpoint{}, fmt.Errorf("address is empty")
	}
	if strings.Contains(value, "://") {
		return Endpoint{}, fmt.Errorf("address must not include a URL scheme")
	}
	if strings.ContainsAny(value, "/?#") {
		return Endpoint{}, fmt.Errorf("address %q must not contain path, query, or fragment", value)
	}

	port, err := normalizePort(port)
	if err != nil {
		return Endpoint{}, err
	}

	host := strings.TrimPrefix(strings.TrimSuffix(value, "]"), "[")
	if host == "" {
		return Endpoint{}, fmt.Errorf("address is empty")
	}
	if _, _, err := net.SplitHostPort(value); err == nil {
		return Endpoint{}, fmt.Errorf("address %q must not include a port; use port=%s", value, port)
	}
	if strings.Contains(value, ":") && net.ParseIP(host) == nil {
		return Endpoint{}, fmt.Errorf("address %q looks like IPv6; use brackets or omit port from address", value)
	}

	endpointAddress := net.JoinHostPort(host, port)
	return Endpoint{
		Raw:        endpointAddress,
		Address:    endpointAddress,
		ServerName: host,
	}, nil
}

func normalizePort(value string) (string, error) {
	port := strings.TrimSpace(value)
	if port == "" {
		return "443", nil
	}

	number, err := strconv.Atoi(port)
	if err != nil {
		return "", fmt.Errorf("port %q is not numeric", port)
	}
	if number < 1 || number > 65535 {
		return "", fmt.Errorf("port %q is outside valid TCP port range 1-65535", port)
	}

	return strconv.Itoa(number), nil
}

func splitHostPort(value string, defaultPort string) (string, string, error) {
	host, port, err := net.SplitHostPort(value)
	if err == nil {
		if port == "" {
			return "", "", fmt.Errorf("endpoint %q has empty port", value)
		}
		return host, port, nil
	}

	if ip := net.ParseIP(value); ip != nil {
		return value, defaultPort, nil
	}
	if strings.HasPrefix(value, "[") {
		closing := strings.LastIndex(value, "]")
		if closing == len(value)-1 {
			return strings.Trim(value, "[]"), defaultPort, nil
		}
	}
	if strings.Count(value, ":") == 0 {
		return value, defaultPort, nil
	}
	if strings.Count(value, ":") > 1 {
		return "", "", fmt.Errorf("endpoint %q looks like IPv6; use brackets, for example [%s]:443", value, value)
	}

	return "", "", fmt.Errorf("parse endpoint %q: %w", value, err)
}
