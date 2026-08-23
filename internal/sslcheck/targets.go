package sslcheck

import (
	"fmt"
	"slices"
	"strings"
)

type FileCheck struct {
	Path   string
	CAFile string
}

type TargetCheck struct {
	Endpoint Endpoint
	CAFile   string
}

func ParseTargets(values []string) ([]FileCheck, []TargetCheck, error) {
	files := make([]FileCheck, 0, len(values))
	targets := make([]TargetCheck, 0, len(values))

	for _, value := range values {
		target, err := parseTarget(value)
		if err != nil {
			return nil, nil, err
		}
		if target.file != nil {
			files = append(files, *target.file)
			continue
		}
		targets = append(targets, *target.target)
	}

	return files, targets, nil
}

type parsedTarget struct {
	file   *FileCheck
	target *TargetCheck
}

func parseTarget(raw string) (parsedTarget, error) {
	values, err := parseTargetValues(raw)
	if err != nil {
		return parsedTarget{}, err
	}
	return parseTargetFromValues(raw, values)
}

func parseTargetFromValues(raw string, values map[string]string) (parsedTarget, error) {
	_, hasAddress := values["address"]
	_, hasFile := values["file"]
	if hasAddress == hasFile {
		return parsedTarget{}, fmt.Errorf("ssl target %q must contain exactly one of address or file", raw)
	}

	caFile := strings.TrimSpace(values["ca"])
	if _, ok := values["ca"]; ok && caFile == "" {
		return parsedTarget{}, fmt.Errorf("ssl target %q has empty ca", raw)
	}
	serverName, hasServerName, err := serverNameValue(values)
	if err != nil {
		return parsedTarget{}, fmt.Errorf("ssl target %q: %w", raw, err)
	}

	if hasFile {
		if _, ok := values["port"]; ok {
			return parsedTarget{}, fmt.Errorf("ssl target %q uses port with file source", raw)
		}
		if hasServerName {
			return parsedTarget{}, fmt.Errorf("ssl target %q uses server_name with file source", raw)
		}

		path := strings.TrimSpace(values["file"])
		if path == "" {
			return parsedTarget{}, fmt.Errorf("ssl target %q has empty file", raw)
		}

		return parsedTarget{
			file: &FileCheck{
				Path:   path,
				CAFile: caFile,
			},
		}, nil
	}

	address := strings.TrimSpace(values["address"])
	if address == "" {
		return parsedTarget{}, fmt.Errorf("ssl target %q has empty address", raw)
	}

	var endpoint Endpoint
	if strings.TrimSpace(values["port"]) == "" {
		endpoint, err = ParseEndpoint(address)
	} else {
		endpoint, err = EndpointFromAddress(address, values["port"])
	}
	if err != nil {
		return parsedTarget{}, fmt.Errorf("ssl target %q: %w", raw, err)
	}
	if hasServerName {
		endpoint.ServerName = serverName
	}

	return parsedTarget{
		target: &TargetCheck{
			Endpoint: endpoint,
			CAFile:   caFile,
		},
	}, nil
}

func parseTargetValues(raw string) (map[string]string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil, fmt.Errorf("ssl target is empty")
	}

	result := make(map[string]string)
	for segment := range strings.SplitSeq(value, ",") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return nil, fmt.Errorf("ssl target %q contains an empty segment", raw)
		}

		key, itemValue, ok := strings.Cut(segment, "=")
		if !ok {
			return nil, fmt.Errorf("ssl target segment %q must use key=value", segment)
		}

		key = strings.ToLower(strings.TrimSpace(key))
		itemValue = strings.TrimSpace(itemValue)
		if key == "" {
			return nil, fmt.Errorf("ssl target segment %q has empty key", segment)
		}
		if !isSupportedTargetKey(key) {
			return nil, fmt.Errorf("ssl target segment %q uses unsupported key %q", segment, key)
		}
		if _, exists := result[key]; exists {
			return nil, fmt.Errorf("ssl target %q contains duplicate key %q", raw, key)
		}

		result[key] = itemValue
	}

	return result, nil
}

func isSupportedTargetKey(key string) bool {
	return slices.Contains([]string{"address", "port", "file", "ca", "server_name", "sni"}, key)
}

func serverNameValue(values map[string]string) (string, bool, error) {
	serverName, hasServerName := values["server_name"]
	sni, hasSNI := values["sni"]
	if hasServerName && hasSNI {
		return "", false, fmt.Errorf("server_name and sni are aliases; use only one")
	}
	if hasSNI {
		serverName = sni
		hasServerName = true
	}
	if !hasServerName {
		return "", false, nil
	}
	serverName = strings.TrimSpace(serverName)
	if serverName == "" {
		return "", false, fmt.Errorf("empty server_name")
	}
	return serverName, true, nil
}
