package sslcheck

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v2"
)

type targetConfigFile struct {
	Targets []map[string]any `yaml:"targets"`
}

func ParseConfigFile(path string) ([]FileCheck, []TargetCheck, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read SSL config file %q: %w", path, err)
	}

	var config targetConfigFile
	if err := yaml.UnmarshalStrict(data, &config); err != nil {
		return nil, nil, fmt.Errorf("parse SSL config file %q: %w", path, err)
	}

	return ParseConfigTargets(path, config.Targets)
}

func ParseConfigTargets(source string, configTargets []map[string]any) ([]FileCheck, []TargetCheck, error) {
	files := make([]FileCheck, 0, len(configTargets))
	targets := make([]TargetCheck, 0, len(configTargets))
	for i, target := range configTargets {
		raw := fmt.Sprintf("%s target %d", source, i+1)
		values, err := configTargetValues(raw, target)
		if err != nil {
			return nil, nil, err
		}
		parsed, err := parseTargetFromValues(raw, values)
		if err != nil {
			return nil, nil, err
		}
		if parsed.file != nil {
			files = append(files, *parsed.file)
			continue
		}
		targets = append(targets, *parsed.target)
	}

	return files, targets, nil
}

func configTargetValues(raw string, target map[string]any) (map[string]string, error) {
	values := make(map[string]string, len(target))
	for key, value := range target {
		key = normalizeConfigKey(key)
		if !isSupportedTargetKey(key) {
			return nil, fmt.Errorf("ssl target %q uses unsupported key %q", raw, key)
		}
		stringValue, err := configTargetString(key, value)
		if err != nil {
			return nil, fmt.Errorf("ssl target %q uses invalid %s: %w", raw, key, err)
		}
		values[key] = stringValue
	}
	return values, nil
}

func normalizeConfigKey(key string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(key)), "-", "_")
}

func configTargetString(key string, value any) (string, error) {
	if value == nil {
		return "", nil
	}

	switch key {
	case "port":
		return configPortString(value)
	case "address", "file", "ca", "server_name", "sni":
		typed, ok := value.(string)
		if !ok {
			return "", fmt.Errorf("must be a string")
		}
		return typed, nil
	default:
		return "", fmt.Errorf("unsupported key %q", key)
	}
}

func configPortString(value any) (string, error) {
	switch typed := value.(type) {
	case string:
		return typed, nil
	case int:
		return strconv.Itoa(typed), nil
	default:
		return "", fmt.Errorf("must be a string or integer")
	}
}
