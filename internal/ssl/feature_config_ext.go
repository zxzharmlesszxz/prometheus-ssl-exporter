package ssl

import (
	"fmt"
	"time"

	"github.com/alecthomas/kingpin/v2"
	framework "github.com/zxzharmlesszxz/prometheus-exporter-framework/exporter"
	"github.com/zxzharmlesszxz/prometheus-exporter-framework/exporter/featurekit"

	"github.com/zxzharmlesszxz/prometheus-ssl-exporter/internal/sslcheck"
)

type Config struct {
	ConfigFile             string
	Targets                []string
	Timeout                time.Duration
	MaxConcurrentTargets   int
	MaxStaleTargetFailures int
	fileChecks             []sslcheck.FileCheck
	targetChecks           []sslcheck.TargetCheck

	timeoutConfigured                bool
	maxConcurrentConfigured          bool
	maxStaleTargetFailuresConfigured bool
}

const (
	DefaultRefreshInterval        = time.Hour
	DefaultTimeout                = sslcheck.DefaultTimeout
	DefaultMaxConcurrentTargets   = sslcheck.DefaultMaxConcurrentTargets
	DefaultMaxStaleTargetFailures = 3
)

var DefaultFeatureConfigFileName = "prometheus-ssl-exporter.yml"

type featureConfigFile struct {
	Targets                []map[string]any `yaml:"targets"`
	Timeout                string           `yaml:"timeout"`
	MaxConcurrentTargets   int              `yaml:"max_concurrent_targets"`
	MaxStaleTargetFailures *int             `yaml:"max_stale_target_failures"`
}

var featureConfigFlagSpecs = []featurekit.FeatureConfigFlagSpec[Config]{
	{
		Name: "target",
		Help: "SSL certificate target, for example address=google.com,port=443,server_name=google.com or file=/etc/ssl/certs/example.pem,ca=/etc/ssl/custom-ca.pem. Can be repeated",
		Bind: func(flag *kingpin.FlagClause, config *Config) {
			flag.StringsVar(&config.Targets)
		},
	},
	{
		Name:    "timeout",
		Help:    "Timeout for each remote TLS check",
		Default: DefaultTimeout.String(),
		Bind: func(flag *kingpin.FlagClause, config *Config) {
			flag.DurationVar(&config.Timeout)
			flag.IsSetByUser(&config.timeoutConfigured)
		},
	},
	{
		Name:    "max-concurrent-targets",
		Help:    "Maximum number of remote TLS targets checked at the same time",
		Default: fmt.Sprint(DefaultMaxConcurrentTargets),
		Bind: func(flag *kingpin.FlagClause, config *Config) {
			flag.IntVar(&config.MaxConcurrentTargets)
			flag.IsSetByUser(&config.maxConcurrentConfigured)
		},
	},
	{
		Name:    "max-stale-target-failures",
		Help:    "Number of consecutive remote TLS read failures tolerated by keeping the last known good certificate data. Set to 0 to disable",
		Default: fmt.Sprint(DefaultMaxStaleTargetFailures),
		Bind: func(flag *kingpin.FlagClause, config *Config) {
			flag.IntVar(&config.MaxStaleTargetFailures)
			flag.IsSetByUser(&config.maxStaleTargetFailuresConfigured)
		},
	},
}

func NewDefaultConfig() Config {
	return Config{
		Timeout:                DefaultTimeout,
		MaxConcurrentTargets:   DefaultMaxConcurrentTargets,
		MaxStaleTargetFailures: DefaultMaxStaleTargetFailures,
	}
}

func FeatureConfigFile(config *Config) *string {
	return &config.ConfigFile
}

func ValidateFeatureConfig(config Config) error {
	if _, _, err := sslcheck.ParseTargets(config.Targets); err != nil {
		return fmt.Errorf("parse SSL target: %w", err)
	}
	return nil
}

func FeatureRuntimeConfigEntries(_ featurekit.RuntimeConfigContext[Config], config Config) []any {
	return []any{
		"targets", config.Targets,
		"timeout", framework.NormalizeDuration(config.Timeout, DefaultTimeout),
		"max_concurrent_targets", normalizePositiveInt(config.MaxConcurrentTargets, DefaultMaxConcurrentTargets),
		"max_stale_target_failures", normalizeNonNegativeInt(config.MaxStaleTargetFailures, DefaultMaxStaleTargetFailures),
	}
}

func normalizePositiveInt(value int, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func normalizeNonNegativeInt(value int, fallback int) int {
	if value < 0 {
		return fallback
	}
	return value
}

func ResolveFeatureConfig(featureName string, config Config) (Config, string, bool, error) {
	var fileConfig featureConfigFile
	cfgFile, loaded, err := featurekit.LoadFeatureConfigFile(featureName, config.ConfigFile, &fileConfig)
	if err != nil {
		return config, cfgFile, false, err
	}

	if loaded {
		if fileConfig.Timeout != "" && !config.timeoutConfigured {
			t, err := time.ParseDuration(fileConfig.Timeout)
			if err != nil {
				return config, cfgFile, true, fmt.Errorf("parse timeout from %q: %w", cfgFile, err)
			}
			config.Timeout = t
		}
		if fileConfig.MaxConcurrentTargets > 0 && !config.maxConcurrentConfigured {
			config.MaxConcurrentTargets = fileConfig.MaxConcurrentTargets
		}
		if fileConfig.MaxStaleTargetFailures != nil && !config.maxStaleTargetFailuresConfigured {
			config.MaxStaleTargetFailures = *fileConfig.MaxStaleTargetFailures
		}

		files, targets, err := sslcheck.ParseConfigTargets(cfgFile, fileConfig.Targets)
		if err != nil {
			return config, cfgFile, true, err
		}
		config.fileChecks = append(files, config.fileChecks...)
		config.targetChecks = append(targets, config.targetChecks...)
	}

	if config.Timeout <= 0 {
		config.Timeout = DefaultTimeout
	}
	if config.MaxConcurrentTargets <= 0 {
		config.MaxConcurrentTargets = DefaultMaxConcurrentTargets
	}
	if config.MaxStaleTargetFailures < 0 {
		config.MaxStaleTargetFailures = DefaultMaxStaleTargetFailures
	}
	return config, cfgFile, loaded, nil
}
