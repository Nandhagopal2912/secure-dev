package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// ScanJob is everything a scan Job is allowed to know.
//
// A separate type from Config, and that is the point rather than tidiness:
// there is no field here for a database URL, a Redis URL, or an API token, so
// the claim ADR 039 makes about this process is structural. A future change
// that hands the scan job a credential has to add a field to this struct,
// which is a thing a reviewer sees.
//
// It was written after the alternative failed in a cluster. cmd/scanjob first
// called Load(), which requires SECUREOPS_DATABASE_URL and SECUREOPS_REDIS_URL
// -- so every scan pod died with "is required" for two credentials it must
// never hold. The validation was right and the caller was wrong.
type ScanJob struct {
	Env       Environment
	LogLevel  slog.Level
	LogFormat string

	WorkspaceRoot  string
	ScannerTimeout time.Duration
	MaxOutputBytes int64

	Fetch    FetchLimits
	Scanners ScannerSettings

	// DataInImage says the scanners' data is already here (ADR 040), so this
	// process must not try to fetch it. Set by the controller, which knows
	// which image it started.
	DataInImage bool
}

// FetchLimits bound pulling untrusted content onto this machine (§14).
type FetchLimits struct {
	Timeout  time.Duration
	MaxBytes int64
	MaxFiles int
}

// ScannerSettings is what the adapters need: where their data lives, and how
// they are invoked. Shared with the controller, which registers the same
// adapters to parse what this process produces.
type ScannerSettings struct {
	GrypeDBCacheDir   string
	SemgrepDir        string
	TrivyDir          string
	TrivyMaxImageSize string
	ZAPHomeDir        string
	ZAPCommand        string
	ZAPJarPath        string
	ZAPMaxHeap        string
	// AllowPrivateTargets is the deployment's address policy, for an adapter that
	// makes its own connections and so enforces it itself (ADR 041). LoadScanJob
	// leaves it false on purpose: a scan pod's network policy excludes private
	// ranges whatever this says, so refusing there fails fast and says why.
	AllowPrivateTargets bool
}

// Scanners exposes the adapter settings held by a full configuration, so both
// binaries register adapters from one description.
func (c Config) Scanners() ScannerSettings {
	return ScannerSettings{
		GrypeDBCacheDir:     c.GrypeDBCacheDir,
		SemgrepDir:          c.SemgrepDir,
		TrivyDir:            c.TrivyDir,
		TrivyMaxImageSize:   c.TrivyMaxImageSize,
		ZAPHomeDir:          c.ZAPHomeDir,
		ZAPCommand:          c.ZAPCommand,
		ZAPJarPath:          c.ZAPJarPath,
		ZAPMaxHeap:          c.ZAPMaxHeap,
		AllowPrivateTargets: c.AllowPrivateTargets,
	}
}

// LoadScanJob reads the environment a scan Job is given.
//
// Deliberately does not call Load(): that requires the data credentials this
// process is designed not to have, and reusing it would mean either weakening
// that requirement for everyone or handing this pod a credential to satisfy it.
func LoadScanJob() (ScanJob, error) {
	cfg := ScanJob{
		Env:           Environment(getenv("SECUREOPS_ENV", string(EnvDevelopment))),
		LogFormat:     getenv("SECUREOPS_LOG_FORMAT", "json"),
		WorkspaceRoot: strings.TrimSpace(getenv("SECUREOPS_WORKSPACE_ROOT", "/tmp/secureops-workspaces")),
		// Set by the controller, which knows which image it started. Without
		// it this process spends the scan trying to fetch data already beside
		// it, from a pod with no egress (ADR 040).
		DataInImage: strings.EqualFold(
			strings.TrimSpace(getenv("SECUREOPS_SCANNER_DATA_IN_IMAGE", "false")), "true"),
		Scanners: ScannerSettings{
			GrypeDBCacheDir:   strings.TrimSpace(getenv("SECUREOPS_GRYPE_DB_DIR", "/var/cache/grype/db")),
			SemgrepDir:        strings.TrimSpace(getenv("SECUREOPS_SEMGREP_DIR", "/var/cache/semgrep")),
			TrivyDir:          strings.TrimSpace(getenv("SECUREOPS_TRIVY_DIR", "/var/cache/trivy")),
			TrivyMaxImageSize: strings.TrimSpace(os.Getenv("SECUREOPS_TRIVY_MAX_IMAGE_SIZE")),
			ZAPHomeDir:        strings.TrimSpace(getenv("SECUREOPS_ZAP_DIR", "/var/cache/zap")),
			ZAPCommand:        strings.TrimSpace(os.Getenv("SECUREOPS_ZAP_COMMAND")),
			ZAPJarPath:        strings.TrimSpace(os.Getenv("SECUREOPS_ZAP_JAR")),
			ZAPMaxHeap:        strings.TrimSpace(getenv("SECUREOPS_ZAP_MAX_HEAP", "1024m")),
		},
	}

	var err error
	if cfg.LogLevel, err = levelEnv("SECUREOPS_LOG_LEVEL", slog.LevelInfo); err != nil {
		return ScanJob{}, err
	}
	if cfg.ScannerTimeout, err = durationEnv("SECUREOPS_SCANNER_TIMEOUT", 10*time.Minute); err != nil {
		return ScanJob{}, err
	}
	if cfg.MaxOutputBytes, err = int64Env("SECUREOPS_SCANNER_MAX_OUTPUT_BYTES", 64<<20); err != nil {
		return ScanJob{}, err
	}
	if cfg.Fetch.Timeout, err = durationEnv("SECUREOPS_FETCH_TIMEOUT", 10*time.Minute); err != nil {
		return ScanJob{}, err
	}
	if cfg.Fetch.MaxBytes, err = int64Env("SECUREOPS_FETCH_MAX_BYTES", 2<<30); err != nil {
		return ScanJob{}, err
	}
	if cfg.Fetch.MaxFiles, err = intEnv("SECUREOPS_FETCH_MAX_FILES", 500_000); err != nil {
		return ScanJob{}, err
	}
	if cfg.WorkspaceRoot == "" {
		return ScanJob{}, fmt.Errorf("SECUREOPS_WORKSPACE_ROOT must not be empty")
	}
	return cfg, nil
}
