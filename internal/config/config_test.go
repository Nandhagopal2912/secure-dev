package config

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"
)

const (
	testDatabaseURL = "postgres://secureops:local-dev-password@localhost:5432/secureops?sslmode=disable"
	testRedisURL    = "redis://:local-dev-password@localhost:6379/0"
)

func setRequired(t *testing.T) {
	t.Helper()
	t.Setenv("SECUREOPS_DATABASE_URL", testDatabaseURL)
	t.Setenv("SECUREOPS_REDIS_URL", testRedisURL)
}

func TestLoadDefaults(t *testing.T) {
	setRequired(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.Env != EnvDevelopment {
		t.Errorf("Env = %q, want %q", cfg.Env, EnvDevelopment)
	}
	if cfg.HTTPAddr != ":8080" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.HTTPAddr, ":8080")
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want %v", cfg.LogLevel, slog.LevelInfo)
	}
	if cfg.LogFormat != "json" {
		t.Errorf("LogFormat = %q, want json", cfg.LogFormat)
	}
	if cfg.DBMaxConns != 10 {
		t.Errorf("DBMaxConns = %d, want 10", cfg.DBMaxConns)
	}
	if cfg.ShutdownTimeout != 20*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 20s", cfg.ShutdownTimeout)
	}
	if cfg.IsProduction() {
		t.Error("IsProduction() = true, want false for development")
	}
}

func TestLoadOverrides(t *testing.T) {
	setRequired(t)
	t.Setenv("SECUREOPS_ENV", "production")
	t.Setenv("SECUREOPS_HTTP_ADDR", "127.0.0.1:9999")
	t.Setenv("SECUREOPS_LOG_LEVEL", "debug")
	t.Setenv("SECUREOPS_LOG_FORMAT", "text")
	t.Setenv("SECUREOPS_DB_MAX_CONNS", "42")
	t.Setenv("SECUREOPS_HTTP_READ_TIMEOUT", "1m")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if !cfg.IsProduction() {
		t.Error("IsProduction() = false, want true")
	}
	if cfg.HTTPAddr != "127.0.0.1:9999" {
		t.Errorf("HTTPAddr = %q", cfg.HTTPAddr)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %v, want debug", cfg.LogLevel)
	}
	if cfg.DBMaxConns != 42 {
		t.Errorf("DBMaxConns = %d, want 42", cfg.DBMaxConns)
	}
	if cfg.ReadTimeout != time.Minute {
		t.Errorf("ReadTimeout = %v, want 1m", cfg.ReadTimeout)
	}
}

func TestLoadValidationErrors(t *testing.T) {
	tests := []struct {
		name     string
		env      map[string]string
		wantSubs []string
	}{
		{
			name:     "missing database url",
			env:      map[string]string{"SECUREOPS_DATABASE_URL": ""},
			wantSubs: []string{"SECUREOPS_DATABASE_URL", "required"},
		},
		{
			name:     "missing redis url",
			env:      map[string]string{"SECUREOPS_REDIS_URL": ""},
			wantSubs: []string{"SECUREOPS_REDIS_URL", "required"},
		},
		{
			name:     "wrong database scheme",
			env:      map[string]string{"SECUREOPS_DATABASE_URL": "mysql://localhost:3306/secureops"},
			wantSubs: []string{"SECUREOPS_DATABASE_URL", "scheme"},
		},
		{
			name:     "database url without host",
			env:      map[string]string{"SECUREOPS_DATABASE_URL": "postgres:///secureops"},
			wantSubs: []string{"SECUREOPS_DATABASE_URL", "host"},
		},
		{
			name:     "unknown environment",
			env:      map[string]string{"SECUREOPS_ENV": "prod"},
			wantSubs: []string{"SECUREOPS_ENV"},
		},
		{
			name:     "bad log level",
			env:      map[string]string{"SECUREOPS_LOG_LEVEL": "verbose"},
			wantSubs: []string{"SECUREOPS_LOG_LEVEL"},
		},
		{
			name:     "bad log format",
			env:      map[string]string{"SECUREOPS_LOG_FORMAT": "xml"},
			wantSubs: []string{"SECUREOPS_LOG_FORMAT"},
		},
		{
			name:     "bad duration",
			env:      map[string]string{"SECUREOPS_HTTP_READ_TIMEOUT": "ten seconds"},
			wantSubs: []string{"SECUREOPS_HTTP_READ_TIMEOUT"},
		},
		{
			name:     "non positive duration",
			env:      map[string]string{"SECUREOPS_SHUTDOWN_TIMEOUT": "0s"},
			wantSubs: []string{"SECUREOPS_SHUTDOWN_TIMEOUT"},
		},
		{
			name:     "zero max conns",
			env:      map[string]string{"SECUREOPS_DB_MAX_CONNS": "0"},
			wantSubs: []string{"SECUREOPS_DB_MAX_CONNS"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setRequired(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			_, err := Load()
			if err == nil {
				t.Fatal("Load() succeeded, want validation error")
			}
			for _, sub := range tc.wantSubs {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("error %q does not mention %q", err.Error(), sub)
				}
			}
		})
	}
}

// Validation errors are user-facing and end up in logs. A malformed DSN must
// never be echoed back verbatim. See CLAUDE.md §15.3.
func TestValidationErrorsDoNotLeakCredentials(t *testing.T) {
	setRequired(t)
	t.Setenv("SECUREOPS_DATABASE_URL", "mysql://admin:sup3r-s3cret@db.internal:3306/x")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() succeeded, want validation error")
	}
	if strings.Contains(err.Error(), "sup3r-s3cret") {
		t.Errorf("validation error leaked a credential: %q", err.Error())
	}
}

func TestRedactURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{
			"postgres with password and query",
			"postgres://secureops:hunter2@db:5432/secureops?sslmode=require",
			"postgres://redacted@db:5432/secureops?redacted",
		},
		{
			"redis with password",
			"redis://:hunter2@cache:6379/0",
			"redis://redacted@cache:6379/0",
		},
		{
			"no credentials is preserved",
			"postgres://db:5432/secureops",
			"postgres://db:5432/secureops",
		},
		{
			"fragment stripped",
			"redis://user:pw@cache:6379/0#note",
			"redis://redacted@cache:6379/0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactURL(tc.in)
			if got != tc.want {
				t.Errorf("RedactURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if strings.Contains(got, "hunter2") {
				t.Errorf("RedactURL leaked the password: %q", got)
			}
		})
	}
}

// Logging a whole Config must not emit a DSN, because slog.LogValuer is what
// stands between a careless log line and a leaked credential.
func TestConfigLogValueRedactsSecrets(t *testing.T) {
	setRequired(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("startup", "config", cfg)

	out := buf.String()
	if strings.Contains(out, "local-dev-password") {
		t.Fatalf("log output leaked a credential: %s", out)
	}
	if !strings.Contains(out, "redacted") {
		t.Fatalf("log output is missing the redaction marker: %s", out)
	}

	var payload map[string]any
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("log output is not valid JSON: %v", err)
	}
	if _, ok := payload["config"]; !ok {
		t.Error("log output has no config group")
	}
}

func TestWorkerDefaults(t *testing.T) {
	setRequired(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.WorkerConcurrency != 2 {
		t.Errorf("WorkerConcurrency = %d, want 2", cfg.WorkerConcurrency)
	}
	if cfg.ScanJobTimeout != 30*time.Minute {
		t.Errorf("ScanJobTimeout = %v, want 30m", cfg.ScanJobTimeout)
	}
	if cfg.ScannerTimeout != 10*time.Minute {
		t.Errorf("ScannerTimeout = %v, want 10m", cfg.ScannerTimeout)
	}
	// The SSRF guard must be on unless explicitly disabled.
	if cfg.AllowPrivateTargets {
		t.Error("AllowPrivateTargets defaults to true; the SSRF guard must be on by default")
	}
	if cfg.WorkerWorkspaceRoot == "" {
		t.Error("WorkerWorkspaceRoot has no default")
	}
}

// A scanner timeout longer than the job timeout would see the scanner killed
// mid-write, losing its result and stranding the scan.
func TestScannerTimeoutMustNotExceedJobTimeout(t *testing.T) {
	setRequired(t)
	t.Setenv("SECUREOPS_SCAN_JOB_TIMEOUT", "1m")
	t.Setenv("SECUREOPS_SCANNER_TIMEOUT", "5m")

	_, err := Load()
	if err == nil {
		t.Fatal("Load accepted a scanner timeout longer than the job timeout")
	}
	if !strings.Contains(err.Error(), "SECUREOPS_SCANNER_TIMEOUT") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// Shipping production with the SSRF guard off is the mistake most likely to be
// made by copying a local .env, so it must fail at boot.
func TestProductionRefusesPrivateTargets(t *testing.T) {
	setRequired(t)
	t.Setenv("SECUREOPS_ENV", "production")
	t.Setenv("SECUREOPS_ALLOW_PRIVATE_TARGETS", "true")

	_, err := Load()
	if err == nil {
		t.Fatal("production accepted ALLOW_PRIVATE_TARGETS=true")
	}
	if !strings.Contains(err.Error(), "SECUREOPS_ALLOW_PRIVATE_TARGETS") {
		t.Errorf("unhelpful error: %v", err)
	}

	// The same setting is legitimate outside production.
	t.Setenv("SECUREOPS_ENV", "development")
	if _, err := Load(); err != nil {
		t.Errorf("development rejected ALLOW_PRIVATE_TARGETS=true: %v", err)
	}
}

func TestWorkerValidationErrors(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"zero concurrency":     {"SECUREOPS_WORKER_CONCURRENCY": "0"},
		"negative concurrency": {"SECUREOPS_WORKER_CONCURRENCY": "-3"},
		"bad concurrency":      {"SECUREOPS_WORKER_CONCURRENCY": "many"},
		"zero output cap":      {"SECUREOPS_SCANNER_MAX_OUTPUT_BYTES": "0"},
		"bad output cap":       {"SECUREOPS_SCANNER_MAX_OUTPUT_BYTES": "lots"},
		"bad bool":             {"SECUREOPS_ALLOW_PRIVATE_TARGETS": "yes-please"},
		"empty workspace root": {"SECUREOPS_WORKSPACE_ROOT": " "},
	} {
		t.Run(name, func(t *testing.T) {
			setRequired(t)
			for k, v := range env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Error("invalid worker configuration accepted")
			}
		})
	}
}

// A scan pod cannot reach a private range whatever this says (ADR 039), so a
// setting meant for the worker must not make its adapters claim otherwise.
func TestScanJobStaysStrictOnPrivateTargets(t *testing.T) {
	t.Setenv("SECUREOPS_ALLOW_PRIVATE_TARGETS", "true")
	cfg, err := LoadScanJob()
	if err != nil {
		t.Fatalf("LoadScanJob: %v", err)
	}
	if cfg.Scanners.AllowPrivateTargets {
		t.Error("a scan job must stay strict on private targets")
	}
}

// An adapter enforcing the address policy itself has to be given the setting,
// and the default has to stay the strict one.
func TestScannerSettingsCarryTheAddressPolicy(t *testing.T) {
	if (Config{}).Scanners().AllowPrivateTargets {
		t.Error("private targets must stay refused unless turned on")
	}
	if !(Config{AllowPrivateTargets: true}).Scanners().AllowPrivateTargets {
		t.Error("the deployment's setting did not reach the adapters")
	}
}
