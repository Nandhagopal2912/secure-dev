// Package all registers every scanner adapter this deployment ships.
//
// It exists because two binaries now need the same set: the controller, which
// resolves adapters to decide what a scan will run and later to parse what it
// produced, and cmd/scanjob, which actually executes them (ADR 039).
//
// Duplicating the list would have quietly broken §7 rule 4 -- "adding a new
// scanner must require zero changes outside internal/scanners/<new> plus one
// registration entry" -- by making it two entries in two places, with a missed
// one showing up as a scan that resolves an adapter the job cannot run.
//
// Under internal/scanners/ deliberately: §5 makes that the only place
// scanner-specific knowledge may live. The scanners root still imports no
// adapter; this is a subpackage, and the dependency runs the right way.
package all

import (
	"github.com/aizen299/secure-dev/internal/config"
	"github.com/aizen299/secure-dev/internal/netguard"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scanners/gitleaks"
	"github.com/aizen299/secure-dev/internal/scanners/grype"
	"github.com/aizen299/secure-dev/internal/scanners/httpprobe"
	"github.com/aizen299/secure-dev/internal/scanners/semgrep"
	"github.com/aizen299/secure-dev/internal/scanners/syft"
	"github.com/aizen299/secure-dev/internal/scanners/trivy"
	"github.com/aizen299/secure-dev/internal/scanners/zap"
)

// Register wires every adapter into the registry.
//
// Grype takes a configured path rather than nothing, which is as far as the
// exception goes: what that path is for, how the database gets there, and what
// happens when it is stale are all inside the adapter. Provisioning is driven
// through the generic scanners.Provisioner hook, so nothing here knows that
// grype needs a database at all.
func Register(registry *scanners.Registry, cfg config.ScannerSettings) {
	registry.MustRegister(gitleaks.New())
	registry.MustRegister(syft.New())
	registry.MustRegister(grype.New(cfg.GrypeDBCacheDir))
	registry.MustRegister(semgrep.New(cfg.SemgrepDir))
	registry.MustRegister(&trivy.Scanner{
		CacheDir:     cfg.TrivyDir,
		MaxImageSize: cfg.TrivyMaxImageSize,
	})
	registry.MustRegister(httpprobe.New(netguard.Policy{AllowPrivate: cfg.AllowPrivateTargets}))
	// ZAP is the one adapter that scans a running application rather than
	// bytes at rest. Registered like any other: the registry selects it by
	// target kind, and nothing here knows what DAST is (§7 rule 4).
	registry.MustRegister(&zap.Scanner{
		HomeDir: cfg.ZAPHomeDir,
		Command: cfg.ZAPCommand,
		JarPath: cfg.ZAPJarPath,
		MaxHeap: cfg.ZAPMaxHeap,
	})
}

// New builds a registry with every adapter already registered.
func New(cfg config.ScannerSettings) *scanners.Registry {
	registry := scanners.NewRegistry()
	Register(registry, cfg)
	return registry
}
