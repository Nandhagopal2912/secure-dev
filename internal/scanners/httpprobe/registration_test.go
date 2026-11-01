package httpprobe_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aizen299/secure-dev/internal/config"
	"github.com/aizen299/secure-dev/internal/normalization"
	"github.com/aizen299/secure-dev/internal/scanners"
	"github.com/aizen299/secure-dev/internal/scanners/all"
	"github.com/aizen299/secure-dev/internal/scanners/httpprobe"
)

// An adapter that was written but never registered would silently cover nothing.
// An external test package, because `all` imports this adapter.
func TestRegisteredForEndpointScans(t *testing.T) {
	registry := all.New(config.ScannerSettings{})

	adapter, ok := registry.Get(httpprobe.Name)
	if !ok {
		t.Fatal("httpprobe is not registered")
	}
	if _, ok := adapter.(normalization.Normalizer); !ok {
		t.Error("httpprobe must implement Normalizer, or its output is never read")
	}

	selected := false
	for _, s := range registry.SelectFor(scanners.KindEndpoint) {
		selected = selected || s.Name() == httpprobe.Name
	}
	if !selected {
		t.Error("an endpoint scan does not select httpprobe")
	}
}

// The deployment's setting has to reach the adapter, or a self-hosted operator
// who turned it on would still see every private target refused.
func TestRegistrationCarriesTheAddressPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	target := scanners.Target{Kind: scanners.KindEndpoint, EndpointURL: srv.URL}

	strict, _ := all.New(config.ScannerSettings{}).Get(httpprobe.Name)
	if _, err := strict.Scan(context.Background(), target); !errors.Is(err, httpprobe.ErrBlockedTarget) {
		t.Errorf("default settings: err = %v, want ErrBlockedTarget", err)
	}

	open, _ := all.New(config.ScannerSettings{AllowPrivateTargets: true}).Get(httpprobe.Name)
	if _, err := open.Scan(context.Background(), target); err != nil {
		t.Errorf("private targets allowed: %v", err)
	}
}
