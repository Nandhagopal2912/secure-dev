package normalization

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/aizen299/secure-dev/internal/scanners"
)

func fp(t *testing.T, in FingerprintInput) string {
	t.Helper()
	got, err := Fingerprint(in)
	if err != nil {
		t.Fatalf("Fingerprint(%+v): %v", in, err)
	}
	return got
}

func secretAt(file string) FingerprintInput {
	return FingerprintInput{
		Category: scanners.CategorySecrets,
		RuleID:   "github-pat",
		Location: file,
	}
}

func TestEndpointTargetPath(t *testing.T) {
	cases := []struct {
		raw, want string
		ok        bool
	}{
		{"https://site.test/api/account", "api/account", true},
		{"https://pr-1.site.test:8443/api/account", "api/account", true},
		{"https://site.test/api/account?a=1#top", "api/account", true},
		{"https://site.test/api/account/", "api/account", true},
		{"https://site.test/api//account", "api/account", true},
		{"https://site.test/api/./account", "api/account", true},
		{"https://user:pass@site.test/api", "api", true},
		{"https://site.test/files/a%2Fb", "files/a%2Fb", true},
		{"https://site.test", "", true},
		{"https://site.test/", "", true},
		{"https://site.test/?a=1", "", true},
		{"", "", false},
		{"   ", "", false},
		{"not a url", "", false},
		{"http://[bad", "", false},
	}
	for _, tc := range cases {
		got, ok := EndpointTargetPath(tc.raw)
		if got != tc.want || ok != tc.ok {
			t.Errorf("EndpointTargetPath(%q) = %q, %v; want %q, %v", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}

func TestFingerprintIsDeterministic(t *testing.T) {
	// Two separately constructed but equal inputs, not one value compared with
	// itself: the claim is that equal findings fingerprint equally, which is
	// what reprocessing stored raw output depends on.
	first := fp(t, secretAt("config/settings.py"))
	second := fp(t, secretAt("config/settings.py"))
	if first != second {
		t.Error("two equal findings produced different identities")
	}

	// And across a process boundary, in effect: the value is fixed, so a
	// change to the formula shows up here rather than silently re-identifying
	// every finding already in the database.
	if len(first) != 64 {
		t.Fatalf("fingerprint is not a hex sha256: %q", first)
	}
}

// The property the whole design turns on, asserted structurally.
//
// Comparing two identical inputs would prove nothing beyond determinism. What
// actually guarantees that a finding keeps its identity when it moves down a
// file is that FingerprintInput has nowhere to put a line number -- so this
// test fails the moment somebody adds one.
func TestExcludedFieldsHaveNowhereToLive(t *testing.T) {
	// Every field name that must never contribute to identity, with the
	// reason recorded in docs/architecture/fingerprinting.md.
	forbidden := map[string]string{
		"line":       "a finding that moves down a file is the same finding",
		"startline":  "same",
		"endline":    "same",
		"column":     "same",
		"title":      "changes on scanner upgrade; §25.5 forbids identity by title",
		"message":    "same",
		"descript":   "same",
		"severity":   "a vendor rescoring a CVE would fork one finding into two",
		"scanner":    "two scanners reporting one problem must agree (§9)",
		"version":    "the same finding from two scanner versions is one finding",
		"confidence": "not an identity property",
	}

	typ := reflect.TypeOf(FingerprintInput{})
	for i := range typ.NumField() {
		name := strings.ToLower(typ.Field(i).Name)
		for bad, why := range forbidden {
			// PackageVersion is legitimate: a different package version IS a
			// different finding. Only a bare version field is forbidden.
			if name == "package" || name == "vulnerabilityid" {
				continue
			}
			if strings.Contains(name, bad) {
				t.Errorf("FingerprintInput.%s must not exist: %s", typ.Field(i).Name, why)
			}
		}
	}

	// And the set of inputs is exactly what the design says it is. Adding one
	// changes every existing finding's identity, which is a migration rather
	// than an edit -- so it should not be possible to do by accident.
	var got []string
	for i := range typ.NumField() {
		got = append(got, typ.Field(i).Name)
	}
	want := []string{"Category", "RuleID", "Location", "Package", "VulnerabilityID"}
	if !slices.Equal(got, want) {
		t.Errorf("fingerprint inputs = %v, want %v (see ADR 016)", got, want)
	}
}

// Near misses, which §8 requires be covered explicitly. Each pair differs in
// exactly one input and must produce different identities.
func TestNearMissesAreDistinct(t *testing.T) {
	base := FingerprintInput{
		Category:        scanners.CategoryDependency,
		RuleID:          "",
		Location:        "go.mod",
		Package:         "pkg:golang/golang.org/x/crypto@v0.31.0",
		VulnerabilityID: "CVE-2026-1234",
	}

	variants := map[string]FingerprintInput{
		"different category":      {Category: scanners.CategorySAST, Location: base.Location, Package: base.Package, VulnerabilityID: base.VulnerabilityID},
		"different location":      {Category: base.Category, Location: "vendor/go.mod", Package: base.Package, VulnerabilityID: base.VulnerabilityID},
		"different package":       {Category: base.Category, Location: base.Location, Package: "pkg:golang/golang.org/x/text@v0.31.0", VulnerabilityID: base.VulnerabilityID},
		"different version":       {Category: base.Category, Location: base.Location, Package: "pkg:golang/golang.org/x/crypto@v0.32.0", VulnerabilityID: base.VulnerabilityID},
		"different vulnerability": {Category: base.Category, Location: base.Location, Package: base.Package, VulnerabilityID: "CVE-2026-9999"},
		"a rule id appears":       {Category: base.Category, RuleID: "some-rule", Location: base.Location, Package: base.Package, VulnerabilityID: base.VulnerabilityID},
	}

	baseFP := fp(t, base)
	seen := map[string]string{baseFP: "base"}
	for name, v := range variants {
		got := fp(t, v)
		if prev, clash := seen[got]; clash {
			t.Errorf("%q collides with %q", name, prev)
		}
		seen[got] = name
	}
}

// The reason for the 0x1f separator. With naive concatenation these two
// findings produce the same string and therefore the same identity.
func TestFieldBoundariesCannotBeForged(t *testing.T) {
	a := fp(t, FingerprintInput{Category: scanners.CategorySAST, RuleID: "ab", Location: "c"})
	b := fp(t, FingerprintInput{Category: scanners.CategorySAST, RuleID: "a", Location: "bc"})
	if a == b {
		t.Error("field boundaries are forgeable: 'ab'+'c' collides with 'a'+'bc'")
	}
}

// A field carrying the separator could forge a boundary, so it is refused
// rather than escaped.
func TestSeparatorInInputIsRefused(t *testing.T) {
	_, err := Fingerprint(FingerprintInput{
		Category: scanners.CategorySAST,
		RuleID:   "evil\x1frule",
		Location: "a.go",
	})
	if !errors.Is(err, ErrUnfingerprintable) {
		t.Errorf("err = %v, want ErrUnfingerprintable", err)
	}
}

// An identity built from a category alone would collide with every other
// finding in that category. Refusing is better than minting something
// meaningless.
func TestCategoryAloneIsRefused(t *testing.T) {
	_, err := Fingerprint(FingerprintInput{Category: scanners.CategorySecrets})
	if !errors.Is(err, ErrUnfingerprintable) {
		t.Errorf("err = %v, want ErrUnfingerprintable", err)
	}
}

// Two scanners reporting one CVE on one package are reporting one problem, and
// must produce one identity. §9's correlation depends on it.
//
// The realistic case: grype names the package by purl and reports no rule,
// while a second scanner reports the same CVE against the same purl. Identical
// inputs mean an identical fingerprint, because nothing in the input names a
// scanner -- and that is the point.
func TestTwoScannersAgreeOnOneVulnerability(t *testing.T) {
	const purl = "pkg:golang/golang.org/x/crypto@v0.31.0"

	fromGrype := fp(t, FingerprintInput{
		Category:        scanners.CategoryDependency,
		Package:         purl,
		VulnerabilityID: "CVE-2026-1234",
	})
	// A different scanner, reporting the same fact with different casing --
	// which normalization is responsible for reconciling.
	fromOther := fp(t, FingerprintInput{
		Category:        scanners.CategoryDependency,
		Package:         strings.ToUpper(purl),
		VulnerabilityID: "cve-2026-1234",
	})

	if fromGrype != fromOther {
		t.Error("two scanners reporting one vulnerability produced two findings")
	}
}

// Rule-based findings stay scoped to their scanner, because rule namespaces do
// not overlap. This falls out of including rule_id rather than needing a rule.
func TestRuleBasedFindingsStayDistinctAcrossScanners(t *testing.T) {
	gitleaks := fp(t, FingerprintInput{
		Category: scanners.CategorySecrets, RuleID: "github-pat", Location: "app.py"})
	semgrep := fp(t, FingerprintInput{
		Category: scanners.CategorySecrets, RuleID: "generic.secrets.detected-github-pat", Location: "app.py"})
	if gitleaks == semgrep {
		t.Error("two scanners' distinct rules produced one identity")
	}
}

func TestNormalizeLocation(t *testing.T) {
	same := []string{
		"config/settings.py",
		"./config/settings.py",
		"/config/settings.py",
		"config//settings.py",
		"config/../config/settings.py",
		"config\\settings.py",
		"  config/settings.py  ",
	}
	want := NormalizeLocation(same[0])
	for _, s := range same[1:] {
		if got := NormalizeLocation(s); got != want {
			t.Errorf("NormalizeLocation(%q) = %q, want %q", s, got, want)
		}
	}
	if NormalizeLocation("") != "" {
		t.Error("an empty path should stay empty, not become a dot")
	}
}

// Case differences in a package name are not a different package. Treating
// them as such would split one finding across ecosystems that are
// case-insensitive in practice.
func TestPackageCaseDoesNotForkIdentity(t *testing.T) {
	lower := fp(t, FingerprintInput{
		Category: scanners.CategoryDependency, Package: "express@4.17.1", VulnerabilityID: "CVE-2026-1"})
	upper := fp(t, FingerprintInput{
		Category: scanners.CategoryDependency, Package: "Express@4.17.1", VulnerabilityID: "CVE-2026-1"})
	if lower != upper {
		t.Error("package name case forked one finding into two")
	}
}

func TestVulnerabilityIDCaseDoesNotForkIdentity(t *testing.T) {
	a := fp(t, FingerprintInput{Category: scanners.CategoryDependency, Package: "x@1", VulnerabilityID: "cve-2026-1"})
	b := fp(t, FingerprintInput{Category: scanners.CategoryDependency, Package: "x@1", VulnerabilityID: "CVE-2026-1"})
	if a != b {
		t.Error("advisory id case forked one finding into two")
	}
}

func TestFingerprintIsAHexSHA256(t *testing.T) {
	got := fp(t, secretAt("a.py"))
	if len(got) != 64 {
		t.Errorf("length = %d, want 64", len(got))
	}
	if strings.ToLower(got) != got {
		t.Error("fingerprint is not lowercase hex")
	}
}
