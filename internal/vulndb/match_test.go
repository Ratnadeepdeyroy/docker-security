package vulndb

import "testing"

func TestVulnerableRanges(t *testing.T) {
	tests := []struct {
		name      string
		scheme    VersionScheme
		installed string
		ranges    []Range
		want      bool
	}{
		{
			name:      "inside introduced-fixed interval",
			scheme:    SchemeSemver,
			installed: "4.17.20",
			ranges:    []Range{{Introduced: "0", Fixed: "4.17.21"}},
			want:      true,
		},
		{
			name:      "at fixed version is not affected (exclusive upper bound)",
			scheme:    SchemeSemver,
			installed: "4.17.21",
			ranges:    []Range{{Introduced: "0", Fixed: "4.17.21"}},
			want:      false,
		},
		{
			name:      "below introduced is not affected",
			scheme:    SchemeSemver,
			installed: "1.9.0",
			ranges:    []Range{{Introduced: "2.0.0", Fixed: "2.5.0"}},
			want:      false,
		},
		{
			name:      "last_affected is inclusive",
			scheme:    SchemeDeb,
			installed: "1.0-3",
			ranges:    []Range{{Introduced: "0", LastAffected: "1.0-3"}},
			want:      true,
		},
		{
			name:      "open-ended range (no fix) is affected above introduced",
			scheme:    SchemePEP440,
			installed: "3.0",
			ranges:    []Range{{Introduced: "1.0"}},
			want:      true,
		},
		{
			name:      "multiple branches: matches the second",
			scheme:    SchemeSemver,
			installed: "2.4.0",
			ranges: []Range{
				{Introduced: "1.0.0", Fixed: "1.5.0"},
				{Introduced: "2.0.0", Fixed: "2.5.0"},
			},
			want: true,
		},
		{
			name:      "epoch-aware: fixed with epoch not matched by lower epoch semantics",
			scheme:    SchemeRPM,
			installed: "1.0-1",
			ranges:    []Range{{Introduced: "0", Fixed: "1:1.0-1"}},
			want:      true, // 1.0-1 < 1:1.0-1 because the fix bumped the epoch
		},
		{
			name:      "empty installed version never matches",
			scheme:    SchemeSemver,
			installed: "",
			ranges:    []Range{{Introduced: "0"}},
			want:      false,
		},
		{
			name:      "per-range scheme override",
			scheme:    SchemeGeneric,
			installed: "1.0.0-rc.1",
			ranges:    []Range{{Scheme: SchemeSemver, Introduced: "0", Fixed: "1.0.0"}},
			want:      true, // rc.1 < 1.0.0 under semver
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Vulnerable(tc.scheme, tc.installed, tc.ranges); got != tc.want {
				t.Errorf("Vulnerable(%s,%q,...) = %v, want %v", tc.scheme, tc.installed, got, tc.want)
			}
		})
	}
}

func TestFixedVersionPicksSmallest(t *testing.T) {
	adv := Advisory{
		Ecosystem: "npm",
		Ranges: []Range{
			{Introduced: "2.0.0", Fixed: "2.5.0"},
			{Introduced: "1.0.0", Fixed: "1.5.0"},
		},
	}
	if got := adv.FixedVersion(SchemeSemver); got != "1.5.0" {
		t.Errorf("FixedVersion = %q, want 1.5.0", got)
	}

	unfixed := Advisory{Ranges: []Range{{Introduced: "0"}}}
	if got := unfixed.FixedVersion(SchemeSemver); got != "" {
		t.Errorf("FixedVersion(unfixed) = %q, want empty", got)
	}
}
