package vulndb

import (
	"math"
	"testing"
)

func TestParseCVSSVector(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0}, // Log4Shell
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N", 6.1},  // scope-changed, partial impact
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5},  // classic network info-leak
		{"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.5},  // local DoS
	}
	for _, tc := range tests {
		c, ok := ParseCVSSVector(tc.vector)
		if !ok {
			t.Errorf("ParseCVSSVector(%q) failed", tc.vector)
			continue
		}
		if math.Abs(c.Score-tc.want) > 0.05 {
			t.Errorf("ParseCVSSVector(%q) score = %.2f, want %.1f", tc.vector, c.Score, tc.want)
		}
	}
}

func TestParseCVSSRejectsNonV3(t *testing.T) {
	for _, v := range []string{"", "AV:N/AC:L", "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"} {
		if _, ok := ParseCVSSVector(v); ok {
			t.Errorf("ParseCVSSVector(%q) should have been rejected", v)
		}
	}
}

func TestSeverityFromScore(t *testing.T) {
	cases := []struct {
		score float64
		want  Severity
	}{
		{10.0, SevCritical}, {9.0, SevCritical},
		{8.9, SevHigh}, {7.0, SevHigh},
		{6.9, SevMedium}, {4.0, SevMedium},
		{3.9, SevLow}, {0.1, SevLow},
		{0.0, SevNegligible},
	}
	for _, c := range cases {
		if got := SeverityFromScore(c.score); got != c.want {
			t.Errorf("SeverityFromScore(%.1f) = %s, want %s", c.score, got, c.want)
		}
	}
}
