package cli

import "testing"

// isLoopbackAddr gates whether riskforge serve refuses to start without
// TLS (ADR 0012), so it gets a direct unit test even though this
// package otherwise relies on real execution rather than unit tests
// (AGENTS.md's "verify with real tools" convention) — the security
// judgment call it makes is worth pinning down precisely.
func TestIsLoopbackAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"localhost:8080", true},
		{"LOCALHOST:8080", true},
		{"[::1]:8080", true},
		{":8080", false},        // wildcard bind, every interface
		{"0.0.0.0:8080", false}, // explicit wildcard
		{"192.168.1.10:8080", false},
		{"riskforge.internal:8080", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isLoopbackAddr(c.addr); got != c.want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}
