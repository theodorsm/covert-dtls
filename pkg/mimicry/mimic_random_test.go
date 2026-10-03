package mimicry

import (
	"math/rand"
	"testing"
)

// A seeded Rand must make LoadRandomFingerprint select the same fingerprint
// across runs, which is what enables deterministic replay.
func TestLoadRandomFingerprintDeterministic(t *testing.T) {
	load := func(seed int64) string {
		m := &MimickedClientHello{Rand: rand.New(rand.NewSource(seed))} //nolint:gosec
		if err := m.LoadRandomFingerprint(); err != nil {
			t.Fatalf("LoadRandomFingerprint failed: %v", err)
		}
		return string(m.clientHelloFingerprint)
	}

	first := load(2024)
	second := load(2024)
	if first == "" {
		t.Fatalf("no fingerprint loaded")
	}
	if first != second {
		t.Fatalf("seeded selection was not deterministic")
	}
}

// With no Rand set, LoadRandomFingerprint must still work using the default
// crypto/rand source.
func TestLoadRandomFingerprintDefaultRand(t *testing.T) {
	m := &MimickedClientHello{}
	if err := m.LoadRandomFingerprint(); err != nil {
		t.Fatalf("LoadRandomFingerprint with default Rand failed: %v", err)
	}
	if string(m.clientHelloFingerprint) == "" {
		t.Fatalf("no fingerprint loaded")
	}
}
