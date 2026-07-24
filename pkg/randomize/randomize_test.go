package randomize

import (
	"math/rand"
	"testing"

	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

func testClientHello() handshake.MessageClientHello {
	return handshake.MessageClientHello{
		Version:            protocol.Version{Major: 0xfe, Minor: 0xfd},
		CipherSuiteIDs:     []uint16{0xc02b, 0xc02f, 0xc00a, 0xc009, 0xc013, 0xc014},
		CompressionMethods: []*protocol.CompressionMethod{{}},
		Extensions: []extension.Extension{
			&extension.RenegotiationInfo{},
			&extension.UseExtendedMasterSecret{},
			&extension.ALPN{ProtocolNameList: []string{"h2", "http/1.1"}},
			&extension.UseSRTP{
				ProtectionProfiles: []extension.SRTPProtectionProfile{
					extension.SRTP_AES128_CM_HMAC_SHA1_80,
					extension.SRTP_AES128_CM_HMAC_SHA1_32,
					extension.SRTP_AEAD_AES_128_GCM,
					extension.SRTP_AEAD_AES_256_GCM,
				},
			},
		},
	}
}

// A seeded Rand must make the randomized ClientHello byte-for-byte
// reproducible, which is the property tunnel-core relies on for replay.
func TestRandomizedClientHelloDeterministic(t *testing.T) {
	marshalWithSeed := func(seed int64) []byte {
		m := &RandomizedMessageClientHello{
			RandomALPN: true,
			Rand:       rand.New(rand.NewSource(seed)), //nolint:gosec
		}
		msg := m.Hook(testClientHello())
		out, err := msg.Marshal()
		if err != nil {
			t.Fatalf("Marshal failed: %v", err)
		}
		return out
	}

	first := marshalWithSeed(1234)
	second := marshalWithSeed(1234)

	if len(first) != len(second) {
		t.Fatalf("seeded runs produced different lengths: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("seeded runs diverged at byte %d", i)
		}
	}
}

// With no Rand set, the hook must still function (using the crypto/rand
// default) and produce a valid, marshalable message.
func TestRandomizedClientHelloDefaultRand(t *testing.T) {
	m := &RandomizedMessageClientHello{RandomALPN: true}
	msg := m.Hook(testClientHello())
	if _, err := msg.Marshal(); err != nil {
		t.Fatalf("Marshal with default Rand failed: %v", err)
	}
}

func hasECC(suites []uint16) bool {
	for _, id := range suites {
		for _, eccID := range eccCipherSuiteIDs {
			if id == eccID {
				return true
			}
		}
	}
	return false
}

// ensureECCCipherSuite must add an ECDHE-ECDSA suite when none is present so
// that pion's ECDSA P-256 certificates can complete the handshake.
func TestEnsureECCCipherSuiteAddsWhenMissing(t *testing.T) {
	suites := []uint16{0x1301, 0x1302, 0x1303}                 // TLS 1.3 suites, no ECDHE-ECDSA
	ensureECCCipherSuite(&suites, rand.New(rand.NewSource(1))) //nolint:gosec
	if !hasECC(suites) {
		t.Fatalf("expected an ECC cipher suite to be added, got %v", suites)
	}
}

// ensureECCCipherSuite must not modify suites that already contain an
// ECDHE-ECDSA suite.
func TestEnsureECCCipherSuiteNoopWhenPresent(t *testing.T) {
	suites := []uint16{0x1301, eccCipherSuiteIDs[0], 0x1302}
	before := append([]uint16{}, suites...)
	ensureECCCipherSuite(&suites, rand.New(rand.NewSource(1))) //nolint:gosec
	if len(suites) != len(before) {
		t.Fatalf("expected no change, len %d -> %d", len(before), len(suites))
	}
	for i := range before {
		if suites[i] != before[i] {
			t.Fatalf("expected no change, %v -> %v", before, suites)
		}
	}
}

// pinECDSAP256 must move an existing ECDSA P-256 entry to index 0, or prepend
// it when absent.
func TestPinECDSAP256(t *testing.T) {
	other := signaturehash.Algorithm{Hash: hash.SHA256, Signature: signature.RSA}

	// Present but not first -> moved to front.
	algs := []signaturehash.Algorithm{other, ecdsaP256SHA256}
	pinECDSAP256(&algs)
	if algs[0] != ecdsaP256SHA256 {
		t.Fatalf("expected ECDSA P-256 first, got %v", algs)
	}

	// Absent -> prepended.
	algs = []signaturehash.Algorithm{other}
	pinECDSAP256(&algs)
	if len(algs) != 2 || algs[0] != ecdsaP256SHA256 {
		t.Fatalf("expected ECDSA P-256 prepended, got %v", algs)
	}

	// Already first -> unchanged length.
	algs = []signaturehash.Algorithm{ecdsaP256SHA256, other}
	pinECDSAP256(&algs)
	if len(algs) != 2 || algs[0] != ecdsaP256SHA256 {
		t.Fatalf("expected unchanged, got %v", algs)
	}
}
