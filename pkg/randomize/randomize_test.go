package randomize

import (
	"math/rand"
	"testing"

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

// A seeded Rand must make the ServerHello extension ordering reproducible.
func TestRandomizedServerHelloDeterministic(t *testing.T) {
	build := func() handshake.MessageServerHello {
		return handshake.MessageServerHello{
			Version: protocol.Version{Major: 0xfe, Minor: 0xfd},
			Extensions: []extension.Extension{
				&extension.RenegotiationInfo{},
				&extension.UseExtendedMasterSecret{},
				&extension.ALPN{ProtocolNameList: []string{"h2"}},
				&extension.UseSRTP{
					ProtectionProfiles: []extension.SRTPProtectionProfile{
						extension.SRTP_AEAD_AES_128_GCM,
					},
				},
			},
		}
	}

	order := func(seed int64) []uint16 {
		m := &RandomizedMessageServerHello{Rand: rand.New(rand.NewSource(seed))} //nolint:gosec
		msg := m.Hook(build())
		sh, ok := msg.(*handshake.MessageServerHello)
		if !ok {
			t.Fatalf("Hook returned unexpected type %T", msg)
		}
		types := make([]uint16, len(sh.Extensions))
		for i, e := range sh.Extensions {
			types[i] = uint16(e.TypeValue())
		}
		return types
	}

	first := order(99)
	second := order(99)
	if len(first) != len(second) {
		t.Fatalf("seeded runs produced different extension counts")
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("seeded ServerHello ordering diverged at %d: %v vs %v", i, first, second)
		}
	}
}
