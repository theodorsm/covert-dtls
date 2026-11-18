package randomize

import (
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/theodorsm/covert-dtls/pkg/utils"
)

// RandomizedMessageServerHello provides a ServerHello hook that shuffles the
// order of the ServerHello extensions to avoid trivial extension-order
// fingerprinting. A ServerHello carries a single cipher suite and fewer
// extensions than a ClientHello, so only the extension order is randomized.
//
// It is intended to be used with pion/dtls' ServerHelloMessageHook (for
// example via webrtc's SettingEngine.SetDTLSServerHelloMessageHook).
type RandomizedMessageServerHello struct {
	// Rand is the randomness source used to shuffle the extension order. When
	// nil, a crypto/rand-backed source is used. Supply a seeded Rand to
	// deterministically replay the same extension ordering.
	Rand utils.Rand
}

// Hook is the ServerHelloMessageHook callback for pion/dtls. It shuffles the
// extension order of the ServerHello message.
func (m *RandomizedMessageServerHello) Hook(sh handshake.MessageServerHello) handshake.Message {
	r := m.Rand
	if r == nil {
		r = utils.DefaultRand()
	}

	if len(sh.Extensions) > 1 {
		r.Shuffle(len(sh.Extensions), func(i, j int) {
			sh.Extensions[i], sh.Extensions[j] = sh.Extensions[j], sh.Extensions[i]
		})
	}

	return &sh
}
