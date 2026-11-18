package randomize

import (
	"encoding/binary"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
	"github.com/theodorsm/covert-dtls/pkg/utils"
)

// eccCipherSuiteIDs are the ECDHE-ECDSA cipher suites supported by pion/dtls.
// At least one must be offered for pion's default ECDSA P-256 certificates to
// complete the handshake.
var eccCipherSuiteIDs = []uint16{
	uint16(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
	uint16(dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
	uint16(dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
	uint16(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM),
	uint16(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8),
}

/*
RandomizedMessageClientHello
*/
type RandomizedMessageClientHello struct {
	Version    protocol.Version
	Random     handshake.Random
	Cookie     []byte
	RandomALPN bool // Add a random ALPN if there is none in the hooked message

	// Rand is the randomness source used for all randomization choices. When
	// nil, a crypto/rand-backed source is used. Supply a seeded Rand to
	// deterministically replay the same randomized ClientHello.
	Rand utils.Rand

	SessionID []byte

	CipherSuiteIDs     []uint16
	CompressionMethods []*protocol.CompressionMethod
	Extensions         []extension.Extension
}

const handshakeMessageClientHelloVariableWidthStart = 34

// Type returns the Handshake Type
func (m RandomizedMessageClientHello) Type() handshake.Type {
	return handshake.TypeClientHello
}

// rand returns the configured randomness source, or a crypto/rand-backed
// default when none was set.
func (m *RandomizedMessageClientHello) rand() utils.Rand {
	if m.Rand == nil {
		return utils.DefaultRand()
	}
	return m.Rand
}

// ClientHello Hook for randomization
func (m *RandomizedMessageClientHello) Hook(ch handshake.MessageClientHello) handshake.Message {
	r := m.rand()

	buf, err := ch.Marshal()
	if err != nil {
		return &ch
	}
	err = m.unmarshalWithRand(buf, r)
	if err != nil {
		return &ch
	}
	m.CipherSuiteIDs = utils.ShuffleRandomLength(m.CipherSuiteIDs, true, r)

	// Ensure at least one ECDHE-ECDSA cipher suite survives truncation so
	// pion's default ECDSA P-256 certificates can complete the handshake.
	ensureECCCipherSuite(&m.CipherSuiteIDs, r)

	hasALPN := false
	for _, e := range m.Extensions {
		if e.TypeValue() == extension.TypeValue(extension.ALPNTypeValue) {
			hasALPN = true
		}
	}
	if !hasALPN && m.RandomALPN {
		e := &extension.ALPN{
			ProtocolNameList: []string{utils.ALPNS[r.Intn(len(utils.ALPNS))]},
		}
		m.Extensions = append(m.Extensions, e)
	}

	m.Extensions = utils.ShuffleRandomLength(m.Extensions, false, r)
	return m
}

// ensureECCCipherSuite guarantees that at least one ECDHE-ECDSA cipher suite is
// present in suites. If none survived truncation, one is chosen with r,
// appended, and the list re-shuffled so the addition is not always last.
func ensureECCCipherSuite(suites *[]uint16, r utils.Rand) {
	for _, id := range *suites {
		for _, eccID := range eccCipherSuiteIDs {
			if id == eccID {
				return
			}
		}
	}

	picked := eccCipherSuiteIDs[r.Intn(len(eccCipherSuiteIDs))]
	*suites = append(*suites, picked)

	r.Shuffle(len(*suites), func(i, j int) {
		(*suites)[i], (*suites)[j] = (*suites)[j], (*suites)[i]
	})
}

// Marshal encodes the Handshake
func (m *RandomizedMessageClientHello) Marshal() ([]byte, error) {
	if len(m.Cookie) > 255 {
		return nil, errCookieTooLong
	}

	out := make([]byte, handshakeMessageClientHelloVariableWidthStart)
	out[0] = m.Version.Major
	out[1] = m.Version.Minor

	rand := m.Random.MarshalFixed()
	copy(out[2:], rand[:])

	out = append(out, byte(len(m.SessionID)))
	out = append(out, m.SessionID...)

	out = append(out, byte(len(m.Cookie)))
	out = append(out, m.Cookie...)
	out = append(out, utils.EncodeCipherSuiteIDs(m.CipherSuiteIDs)...)
	out = append(out, protocol.EncodeCompressionMethods(m.CompressionMethods)...)
	extensions, err := utils.ExtensionMarshal(m.Extensions)
	if err != nil {
		return nil, err
	}

	return append(out, extensions...), nil
}

// Unmarshal populates the message from encoded data, randomizing extensions
// with a crypto/rand-backed source or, when set, the configured Rand.
func (m *RandomizedMessageClientHello) Unmarshal(data []byte) error {
	return m.unmarshalWithRand(data, m.rand())
}

// unmarshalWithRand populates the message from encoded data, using r for
// extension randomization.
func (m *RandomizedMessageClientHello) unmarshalWithRand(data []byte, r utils.Rand) error {
	if len(data) < 2+handshake.RandomLength {
		return errBufferTooSmall
	}

	m.Version.Major = data[0]
	m.Version.Minor = data[1]

	var random [handshake.RandomLength]byte
	copy(random[:], data[2:])
	m.Random.UnmarshalFixed(random)

	// rest of packet has variable width sections
	currOffset := handshakeMessageClientHelloVariableWidthStart

	currOffset++
	if len(data) <= currOffset {
		return errBufferTooSmall
	}
	n := int(data[currOffset-1])
	if len(data) <= currOffset+n {
		return errBufferTooSmall
	}
	m.SessionID = append([]byte{}, data[currOffset:currOffset+n]...)
	currOffset += len(m.SessionID)

	currOffset++
	if len(data) <= currOffset {
		return errBufferTooSmall
	}
	n = int(data[currOffset-1])
	if len(data) <= currOffset+n {
		return errBufferTooSmall
	}
	m.Cookie = append([]byte{}, data[currOffset:currOffset+n]...)
	currOffset += len(m.Cookie)

	// Cipher Suites
	if len(data) < currOffset {
		return errBufferTooSmall
	}
	cipherSuiteIDs, err := utils.DecodeCipherSuiteIDs(data[currOffset:])
	if err != nil {
		return err
	}
	m.CipherSuiteIDs = cipherSuiteIDs
	if len(data) < currOffset+2 {
		return errBufferTooSmall
	}
	currOffset += int(binary.BigEndian.Uint16(data[currOffset:])) + 2

	// Compression Methods
	if len(data) < currOffset {
		return errBufferTooSmall
	}
	compressionMethods, err := protocol.DecodeCompressionMethods(data[currOffset:])
	if err != nil {
		return err
	}
	m.CompressionMethods = compressionMethods
	if len(data) < currOffset {
		return errBufferTooSmall
	}
	currOffset += int(data[currOffset]) + 1

	// Extensions
	extensions, err := RandomizeExtensionUnmarshal(data[currOffset:], r)
	if err != nil {
		return err
	}
	m.Extensions = extensions
	return nil
}
