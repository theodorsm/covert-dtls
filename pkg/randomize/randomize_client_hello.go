package randomize

import (
	"encoding/binary"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/pion/dtls/v3/pkg/protocol/handshake"
)

/*
RandomizedMessageClientHello
*/
type RandomizedMessageClientHello struct {
	Version    protocol.Version
	Random     handshake.Random
	Cookie     []byte
	RandomALPN bool // Add a random ALPN if there is none in the hooked message

	SessionID []byte

	CipherSuiteIDs     []uint16
	CompressionMethods []*protocol.CompressionMethod
	Extensions         []Extension
}

const handshakeMessageClientHelloVariableWidthStart = 34

// Type returns the Handshake Type
func (m RandomizedMessageClientHello) Type() handshake.Type {
	return handshake.TypeClientHello
}

// ClientHello Hook for randomization
func (m *RandomizedMessageClientHello) Hook(ch handshake.MessageClientHello) handshake.Message {
	buf, err := ch.Marshal()
	if err != nil {
		return &ch
	}
	err = m.Unmarshal(buf)
	if err != nil {
		return &ch
	}
	m.CipherSuiteIDs = ShuffleRandomLength(m.CipherSuiteIDs, true)

	hasALPN := false
	for _, e := range m.Extensions {
		if e.TypeValue() == extension.TypeValue(ALPNTypeValue) {
			hasALPN = true
		}
	}
	if !hasALPN && m.RandomALPN {
		e := &extension.ALPN{
			ProtocolNameList: []string{ALPNS[randRange(0, len(ALPNS)-1)]},
		}
		m.Extensions = append(m.Extensions, e)
	}

	m.Extensions = ShuffleRandomLength(m.Extensions, false)
	return m
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
	out = append(out, encodeCipherSuiteIDs(m.CipherSuiteIDs)...)
	out = append(out, protocol.EncodeCompressionMethods(m.CompressionMethods)...)
	extensions, err := RandomizeExtensionMarshal(m.Extensions)
	if err != nil {
		return nil, err
	}

	return append(out, extensions...), nil
}

// Unmarshal populates the message from encoded data
func (m *RandomizedMessageClientHello) Unmarshal(data []byte) error {
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
	cipherSuiteIDs, err := decodeCipherSuiteIDs(data[currOffset:])
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
	extensions, err := RandomizeExtensionUnmarshal(data[currOffset:])
	if err != nil {
		return err
	}
	m.Extensions = extensions
	return nil
}
