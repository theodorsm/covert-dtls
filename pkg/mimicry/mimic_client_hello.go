package mimicry

import (
	"encoding/hex"
	"errors"

	"github.com/pion/dtls/v2/pkg/protocol/extension"
	"github.com/pion/dtls/v2/pkg/protocol/handshake"
	"github.com/theodorsm/dtls-webrtc-fingerprint/pkg/fingerprints"
)

var errBufferTooSmall = errors.New("buffer is too small") //nolint:goerr113

// MimickedClientHello is to be used as a way to replay DTLS client hello messages. To be used with the Pion dtls library.
type MimickedClientHello struct {
	clientHelloFingerprint fingerprints.ClientHelloFingerprint
	Random                 handshake.Random
	SessionID              []byte
	Cookie                 []byte
	Extensions             []extension.Extension
	SRTPProtectionProfiles []extension.SRTPProtectionProfile
}

func (m *MimickedClientHello) Hook(random handshake.Random, sessionID []byte, cookie []byte) handshake.Message {
	m.Random = random
	m.SessionID = sessionID
	m.Cookie = cookie
	return m
}

//nolint:revive
func (m MimickedClientHello) Type() handshake.Type {
	return handshake.TypeClientHello
}

func (m *MimickedClientHello) LoadFingerprint(fingerprint fingerprints.ClientHelloFingerprint) error {
	m.clientHelloFingerprint = fingerprint
	clientHello := handshake.MessageClientHello{}
	data, err := hex.DecodeString(string(m.clientHelloFingerprint))
	if err != nil {
		return errors.New("mimicry: failed to decode mimicry hexstring") //nolint:goerr113
	}
	err = clientHello.Unmarshal(data)
	if err != nil {
		return err
	}
	m.Extensions = clientHello.Extensions
	for _, ext := range m.Extensions {
		if ext.TypeValue() == extension.UseSRTPTypeValue {
			srtp := extension.UseSRTP{}
			buf, err := ext.Marshal()
			if err != nil {
				return err
			}
			err = srtp.Unmarshal(buf)
			if err != nil {
				return err
			}
			m.SRTPProtectionProfiles = srtp.ProtectionProfiles
		}
	}
	return nil
}

//nolint:revive
func (m *MimickedClientHello) Marshal() ([]byte, error) {
	var out []byte

	fingerprint := m.clientHelloFingerprint

	if string(fingerprint) == "" {
		fingerprints := fingerprints.GetClientHelloFingerprints()
		if len(fingerprints) < 1 {
			return out, errors.New("no fingerprints available") //nolint:goerr113
		}
		fingerprint = fingerprints[len(fingerprints)-1]
		m.LoadFingerprint(fingerprint)
	}

	data, err := hex.DecodeString(string(fingerprint))
	if err != nil {
		err = errors.New("mimicry: failed to decode mimicry hexstring") //nolint:goerr113
	}

	if len(data) <= 2 {
		return out, errors.New("mimicked fingerprint is too short") //nolint:goerr113
	}

	// Major and minor version
	currOffset := 2
	out = append(out, data[:currOffset]...)

	rb := m.Random.MarshalFixed()
	out = append(out, rb[:]...)

	// Skip past random
	currOffset += 32

	currOffset++
	if len(data) <= currOffset {
		return out, errBufferTooSmall
	}
	n := int(data[currOffset-1])
	if len(data) <= currOffset+n {
		return out, errBufferTooSmall
	}
	mimickedSessionID := append([]byte{}, data[currOffset:currOffset+n]...)
	currOffset += len(mimickedSessionID)

	currOffset++
	if len(data) <= currOffset {
		return out, errBufferTooSmall
	}
	n = int(data[currOffset-1])
	if len(data) <= currOffset+n {
		return out, errBufferTooSmall
	}
	mimickedCookie := append([]byte{}, data[currOffset:currOffset+n]...)
	currOffset += len(mimickedCookie)

	out = append(out, byte(len(m.SessionID)))
	out = append(out, m.SessionID...)

	out = append(out, byte(len(m.Cookie)))
	out = append(out, m.Cookie...)

	out = append(out, data[currOffset:]...)

	return out, err
}

//nolint:revive
func (m *MimickedClientHello) Unmarshal(data []byte) error { return nil }
