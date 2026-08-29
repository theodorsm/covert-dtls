package utils

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

func DefaultSRTPProtectionProfiles() []dtls.SRTPProtectionProfile {
	return []dtls.SRTPProtectionProfile{
		dtls.SRTP_AES128_CM_HMAC_SHA1_80,
		dtls.SRTP_AES128_CM_HMAC_SHA1_32,
		dtls.SRTP_AES256_CM_SHA1_80,
		dtls.SRTP_AES256_CM_SHA1_32,
		dtls.SRTP_NULL_HMAC_SHA1_80,
		dtls.SRTP_NULL_HMAC_SHA1_32,
		dtls.SRTP_AEAD_AES_128_GCM,
		dtls.SRTP_AEAD_AES_256_GCM,
	}
}

var ALPNS = []string{"http/1.0", "http/1.1", "h2c", "h2", "h3", "stun.turn", "webrtc", "c-webrtc", "ftp", "pop3", "imap", "mqtt", "smb", "irc", "sip/2"}

// ShuffleRandomLength shuffles s using r and, when randomLen is true, randomly
// truncates the result. Truncation uses a coin-flip (geometric) distribution
// biased toward keeping more elements: at least one element is always kept.
// Passing a seeded Rand makes both the ordering and the truncation length
// reproducible.
func ShuffleRandomLength[T any](s []T, randomLen bool, r Rand) []T {
	if len(s) == 0 {
		return s
	}

	result := make([]T, len(s))
	copy(result, s)

	r.Shuffle(len(result), func(i, j int) {
		result[i], result[j] = result[j], result[i]
	})

	if randomLen {
		// Each coin flip decides whether to drop one more element from the
		// end. This keeps at least one element and is biased toward keeping
		// more, which is safer for handshake compatibility than uniform
		// truncation.
		n := len(result)
		for n > 1 && r.Intn(2) == 1 {
			n--
		}
		result = result[:n]
	}

	return result
}

// GenerateRandomP256PublicKey generates a random valid secp256r1 public key
func GenerateRandomP256PublicKey() (*ecdh.PublicKey, error) {
	curve := ecdh.P256()

	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	return privateKey.PublicKey(), nil
}

// GenerateRandomPublicKey generates a random valid X25519 public key
func GenerateRandomX25519PublicKey() (*ecdh.PublicKey, error) {
	curve := ecdh.X25519()

	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	return privateKey.PublicKey(), nil
}

// Marshal many extensions at once
func ExtensionMarshal(e []extension.Extension) ([]byte, error) {
	extensions := []byte{}
	for _, e := range e {
		raw, err := e.Marshal()
		if err != nil {
			return nil, err
		}
		extensions = append(extensions, raw...)
	}
	out := []byte{0x00, 0x00}
	binary.BigEndian.PutUint16(out, uint16(len(extensions)))
	return append(out, extensions...), nil
}
