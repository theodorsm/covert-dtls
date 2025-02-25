package utils

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"math/big"
)

func RandRange(min, max int) int {
	bigRandomNumber, err := rand.Int(rand.Reader, big.NewInt(int64(max+1)))
	if err != nil {
		panic(err)
	}
	randomNumber := int(bigRandomNumber.Int64())
	if randomNumber < min {
		return min
	}
	return randomNumber
}

var ALPNS = []string{"http/1.0", "http/1.1", "h2c", "h2", "h3", "stun.turn", "webrtc", "c-webrtc", "ftp", "pop3", "imap", "mqtt", "smb", "irc", "sip/2"}

func ShuffleRandomLength[T any](s []T, randomLen bool) []T {
	var out = []T{}
	if len(s) == 0 {
		return s
	}
	tmp := make([]T, len(s))
	_ = copy(tmp, s)
	var n int
	if randomLen {
		n = RandRange(1, len(tmp))
	} else {
		n = len(tmp)
	}
	for len(out) < n {
		pick := RandRange(0, len(tmp)-1)
		out = append(out, tmp[pick])
		tmp = remove(tmp, pick)
	}
	return out
}

func remove[T any](s []T, index int) []T {
	ret := make([]T, 0)
	ret = append(ret, s[:index]...)
	return append(ret, s[index+1:]...)
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
