package utils

import (
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

const (
	keyShareHeaderSize                      = 6
	KeyGroupP256Value                       = 23
	KeyGroupX25519Value                     = 29
	KeyShareTypeValue   extension.TypeValue = 51
)

var (
	errKeyLength = errors.New("generated key length does not match")
	errRandomKey = errors.New("error while generating random key")
)

type KeyShareEntry struct {
	group     uint16
	keyLength uint16
	key       []byte
}

type KeyShare struct {
	KeyShareEntries []KeyShareEntry
}

func (k KeyShare) TypeValue() extension.TypeValue {
	return KeyShareTypeValue
}

// Marshal with fresh random keys
func (k KeyShare) Marshal() ([]byte, error) {
	out := make([]byte, keyShareHeaderSize)

	binary.BigEndian.AppendUint16(out, uint16(k.TypeValue()))

	var tmp []byte
	for _, entry := range k.KeyShareEntries {
		tmp = append(tmp, byte(entry.group))
		tmp = append(tmp, byte(entry.keyLength))
		switch entry.group {
		case uint16(KeyGroupX25519Value):
			key, err := GenerateRandomX25519PublicKey()
			if err != nil {
				return []byte{}, nil
			}
			if len(key.Bytes()) != int(entry.keyLength) {
				return []byte{}, nil
			}
			tmp = append(tmp, key.Bytes()...)
		case uint16(KeyGroupP256Value):
			key, err := GenerateRandomX25519PublicKey()
			if err != nil {
				return []byte{}, nil
			}
			if len(key.Bytes()) != int(entry.keyLength) {
				return []byte{}, nil
			}
			tmp = append(tmp, key.Bytes()...)
		default:
			key := make([]byte, entry.keyLength)
			_, err := rand.Read(key)
			if err != nil {
				return []byte{}, errRandomKey
			}
			tmp = append(tmp, key...)
		}
	}

	binary.BigEndian.AppendUint16(out, uint16(len(tmp)))
	binary.BigEndian.AppendUint16(out, uint16(len(tmp)-2))
	out = append(tmp, out...)

	return out, nil
}

func (k KeyShare) Unmarshal(data []byte) error {
	return nil
}
