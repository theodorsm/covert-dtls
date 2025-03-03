package utils

import (
	"encoding/binary"

	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

type FakeExt struct {
	FakeTypeValue extension.TypeValue
	Bytes         []byte
}

func (f FakeExt) TypeValue() extension.TypeValue {
	return f.FakeTypeValue
}

func (f FakeExt) Marshal() ([]byte, error) {
	return f.Bytes, nil
}

func (f FakeExt) Unmarshal(data []byte) error {
	if len(data) < 2 {
		return errBufferTooSmall
	}
	f.FakeTypeValue = extension.TypeValue(binary.BigEndian.Uint16(data))
	f.Bytes = data
	return nil
}
