package utils

import (
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol/extension"
)

// The last extension in a buffer, whose declared length exactly consumes the
// remaining bytes, must be accepted rather than rejected.
func TestFakeExtUnmarshalLastExtension(t *testing.T) {
	// type 0xabcd, declared length 2, 2-byte body -> 6 bytes total.
	data := []byte{0xab, 0xcd, 0x00, 0x02, 0xaa, 0xbb}

	var f FakeExt
	if err := f.Unmarshal(data); err != nil {
		t.Fatalf("Unmarshal of a full-buffer extension failed: %v", err)
	}
	if f.FakeTypeValue != extension.TypeValue(0xabcd) {
		t.Fatalf("unexpected type 0x%x", uint16(f.FakeTypeValue))
	}
	if len(f.Bytes) != len(data) {
		t.Fatalf("expected %d bytes, got %d", len(data), len(f.Bytes))
	}
}

// A declared length that exceeds the buffer must still be rejected.
func TestFakeExtUnmarshalRejectsOverlong(t *testing.T) {
	// declared length 0x10 (16) but only 2 body bytes present.
	data := []byte{0xab, 0xcd, 0x00, 0x10, 0xaa, 0xbb}

	var f FakeExt
	if err := f.Unmarshal(data); err == nil {
		t.Fatalf("expected error for over-long declared length, got nil")
	}
}
