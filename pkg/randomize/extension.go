package randomize

import (
	"encoding/binary"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/theodorsm/covert-dtls/pkg/utils"
)

// TypeValue is the 2 byte value for a TLS Extension as registered in the IANA
//
// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
type TypeValue uint16

// TypeValue constants
const (
	ServerNameTypeValue                   TypeValue = 0
	SupportedEllipticCurvesTypeValue      TypeValue = 10
	SupportedPointFormatsTypeValue        TypeValue = 11
	SupportedSignatureAlgorithmsTypeValue TypeValue = 13
	UseSRTPTypeValue                      TypeValue = 14
	ALPNTypeValue                         TypeValue = 16
	UseExtendedMasterSecretTypeValue      TypeValue = 23
	ConnectionIDTypeValue                 TypeValue = 54
	RenegotiationInfoTypeValue            TypeValue = 65281
)

// Extension represents a single TLS extension
type Extension = extension.Extension

// Unmarshal many extensions at once, will randomize use_srtp, signature_algorithms and supported_groups.
func RandomizeExtensionUnmarshal(buf []byte) ([]Extension, error) {
	switch {
	case len(buf) == 0:
		return []Extension{}, nil
	case len(buf) < 2:
		return nil, errBufferTooSmall
	}

	declaredLen := binary.BigEndian.Uint16(buf)
	if len(buf)-2 != int(declaredLen) {
		return nil, errLengthMismatch
	}

	extensions := []Extension{}
	unmarshalAndAppend := func(data []byte, e Extension) error {
		err := e.Unmarshal(data)
		if err != nil {
			return err
		}
		extensions = append(extensions, e)
		return nil
	}

	for offset := 2; offset < len(buf); {
		if len(buf) < (offset + 2) {
			return nil, errBufferTooSmall
		}
		var err error
		switch TypeValue(binary.BigEndian.Uint16(buf[offset:])) {
		case ServerNameTypeValue:
			err = unmarshalAndAppend(buf[offset:], &extension.ServerName{})
		case SupportedEllipticCurvesTypeValue:
			e := &extension.SupportedEllipticCurves{}
			err = e.Unmarshal(buf[offset:])
			if err != nil {
				return nil, err
			}
			e.EllipticCurves = utils.ShuffleRandomLength(e.EllipticCurves, true)
			extensions = append(extensions, e)
		case SupportedPointFormatsTypeValue:
			err = unmarshalAndAppend(buf[offset:], &extension.SupportedPointFormats{})
		case SupportedSignatureAlgorithmsTypeValue:
			e := &extension.SupportedSignatureAlgorithms{}
			err = e.Unmarshal(buf[offset:])
			if err != nil {
				return nil, err
			}
			e.SignatureHashAlgorithms = utils.ShuffleRandomLength(e.SignatureHashAlgorithms, true)
			extensions = append(extensions, e)
		case UseSRTPTypeValue:
			e := &extension.UseSRTP{}
			err = e.Unmarshal(buf[offset:])
			if err != nil {
				return nil, err
			}
			e.ProtectionProfiles = utils.ShuffleRandomLength(e.ProtectionProfiles, true)
			extensions = append(extensions, e)
		case ALPNTypeValue:
			err = unmarshalAndAppend(buf[offset:], &extension.ALPN{})
		case UseExtendedMasterSecretTypeValue:
			err = unmarshalAndAppend(buf[offset:], &extension.UseExtendedMasterSecret{})
		case RenegotiationInfoTypeValue:
			err = unmarshalAndAppend(buf[offset:], &extension.RenegotiationInfo{})
		default:
		}
		if err != nil {
			return nil, err
		}
		if len(buf) < (offset + 4) {
			return nil, errBufferTooSmall
		}
		extensionLength := binary.BigEndian.Uint16(buf[offset+2:])
		offset += (4 + int(extensionLength))
	}
	return extensions, nil
}

// Marshal many extensions at once
func RandomizeExtensionMarshal(e []Extension) ([]byte, error) {
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
