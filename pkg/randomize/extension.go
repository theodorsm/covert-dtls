package randomize

import (
	"encoding/binary"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/theodorsm/covert-dtls/pkg/utils"
)

// Unmarshal many extensions at once, will randomize use_srtp, signature_algorithms and supported_groups.
func RandomizeExtensionUnmarshal(buf []byte) ([]extension.Extension, error) {
	switch {
	case len(buf) == 0:
		return []extension.Extension{}, nil
	case len(buf) < 2:
		return nil, errBufferTooSmall
	}

	declaredLen := binary.BigEndian.Uint16(buf)
	if len(buf)-2 != int(declaredLen) {
		return nil, errLengthMismatch
	}

	extensions := []extension.Extension{}
	unmarshalAndAppend := func(data []byte, e extension.Extension) error {
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
		switch extension.TypeValue(binary.BigEndian.Uint16(buf[offset:])) {
		case extension.ServerNameTypeValue:
			err = unmarshalAndAppend(buf[offset:], &extension.ServerName{})
		case extension.SupportedEllipticCurvesTypeValue:
			e := &extension.SupportedEllipticCurves{}
			err = e.Unmarshal(buf[offset:])
			if err != nil {
				return nil, err
			}
			e.EllipticCurves = utils.ShuffleRandomLength(e.EllipticCurves, true)
			extensions = append(extensions, e)
		case extension.SupportedPointFormatsTypeValue:
			err = unmarshalAndAppend(buf[offset:], &extension.SupportedPointFormats{})
		case extension.SupportedSignatureAlgorithmsTypeValue:
			e := &extension.SupportedSignatureAlgorithms{}
			err = e.Unmarshal(buf[offset:])
			if err != nil {
				return nil, err
			}
			e.SignatureHashAlgorithms = utils.ShuffleRandomLength(e.SignatureHashAlgorithms, true)
			extensions = append(extensions, e)
		case extension.UseSRTPTypeValue:
			e := &extension.UseSRTP{}
			err = e.Unmarshal(buf[offset:])
			if err != nil {
				return nil, err
			}
			e.ProtectionProfiles = utils.ShuffleRandomLength(e.ProtectionProfiles, true)
			extensions = append(extensions, e)
		case extension.ALPNTypeValue:
			err = unmarshalAndAppend(buf[offset:], &extension.ALPN{})
		case extension.UseExtendedMasterSecretTypeValue:
			err = unmarshalAndAppend(buf[offset:], &extension.UseExtendedMasterSecret{})
		case extension.RenegotiationInfoTypeValue:
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
