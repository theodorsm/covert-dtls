package randomize

import (
	"encoding/binary"

	"github.com/pion/dtls/v3/pkg/crypto/hash"
	"github.com/pion/dtls/v3/pkg/crypto/signature"
	"github.com/pion/dtls/v3/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v3/pkg/protocol/extension"
	"github.com/theodorsm/covert-dtls/pkg/utils"
)

// ecdsaP256SHA256 is the ECDSA P-256 / SHA-256 signature algorithm used by
// pion's default self-signed certificates.
var ecdsaP256SHA256 = signaturehash.Algorithm{
	Hash:      hash.SHA256,
	Signature: signature.ECDSA,
}

// RandomizeExtensionUnmarshal unmarshals many extensions at once, randomizing
// use_srtp, signature_algorithms and supported_groups using r. Passing a
// seeded Rand makes the randomization reproducible.
func RandomizeExtensionUnmarshal(buf []byte, r utils.Rand) ([]extension.Extension, error) {
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
			e.EllipticCurves = utils.ShuffleRandomLength(e.EllipticCurves, true, r)
			extensions = append(extensions, e)
		case extension.SupportedPointFormatsTypeValue:
			err = unmarshalAndAppend(buf[offset:], &extension.SupportedPointFormats{})
		case extension.SupportedSignatureAlgorithmsTypeValue:
			e := &extension.SupportedSignatureAlgorithms{}
			err = e.Unmarshal(buf[offset:])
			if err != nil {
				return nil, err
			}
			e.SignatureHashAlgorithms = utils.ShuffleRandomLength(e.SignatureHashAlgorithms, true, r)
			// Ensure ECDSA P-256 / SHA-256 is present and first so pion's
			// default ECDSA P-256 certificates remain usable after
			// randomization.
			pinECDSAP256(&e.SignatureHashAlgorithms)
			extensions = append(extensions, e)
		case extension.UseSRTPTypeValue:
			e := &extension.UseSRTP{}
			err = e.Unmarshal(buf[offset:])
			if err != nil {
				return nil, err
			}
			e.ProtectionProfiles = utils.ShuffleRandomLength(e.ProtectionProfiles, true, r)
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

// pinECDSAP256 ensures ecdsaP256SHA256 is present at index 0 of algs. If it is
// present elsewhere it is moved to the front; if it was truncated away by
// randomization it is prepended. This keeps randomized ClientHellos compatible
// with pion's default ECDSA P-256 certificates.
func pinECDSAP256(algs *[]signaturehash.Algorithm) {
	for i, alg := range *algs {
		if alg.Hash == ecdsaP256SHA256.Hash && alg.Signature == ecdsaP256SHA256.Signature {
			if i != 0 {
				(*algs)[0], (*algs)[i] = (*algs)[i], (*algs)[0]
			}
			return
		}
	}

	*algs = append([]signaturehash.Algorithm{ecdsaP256SHA256}, *algs...)
}
