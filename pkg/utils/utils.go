package utils

import (
	"github.com/pion/dtls/v3"
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
