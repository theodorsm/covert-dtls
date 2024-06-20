# covertDTLS

covertDTLS is a library inspired by [uTLS](https://github.com/refraction-networking/utls) for offering fingerprint-resistance features to [pion/dtls](https://github.com/pion/dtls).

## Why does this library exists?

The censorship circumvention system [Snowflake](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake) has previously been blocked by fingerprinting the DTLS handshake. This library is a module that extends the `pion/dtls` library by hooking and manipulating handshake messages to make them indistinguishable from other DTLS implementations used for WebRTC traffic.

## Fingerprint generation

This repo contains a workflow ([.github/workflows/fingerprint.yaml](.github/workflows/fingerprint.yaml)) for automatically generating fresh DTLS handshakes (fingerprints) of new browser versions (Firefox and Chrome) by using a minimal WebRTC example application and Selenium. Fresh handshakes are captured each day and stored as pcap artifacts and the [fingerprints-captures](fingerprints-captures) directory. The pcaps are further parsed and a fingerprint is added to [pkg/mimicry/fingerprints.go](pkg/mimicry/fingerprints.go)

## Features

- Mimicking/replaying *ClientHello*s
- Randomization of *ClientHello*s
  - cipher suites: shuffle and random size
  - extensions: shuffle
  - `use_srtp`: shuffle and random size
  - `supported_groups`: shuffle and random size
  - `signature_algorithm`: shuffle and random size
  - ALPN: add random ALPN of common protocols

### Planned

- Mimicking *ServerHello*
- Mimicking *CertificateRequest*

## Examples

### Mimicry
```go
import  (
  "github.com/pion/dtls/v2"
  "github.com/theodorsm/covert-dtls/pkg/fingerprints"
  "github.com/theodorsm/covert-dtls/pkg/mimicry"
)

// Get a specific fingerprint
fingerprint := fingerprints.Mozilla_Firefox_125_0_1

clientHello := mimicry.MimickedClientHello{}

// If no specific fingerprint is loaded, the most recent one will be used
clientHello.LoadFingerprint(fingerprint)

cfg := &dtls.Config{
    // SRTP needs to be enabled as the fingerprints are from webrtc traffic, thus containing the use_srtp extension.
    SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtls.SRTP_AES128_CM_HMAC_SHA1_80, dtls.SRTP_AES128_CM_HMAC_SHA1_32, dtls.SRTP_AEAD_AES_128_GCM, dtls.SRTP_AEAD_AES_256_GCM},
    ClientHelloMessageHook: clientHello.Hook,
}

// Use config with connection...
```

### Randomization
```go
import  (
  "github.com/pion/dtls/v2"
  "github.com/theodorsm/covert-dtls/pkg/randomize"
)

clientHello := randomize.RandomizedMessageClientHello{RandomALPN: true}

cfg := &dtls.Config{
    ClientHelloMessageHook: clientHello.Hook,
}

// Use config with connection...
```
