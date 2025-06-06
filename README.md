# covertDTLS

covertDTLS is a library inspired by [uTLS](https://github.com/refraction-networking/utls) for offering fingerprint-resistance features to [pion/dtls](https://github.com/pion/dtls).

## Why does this library exists?

The censorship circumvention system [Snowflake](https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake) has previously been blocked by fingerprinting the DTLS handshake. This library is a module that extends the `pion/dtls` library by hooking and manipulating handshake messages to make them indistinguishable from other DTLS implementations used for WebRTC traffic. 

## Fingerprint generation

This repo contains a workflow ([.github/workflows/fingerprint.yaml](.github/workflows/fingerprint.yaml)) for automatically generating fresh DTLS 1.2 handshakes (fingerprints) of new browser versions (Firefox and Chrome) by using a minimal WebRTC example application and Selenium. Fresh handshakes are captured each day and stored as pcap artifacts and the [fingerprints-captures](fingerprints-captures) directory. The pcaps are further parsed and a fingerprint is added to [pkg/mimicry/fingerprints.go](pkg/mimicry/fingerprints.go). Some DTLS 1.3 fingerprints are found in [pkg/mimicry/fingerprints_13.go](pkg/mimicry/fingerprints_13.go)

[main.go](main.go) contains a script for parsing pcaps, extracting the fingerprints and adding them to [pkg/mimicry/fingerprints.go](pkg/mimicry/fingerprints.go)

## Validation

This library was developed as part of a Master thesis: "*[Reducing distinguishability of DTLS for usage in Snowflake](https://theodorsm.net/thesis)"*. Additionally, *[dfind](https://github.com/theodorsm/dfind)* was created for analyzing and finding passive field-based fingerprints of DTLS. *dfind* was used to validate this library, finding that mimicked *ClientHello* messages was indistinguishable from the fresh browser handshakes . Analysis also found that randomization of extensions was especially effective against fingerprinting, while randomization of ciphers has potential, but must be configured properly. To provide more effective randomization, it is recommended to use this library with **configuring as many supported ciphers as possible** (using `Config.CipherSuites`).

## Features

- Mimicking/replaying *ClientHello*
  - key_share with fake keys (DTLS 1.3). *This feature is highly experimental and unstable: do NOT expect handshake to be completed successfully*.
- Randomization of *ClientHello* 
  - cipher suites: shuffle and random size
  - extensions: shuffle
  - `use_srtp`: shuffle and random size
  - `supported_groups`: shuffle and random size
  - `signature_algorithm`: shuffle and random size
  - ALPN: add random ALPN of common protocols

*Note*: using these features might make handshakes unstable as unsupported features might be announced in the *ClientHello* message.

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
  "github.com/theodorsm/covert-dtls/pkg/utils"
)

// Get a specific fingerprint
fingerprint := fingerprints.Mozilla_Firefox_125_0_1

clientHello := mimicry.MimickedClientHello{}

// If no specific fingerprint is loaded, the most recent one will be used
clientHello.LoadFingerprint(fingerprint)

cfg := &dtls.Config{
    // SRTP needs to be enabled as the fingerprints are from webrtc traffic, thus containing the use_srtp extension.
    SRTPProtectionProfiles: utils.DefaultSRTPProtectionProfiles(),
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
    // Enable all ciphers for making randomization more effective. Optional step.
    CipherSuites: randomize.DefaultCipherSuites() ,
    ClientHelloMessageHook: clientHello.Hook,
}

// Use config with connection...
```
