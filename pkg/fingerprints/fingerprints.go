package fingerprints

//nolint:revive,unused
type ClientHelloFingerprint string

// These fingerprints are added automatically generated and added by the 'fingerprint' workflow
// The first byte should correspond to the DTLS version in a handshake message
const (
	Google_Chrome_124_0_6367_60_unknown ClientHelloFingerprint = "fefdfb488cdc1fcbdc745fc66be4ccf7b1b94302f086bc993bfea9ddd13acb560ba000000016c02bc02fcca9cca8c009c013c00ac014009c002f00350100004400170000ff01000100000a00080006001d00170018000b0002010000230000000d00140012040308040401050308050501080606010201000e0009000600010008000700"                                                                 //nolint:revive,stylecheck
	Mozilla_Firefox_125_0_1             ClientHelloFingerprint = "fefd6bb83b8242cde1d88cf63b1561439f2481d61529857c52838b5e6dcb3dd3007400000010c02bc02fcca9cca8c00ac009c013c0140100006a00170000ff01000100000a00080006001d00170018000b000201000010001200100677656272746308632d776562727463000d0020001e040305030603020308040805080604010501060102010402050206020202001c00024000000e000b0008000700080001000200" //nolint:revive,stylecheck
)

//nolint:unused
func getClientHelloFingerprints() []ClientHelloFingerprint {
	return []ClientHelloFingerprint{
		Google_Chrome_124_0_6367_60_unknown, //nolint:revive,stylecheck
		Mozilla_Firefox_125_0_1,             //nolint:revive,stylecheck
	}
}
