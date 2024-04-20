package fingerprints

//nolint:revive,unused
type ClientHelloFingerprint string

// These fingerprints are added automatically generated and added by the 'fingerprint' workflow
// The first byte should correspond to the DTLS version in a handshake message
const (
	Google_Chrome_124_0_6367_60_unknown ClientHelloFingerprint = "fefd1e58f339342e145c3ce9ac827d15dbc1d7416b97e564fd5a0b45726b5fe272c000000016c02bc02fcca9cca8c009c013c00ac014009c002f00350100004400170000ff01000100000a00080006001d00170018000b0002010000230000000d00140012040308040401050308050501080606010201000e0009000600010008000700"                                                                 //nolint:revive,stylecheck
	Mozilla_Firefox_125_0_1             ClientHelloFingerprint = "fefdf8ae66cea676a21d364ac5bf6b4826ab1ceb739ed86bb17c0fef981b0596492c00000010c02bc02fcca9cca8c00ac009c013c0140100006a00170000ff01000100000a00080006001d00170018000b000201000010001200100677656272746308632d776562727463000d0020001e040305030603020308040805080604010501060102010402050206020202001c00024000000e000b0008000700080001000200" //nolint:revive,stylecheck
)

//nolint:unused
func getClientHelloFingerprints() []ClientHelloFingerprint {
	return []ClientHelloFingerprint{
		Google_Chrome_124_0_6367_60_unknown, //nolint:revive,stylecheck
		Mozilla_Firefox_125_0_1,             //nolint:revive,stylecheck
	}
}
