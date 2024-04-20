package fingerprints

//nolint:revive,unused
type ClientHelloFingerprint string

// These fingerprints are added automatically generated and added by the 'fingerprint' workflow
// The first byte should correspond to the DTLS version in a handshake message
const (
	Google_Chrome_124_0_6367_60_unknown ClientHelloFingerprint = "fefda20ee7841620b36a9c1736ea6846255d7da83e9271816b0cc85b7f948951581700000016c02bc02fcca9cca8c009c013c00ac014009c002f00350100004400170000ff01000100000a00080006001d00170018000b0002010000230000000d00140012040308040401050308050501080606010201000e0009000600010008000700"                                                                 //nolint:revive,stylecheck
	Mozilla_Firefox_125_0_1             ClientHelloFingerprint = "fefdb22e77791af4658e6fa29c6d396dcdfe51f471e584744683e6c22bd251a2aba000000010c02bc02fcca9cca8c00ac009c013c0140100006a00170000ff01000100000a00080006001d00170018000b000201000010001200100677656272746308632d776562727463000d0020001e040305030603020308040805080604010501060102010402050206020202001c00024000000e000b0008000700080001000200" //nolint:revive,stylecheck
)

//nolint:unused
func getClientHelloFingerprints() []ClientHelloFingerprint {
	return []ClientHelloFingerprint{
		Google_Chrome_124_0_6367_60_unknown, //nolint:revive,stylecheck
		Mozilla_Firefox_125_0_1,             //nolint:revive,stylecheck
	}
}
