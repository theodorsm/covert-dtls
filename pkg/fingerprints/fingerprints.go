package fingerprints

//nolint:revive,unused
type ClientHelloFingerprint string

// These fingerprints are added automatically generated and added by the 'fingerprint' workflow
// The first byte should correspond to the DTLS version in a handshake message
const (
	Google_Chrome_124_0_6367_60_unknown ClientHelloFingerprint = "fefda2c9b6b6d40048658f5944cc714a3450e0c36961b6745a04d235242adb5ccc0100000016c02bc02fcca9cca8c009c013c00ac014009c002f00350100004400170000ff01000100000a00080006001d00170018000b0002010000230000000d00140012040308040401050308050501080606010201000e0009000600010008000700"                                                                 //nolint:revive,stylecheck
	Mozilla_Firefox_125_0_1             ClientHelloFingerprint = "fefd187d9d39b8fde4410f1c95d278667938efe98260e6a0973885ec0368c19b2fc100000010c02bc02fcca9cca8c00ac009c013c0140100006a00170000ff01000100000a00080006001d00170018000b000201000010001200100677656272746308632d776562727463000d0020001e040305030603020308040805080604010501060102010402050206020202001c00024000000e000b0008000700080001000200" //nolint:revive,stylecheck
)

//nolint:unused
func GetClientHelloFingerprints() []ClientHelloFingerprint {
	return []ClientHelloFingerprint{
		Google_Chrome_124_0_6367_60_unknown, //nolint:revive,stylecheck
		Mozilla_Firefox_125_0_1,             //nolint:revive,stylecheck
	}
}
