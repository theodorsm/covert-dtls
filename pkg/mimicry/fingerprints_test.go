package mimicry

import (
	"testing"

	"github.com/theodorsm/covert-dtls/pkg/fingerprints"
)

func TestLoadFingerprints(t *testing.T) {
	for _, fingerprint := range fingerprints.GetClientHelloFingerprints() {
		m := &MimickedClientHello{}
		err := m.LoadFingerprint(fingerprint)
		if err != nil {
			t.Errorf("Load failed for fingerprint: %v, with error: %v\n", fingerprint, err)
		}
	}

}
