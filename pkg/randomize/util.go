package randomize

import (
	"math/rand/v2"
)

// nolint:typecheck
func randRange(min, max int) int {
	return rand.IntN(max-min) + min
}

var ALPNS = []string{"http/1.0", "http/1.1", "h2c", "h2", "h3", "stun.turn", "webrtc", "c-webrtc", "ftp", "pop3", "imap", "mqtt", "smb", "irc", "sip/2"}

func ShuffleSlice[T any](s []T, randomLen bool) []T {
	var out = []T{}
	tmp := make([]T, len(s))
	_ = copy(tmp, s)
	var i int
	if randomLen {
		i = randRange(1, len(tmp))
	} else {
		i = len(tmp)
	}
	for i > 0 {
		pick := randRange(0, len(tmp))
		out = append(out, tmp[pick])
		tmp = append(tmp[:pick], tmp[pick+1:]...)
		i--
	}
	return out
}
