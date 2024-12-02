package randomize

import (
	"crypto/rand"
	"math/big"
)

func randRange(min, max int) int {
	bigRandomNumber, err := rand.Int(rand.Reader, big.NewInt(int64(max+1)))
	if err != nil {
		panic(err)
	}
	randomNumber := int(bigRandomNumber.Int64())
	if randomNumber < min {
		return min
	}
	return randomNumber
}

var ALPNS = []string{"http/1.0", "http/1.1", "h2c", "h2", "h3", "stun.turn", "webrtc", "c-webrtc", "ftp", "pop3", "imap", "mqtt", "smb", "irc", "sip/2"}

func ShuffleRandomLength[T any](s []T, randomLen bool) []T {
	var out = []T{}
	if len(s) == 0 {
		return s
	}
	tmp := make([]T, len(s))
	_ = copy(tmp, s)
	var n int
	if randomLen {
		n = randRange(1, len(tmp))
	} else {
		n = len(tmp)
	}
	for len(out) < n {
		pick := randRange(0, len(tmp)-1)
		out = append(out, tmp[pick])
		tmp = remove(tmp, pick)
	}
	return out
}

func remove[T any](s []T, index int) []T {
	ret := make([]T, 0)
	ret = append(ret, s[:index]...)
	return append(ret, s[index+1:]...)
}
