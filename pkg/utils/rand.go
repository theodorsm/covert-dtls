package utils

import (
	"crypto/rand"
	"math/big"
)

// Rand is the source of randomness used by the randomization and mimicry
// packages. It is intentionally small so that callers can supply their own
// implementation: passing a seeded, reproducible source enables deterministic
// replay of a randomized or mimicked handshake, while the default
// implementation draws from crypto/rand.
//
// The interface is satisfied by *math/rand.Rand and by any seeded PRNG that
// exposes Intn and Shuffle with these signatures.
type Rand interface {
	// Intn returns a non-negative pseudo-random int in the half-open interval
	// [0,n). It panics if n <= 0, matching the semantics of math/rand.Intn.
	Intn(n int) int
	// Shuffle pseudo-randomizes the order of n elements, calling swap to swap
	// the elements with indexes i and j.
	Shuffle(n int, swap func(i, j int))
}

// DefaultRand returns a Rand backed by crypto/rand. It is non-deterministic
// and safe for concurrent use.
func DefaultRand() Rand {
	return cryptoRand{}
}

// cryptoRand is the default Rand implementation, backed by crypto/rand.
type cryptoRand struct{}

// Intn returns a uniform random int in [0,n). It panics if n <= 0.
func (cryptoRand) Intn(n int) int {
	if n <= 0 {
		panic("utils: Intn requires n > 0")
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		// crypto/rand.Reader failing is catastrophic and not something a
		// circumvention handshake can meaningfully recover from.
		panic(err)
	}
	return int(v.Int64())
}

// Shuffle randomizes the order of n elements using a Fisher-Yates shuffle,
// matching the semantics of math/rand.Shuffle.
func (c cryptoRand) Shuffle(n int, swap func(i, j int)) {
	for i := n - 1; i > 0; i-- {
		swap(i, c.Intn(i+1))
	}
}
