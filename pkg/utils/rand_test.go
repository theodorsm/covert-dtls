package utils

import (
	"math/rand"
	"testing"
)

// *rand.Rand must satisfy the Rand interface, which is what allows callers to
// supply a seeded, reproducible randomness source.
var _ Rand = (*rand.Rand)(nil)

func TestCryptoRandIntn(t *testing.T) {
	r := DefaultRand()
	for i := 0; i < 1000; i++ {
		v := r.Intn(10)
		if v < 0 || v >= 10 {
			t.Fatalf("Intn(10) returned out-of-range value %d", v)
		}
	}
}

func TestCryptoRandIntnPanicsOnNonPositive(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatalf("Intn(0) did not panic")
		}
	}()
	DefaultRand().Intn(0)
}

func TestCryptoRandShuffle(t *testing.T) {
	// A permutation must preserve the multiset of elements.
	input := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	got := make([]int, len(input))
	copy(got, input)
	DefaultRand().Shuffle(len(got), func(i, j int) { got[i], got[j] = got[j], got[i] })

	sum := 0
	for _, v := range got {
		sum += v
	}
	if sum != 55 {
		t.Fatalf("Shuffle did not preserve elements, sum = %d", sum)
	}
}

// A seeded Rand must produce identical ShuffleRandomLength output across runs,
// which is the property that enables deterministic handshake replay.
func TestShuffleRandomLengthDeterministic(t *testing.T) {
	input := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	first := ShuffleRandomLength(input, true, rand.New(rand.NewSource(42)))  //nolint:gosec
	second := ShuffleRandomLength(input, true, rand.New(rand.NewSource(42))) //nolint:gosec

	if len(first) != len(second) {
		t.Fatalf("seeded runs produced different lengths: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("seeded runs diverged at index %d: %v vs %v", i, first, second)
		}
	}

	// Input must not be mutated.
	for i, v := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10} {
		if input[i] != v {
			t.Fatalf("ShuffleRandomLength mutated its input at index %d", i)
		}
	}
}
