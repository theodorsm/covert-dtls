package utils

import (
	"testing"
)

func TestShuffle(t *testing.T) {
	list := []int{1, 2, 3, 4, 5}
	for i := 1; i < 1000; i++ {
		shuffled := ShuffleRandomLength(list, true)
		if len(shuffled) == 0 {
			t.Fatalf("Shuffle returned a empty slice")
		}
	}
}
