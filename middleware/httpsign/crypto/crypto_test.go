package crypto

import (
	"encoding/hex"
	"hash"
	"testing"
)

// RFC 4231 Test Case 2
func TestHmacSha2Vectors(t *testing.T) {
	const key, msg = "Jefe", "what do ya want for nothing?"
	tests := []struct {
		algo Crypto
		want string
	}{
		{&HmacSha256{}, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"},
		{&HmacSha512{}, "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"},
	}
	for _, tt := range tests {
		sig, err := tt.algo.Sign(msg, key)
		if err != nil {
			t.Fatalf("%s: %v", tt.algo.Name(), err)
		}
		if got := hex.EncodeToString(sig); got != tt.want {
			t.Errorf("%s: got %s, want %s", tt.algo.Name(), got, tt.want)
		}
	}
}

func TestAllAlgorithmsSign(t *testing.T) {
	algos := []Crypto{
		&HmacSha256{}, &HmacSha512{},
		&HmacBlake2b256{}, &HmacBlake2b512{}, &HmacBlake2c256{},
		&HmacShake128{}, &HmacShake256{},
	}
	names := make(map[string]bool, len(algos))
	for _, a := range algos {
		if names[a.Name()] {
			t.Errorf("duplicate algorithm name %q", a.Name())
		}
		names[a.Name()] = true

		s1, err := a.Sign("msg", "secret")
		if err != nil {
			t.Fatalf("%s: %v", a.Name(), err)
		}
		s2, _ := a.Sign("msg", "secret")
		if hex.EncodeToString(s1) != hex.EncodeToString(s2) {
			t.Errorf("%s: signature is not deterministic", a.Name())
		}
	}
}

func TestShakeHashSizes(t *testing.T) {
	for _, tt := range []struct {
		h         func() hash.Hash
		size, blk int
	}{
		{newHmacShake128, 16, 128},
		{newHmacShake256, 32, 256},
	} {
		h := tt.h()
		if h.Size() != tt.size || h.BlockSize() != tt.blk {
			t.Errorf("size=%d block=%d, want %d/%d", h.Size(), h.BlockSize(), tt.size, tt.blk)
		}
		// Sum 不能改变内部状态：连续两次 Sum 结果相同
		h.Write([]byte("x"))
		if hex.EncodeToString(h.Sum(nil)) != hex.EncodeToString(h.Sum(nil)) {
			t.Error("Sum must not change the hash state")
		}
	}
}
