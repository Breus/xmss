package xmss

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func benchmarkKeyGen(h, d uint32, b *testing.B) {
	seed := generateSeed()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk, err := NewPrivKeyMT(seed, h, d)
		if err != nil {
			b.Fatal("Keygen benchmark failed with error", err)
		}
		sk.PublicKey()
	}
}

func BenchmarkXMSSKeyGen(b *testing.B) {
	hCases := []uint32{20}
	dCases := []uint32{2, 4}

	for _, h := range hCases {
		for _, d := range dCases {
			name := "KEYGEN-h" + fmt.Sprint(h) + "d" + fmt.Sprint(d)
			b.Run(name, func(b *testing.B) {
				benchmarkKeyGen(h, d, b)
			})
		}
	}
}

func benchmarkSign(h, d uint32, b *testing.B) {
	seed := generateSeed()
	msg := make([]byte, 51200)
	rand.Read(msg)
	sk, _ := NewPrivKeyMT(seed, h, d)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sk.Sign(msg)
	}
}

func BenchmarkXMSSSign(b *testing.B) {
	hCases := []uint32{20}
	dCases := []uint32{2, 4}
	for _, h := range hCases {
		for _, d := range dCases {
			name := "SIGN-h" + fmt.Sprint(h) + "d" + fmt.Sprint(d)
			b.Run(name, func(b *testing.B) {
				benchmarkSign(h, d, b)
			})
		}
	}

}

func benchmarkVerify(h, d uint32, b *testing.B) {
	seed := generateSeed()
	msg := make([]byte, 51200)
	rand.Read(msg)
	sk, _ := NewPrivKeyMT(seed, h, d)
	pk := sk.PublicKey()
	sig := sk.Sign(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyMT(sig, msg, pk)
	}
}

func BenchmarkXMSSVerify(b *testing.B) {
	hCases := []uint32{20}
	dCases := []uint32{2, 4}
	for _, h := range hCases {
		for _, d := range dCases {
			name := "VERIFY-h" + fmt.Sprint(h) + "d" + fmt.Sprint(d)
			b.Run(name, func(b *testing.B) {
				benchmarkVerify(h, d, b)
			})
		}
	}

}
