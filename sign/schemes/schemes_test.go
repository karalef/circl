package schemes_test

import (
	"fmt"
	"testing"

	"github.com/karalef/circl/sign/schemes"
)

func TestCaseSensitivity(t *testing.T) {
	if schemes.ByName("ed25519") != schemes.ByName("Ed25519") {
		t.Fatal()
	}
}

func TestApi(t *testing.T) {
	allSchemes := schemes.All()
	for _, scheme := range allSchemes {
		scheme := scheme
		t.Run(scheme.Name(), func(t *testing.T) {
			if scheme == nil {
				t.Fatal()
			}

			pk, sk, err := scheme.GenerateKey(nil)
			if err != nil {
				t.Fatal()
			}

			packedPk, err := pk.MarshalBinary()
			if err != nil {
				t.Fatal()
			}

			if len(packedPk) != scheme.PublicKeySize() {
				t.Fatal()
			}

			packedSk, err := sk.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}

			if len(packedSk) != scheme.PrivateKeySize() {
				t.Fatal()
			}

			pk2, err := scheme.UnmarshalBinaryPublicKey(packedPk)
			if err != nil {
				t.Fatal(err)
			}

			sk2, err := scheme.UnmarshalBinaryPrivateKey(packedSk)
			if err != nil {
				t.Fatal(err)
			}

			if !sk.Equal(sk2) {
				t.Fatal()
			}

			if !pk.Equal(pk2) {
				t.Fatal()
			}

			msg := []byte(fmt.Sprintf("Signing with %s", scheme.Name()))
			sig := scheme.Sign(sk, msg)

			if scheme.SignatureSize() != len(sig) {
				t.Fatal()
			}

			if !scheme.Verify(pk2, msg, sig) {
				t.Fatal()
			}

			sig[0]++
			if scheme.Verify(pk2, msg, sig) {
				t.Fatal()
			}

			scheme2 := schemes.ByName(scheme.Name())
			if scheme2 == nil || scheme2 != scheme {
				t.Fatal()
			}

			if pk.Scheme() != scheme {
				t.Fatal()
			}

			if sk.Scheme() != scheme {
				t.Fatal()
			}
		})
	}
}

func Example() {
	for _, sch := range schemes.All() {
		fmt.Println(sch.Name())
	}
	// Output:
	// Ed25519-Dilithium2
	// Ed448-Dilithium3
}

func BenchmarkGenerateKeyPair(b *testing.B) {
	allSchemes := schemes.All()
	for _, scheme := range allSchemes {
		scheme := scheme
		b.Run(scheme.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _, _ = scheme.GenerateKey(nil)
			}
		})
	}
}

func BenchmarkSign(b *testing.B) {
	allSchemes := schemes.All()
	for _, scheme := range allSchemes {
		msg := []byte(fmt.Sprintf("Signing with %s", scheme.Name()))
		scheme := scheme
		_, sk, _ := scheme.GenerateKey(nil)
		b.Run(scheme.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = scheme.Sign(sk, msg)
			}
		})
	}
}

func BenchmarkVerify(b *testing.B) {
	allSchemes := schemes.All()
	for _, scheme := range allSchemes {
		msg := []byte(fmt.Sprintf("Signing with %s", scheme.Name()))
		scheme := scheme
		pk, sk, _ := scheme.GenerateKey(nil)
		sig := scheme.Sign(sk, msg)
		b.Run(scheme.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = scheme.Verify(pk, msg, sig)
			}
		})
	}
}
