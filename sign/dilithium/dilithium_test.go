package dilithium

import (
	"encoding/hex"
	"testing"

	"github.com/karalef/circl/internal/sha3"
	"github.com/karalef/circl/sign/dilithium/mode3"
)

func hexHash(in []byte) string {
	var ret [16]byte
	h := sha3.NewShake256()
	_, _ = h.Write(in[:])
	_, _ = h.Read(ret[:])
	return hex.EncodeToString(ret[:])
}

func TestNewKeyFromSeed(t *testing.T) {
	// Test vectors generated from reference implementation
	for _, tc := range []struct {
		name string
		esk  string
		epk  string
	}{
		{
			"Dilithium2", "afe2e91f5f5899354230744c18410498",
			"7522162619f3329b5312322d3ee45b87",
		},
		{
			"Dilithium3", "8ad3142e08b718b33f7c2668cd9d053c",
			"3562fc184dce1a10aad099051705b5d3",
		},
		{
			"Dilithium5", "3956d812a7961af6e5dad16af15c736c",
			"665388291aa01e12e7f94bdc7769db18",
		},
		{
			"Dilithium2-AES", "8466a752b0a09e63e42f66d3174a6471",
			"c3f8e705a0d8dfd489b98b205670f393",
		},
		{
			"Dilithium3-AES", "2bb713ba7cb15f3ebf05c4c1fbb1b03c",
			"eb2bd8d98630835a3b18594ac436368b",
		},
		{
			"Dilithium5-AES", "a613a08b564ee8717ba4f5ccfddc2693",
			"2f541bf6fedd12854d06a6b80090932a",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mode := ModeByName(tc.name)
			if mode == nil {
				t.Fatal()
			}
			var seed [32]byte
			pk, sk := mode.DeriveKey(seed[:])

			pkh := hexHash(pk.Bytes())
			skh := hexHash(sk.Bytes())
			if pkh != tc.epk {
				t.Fatalf("%s expected pk %s, got %s", tc.name, tc.epk, pkh)
			}
			if skh != tc.esk {
				t.Fatalf("%s expected pk %s, got %s", tc.name, tc.esk, skh)
			}
		})
	}
}

func TestStream(t *testing.T) {
	mode := mode3.Scheme
	pub, priv, err := mode.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("hello world")

	signature1 := mode.Sign(priv, msg)
	signState := mode.Signer(priv)
	_, err = signState.Write(msg[:3])
	if err != nil {
		t.Fatal(err)
	}
	_, err = signState.Write(msg[3:])
	signature2 := make([]byte, mode.SignatureSize())
	signState.SignTo(signature2)

	println(hexHash(signature1))
	println(hexHash(signature2))

	ok := mode.Verify(pub, msg, signature1)
	if !ok {
		t.Fatal()
	}

	verifState := mode.Verifier(pub)
	_, err = verifState.Write(msg)
	if err != nil {
		t.Fatal(err)
	}
	ok = verifState.Verify(signature2)
	if !ok {
		t.Fatal()
	}
}
