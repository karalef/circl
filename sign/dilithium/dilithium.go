//go:generate go run gen.go

// dilithium implements the CRYSTALS-Dilithium signature schemes
// as submitted to round3 of the NIST PQC competition and described in
//
// https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
//
// Each of the eight different modes of Dilithium is implemented by a
// subpackage.  For instance, Dilithium2 (the recommended mode)
// can be found in
//
//	github.com/cloudflare/circl/sign/dilithium/mode2
//
// If your choice for mode is fixed compile-time, use the subpackages.
// This package provides a convenient wrapper around all of the subpackages
// so one can be chosen at runtime.
//
// The authors of Dilithium recommend to combine it with a "pre-quantum"
// signature scheme.  The packages
//
//	github.com/cloudflare/circl/sign/eddilithium2
//	github.com/cloudflare/circl/sign/eddilithium3
//
// implement such hybrids of Dilithium2 with Ed25519 respectively and
// Dilithium3 with Ed448.  These packages are a drop in replacements for the
// mode subpackages of this package.
package dilithium

import (
	"crypto"
	"io"
)

// PublicKey is a Dilithium public key.
//
// The structure contains values precomputed during unpacking/key generation
// and is therefore significantly larger than a packed public key.
type PublicKey interface {
	// Packs public key
	Bytes() []byte
	Equal(crypto.PublicKey) bool
}

// PrivateKey is a Dilithium public key.
//
// The structure contains values precomputed during unpacking/key generation
// and is therefore significantly larger than a packed private key.
type PrivateKey interface {
	// Packs private key
	Bytes() []byte
	Equal(crypto.PrivateKey) bool
}

// Signer represents a Dilithium signature state.
type Signer interface {
	io.Writer

	// Sign signs the written message and returns the signature.
	Sign() []byte

	// SignTo creates a signature on the written message and writes it to
	// the given buffer.
	SignTo(buf []byte)
}

// Verifier represents a Dilithium signature verification state.
type Verifier interface {
	io.Writer

	// Verify checks whether the given signature is a valid signature set by
	// the private key corresponding to the specified public key on the
	// written message.
	Verify(signature []byte) bool
}

// Mode is a certain configuration of the Dilithium signature scheme.
type Mode interface {
	// GenerateKey generates a public/private key pair using entropy from rand.
	// If rand is nil, crypto/rand.Reader will be used.
	GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error)

	// NewKeyFromSeed derives a public/private key pair using the given seed.
	// Panics if len(seed) != SeedSize()
	NewKeyFromSeed(seed []byte) (PublicKey, PrivateKey)

	// Sign signs the given message and returns the signature.
	// It will panic if sk has not been generated for this mode.
	Sign(sk PrivateKey, msg []byte) []byte

	// Verify checks whether the given signature by pk on msg is valid.
	// It will panic if pk is of the wrong mode.
	Verify(pk PublicKey, msg []byte, signature []byte) bool

	// Signer creates a signature state.
	// It will panic if sk is of the wrong mode.
	Signer(sk PrivateKey) Signer

	// Verifier creates a signature verification state.
	// It will panic if pk is of the wrong mode.
	Verifier(pk PublicKey) Verifier

	// Unpacks a public key. Panics if the buffer is not of PublicKeySize()
	// length. Precomputes values to speed up subsequent calls to Verify.
	PublicKeyFromBytes([]byte) PublicKey

	// Unpacks a private key. Panics if the buffer is not
	// of PrivateKeySize() length. Precomputes values to speed up subsequent
	// calls to Sign(To).
	PrivateKeyFromBytes([]byte) PrivateKey

	// SeedSize returns the size of the seed for NewKeyFromSeed
	SeedSize() int

	// PublicKeySize returns the size of a packed PublicKey
	PublicKeySize() int

	// PrivateKeySize returns the size of a packed PrivateKey
	PrivateKeySize() int

	// SignatureSize returns the size of a signature
	SignatureSize() int

	// Name returns the name of this mode
	Name() string
}

var modes = make(map[string]Mode)

// ModeNames returns the list of supported modes.
func ModeNames() []string {
	names := []string{}
	for name := range modes {
		names = append(names, name)
	}
	return names
}

// ModeByName returns the mode with the given name or nil when not supported.
func ModeByName(name string) Mode {
	return modes[name]
}
