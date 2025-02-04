// Package sign provides unified interfaces for signature schemes.
//
// A register of schemes is available in the package
//
//	github.com/cloudflare/circl/sign/schemes
package sign

import (
	"encoding"
	"errors"
	"io"
)

// PublicKey is used to verify a signature set by the corresponding private
// key.
type PublicKey interface {
	// Returns the signature scheme for this public key.
	Scheme() Scheme
	Equal(PublicKey) bool

	// Allocates a byte slice and writes the public key to it.
	Bytes() []byte

	encoding.BinaryMarshaler
}

// PrivateKey allows one to create signatures.
type PrivateKey interface {
	// Returns the signature scheme for this private key.
	Scheme() Scheme
	Public() PublicKey
	Equal(PrivateKey) bool

	// Allocates a byte slice and writes the private key to it.
	Bytes() []byte

	encoding.BinaryMarshaler
}

// Signer represents a signature state.
type Signer interface {
	io.Writer

	// Reset resets the Signer.
	Reset()

	// Sign signs the written message and returns the signature.
	Sign() []byte

	// SignTo creates a signature on the written message and writes it to
	// the given buffer.
	SignTo(signature []byte)
}

// Verifier represents a signature verification state.
type Verifier interface {
	io.Writer

	// Reset resets the Verifier.
	Reset()

	// Verify checks whether the given signature is a valid signature set by
	// the private key corresponding to the specified public key on the
	// written message.
	Verify(signature []byte) bool
}

// A Scheme represents a specific instance of a signature scheme.
type Scheme interface {
	// Name of the scheme.
	Name() string

	// GenerateKey creates a new key-pair.
	GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error)

	// Creates a signature using the PrivateKey on the given message and
	// returns the signature.
	//
	// Panics if key is nil or wrong type.
	Sign(sk PrivateKey, message []byte) []byte

	// Signer creates a signature state.
	//
	// Panics if key is nil or wrong type.
	Signer(sk PrivateKey) Signer

	// Checks whether the given signature is a valid signature set by
	// the private key corresponding to the given public key on the
	// given message.
	//
	// Panics if key is nil or wrong type.
	Verify(pk PublicKey, message []byte, signature []byte) bool

	// Verifier creates a signature verification state.
	//
	// Panics if key is nil or wrong type.
	Verifier(pk PublicKey) Verifier

	// Deterministically derives a key-pair from a seed. If you're unsure,
	// you're better off using GenerateKey().
	//
	// Panics if seed is not of length SeedSize().
	DeriveKey(seed []byte) (PublicKey, PrivateKey)

	// Unmarshals a PublicKey from the provided buffer.
	UnmarshalBinaryPublicKey([]byte) (PublicKey, error)

	// Unmarshals a PublicKey from the provided buffer.
	UnmarshalBinaryPrivateKey([]byte) (PrivateKey, error)

	// Size of binary marshalled public keys.
	PublicKeySize() int

	// Size of binary marshalled public keys.
	PrivateKeySize() int

	// Size of signatures.
	SignatureSize() int

	// Size of seeds.
	SeedSize() int
}

var (
	// ErrTypeMismatch is the error used if types of, for instance, private
	// and public keys don't match.
	ErrTypeMismatch = errors.New("types mismatch")

	// ErrSeedSize is the error used if the provided seed is of the wrong
	// size.
	ErrSeedSize = errors.New("wrong seed size")

	// ErrPubKeySize is the error used if the provided public key is of
	// the wrong size.
	ErrPubKeySize = errors.New("wrong size for public key")

	// ErrPrivKeySize is the error used if the provided private key is of
	// the wrong size.
	ErrPrivKeySize = errors.New("wrong size for private key")
)
