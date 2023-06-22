// Code generated from modePkg.templ.go. DO NOT EDIT.

// mode3aes implements the CRYSTALS-Dilithium signature scheme Dilithium3-AES
// as submitted to round3 of the NIST PQC competition and described in
//
// https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf
package mode3aes

import (
	"crypto"
	"errors"
	"fmt"
	"io"

	"github.com/karalef/circl/sign"
	"github.com/karalef/circl/sign/dilithium/internal/common"
	"github.com/karalef/circl/sign/dilithium/mode3aes/internal"
)

const (
	// Size of seed for NewKeyFromSeed
	SeedSize = common.SeedSize

	// Size of a packed PublicKey
	PublicKeySize = internal.PublicKeySize

	// Size of a packed PrivateKey
	PrivateKeySize = internal.PrivateKeySize

	// Size of a signature
	SignatureSize = internal.SignatureSize
)

// PublicKey is the type of Dilithium3-AES public key
type PublicKey internal.PublicKey

// PrivateKey is the type of Dilithium3-AES private key
type PrivateKey internal.PrivateKey

// State is the type of Dilithium3-AES state
type State = internal.State

var (
	_ sign.PublicKey = (*PublicKey)(nil)
	_ sign.PrivateKey = (*PrivateKey)(nil)
	_ sign.Signer = (*State)(nil)
	_ sign.Verifier = (*State)(nil)
)

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	pk, sk, err := internal.GenerateKey(rand)
	return (*PublicKey)(pk), (*PrivateKey)(sk), err
}

// NewKeyFromSeed derives a public/private key pair using the given seed.
func NewKeyFromSeed(seed *[SeedSize]byte) (*PublicKey, *PrivateKey) {
	pk, sk := internal.NewKeyFromSeed(seed)
	return (*PublicKey)(pk), (*PrivateKey)(sk)
}

// SignTo signs the given message and writes the signature into signature.
// It will panic if signature is not of length at least SignatureSize.
func SignTo(sk *PrivateKey, msg []byte, signature []byte) {
	internal.SignTo(
		(*internal.PrivateKey)(sk),
		msg,
		signature,
	)
}

// Verify checks whether the given signature by pk on msg is valid.
func Verify(pk *PublicKey, msg []byte, signature []byte) bool {
	return internal.Verify(
		(*internal.PublicKey)(pk),
		msg,
		signature,
	)
}

// NewSigner creates a signature state.
func NewSigner(sk *PrivateKey) *State {
	return internal.NewSigner((*internal.PrivateKey)(sk))
}

// NewVerifier creates a signature verification state.
func NewVerifier(pk *PublicKey) *State {
	return internal.NewVerifier((*internal.PublicKey)(pk))
}

// Sets pk to the public key encoded in buf.
func (pk *PublicKey) Unpack(buf *[PublicKeySize]byte) {
	(*internal.PublicKey)(pk).Unpack(buf)
}

// Sets sk to the private key encoded in buf.
func (sk *PrivateKey) Unpack(buf *[PrivateKeySize]byte) {
	(*internal.PrivateKey)(sk).Unpack(buf)
}

// Packs the public key into buf.
func (pk *PublicKey) Pack(buf *[PublicKeySize]byte) {
	(*internal.PublicKey)(pk).Pack(buf)
}

// Packs the private key into buf.
func (sk *PrivateKey) Pack(buf *[PrivateKeySize]byte) {
	(*internal.PrivateKey)(sk).Pack(buf)
}

// Packs the public key.
func (pk *PublicKey) Bytes() []byte {
	var buf [PublicKeySize]byte
	pk.Pack(&buf)
	return buf[:]
}

// Packs the private key.
func (sk *PrivateKey) Bytes() []byte {
	var buf [PrivateKeySize]byte
	sk.Pack(&buf)
	return buf[:]
}

// Packs the public key.
func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	return pk.Bytes(), nil
}

// Packs the private key.
func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	return sk.Bytes(), nil
}

// Unpacks the public key from data.
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	if len(data) != PublicKeySize {
		return errors.New("packed public key must be of internal.PublicKeySize bytes")
	}
	var buf [PublicKeySize]byte
	copy(buf[:], data)
	pk.Unpack(&buf)
	return nil
}

// Unpacks the private key from data.
func (sk *PrivateKey) UnmarshalBinary(data []byte) error {
	if len(data) != PrivateKeySize {
		return errors.New("packed private key must be of internal.PrivateKeySize bytes")
	}
	var buf [PrivateKeySize]byte
	copy(buf[:], data)
	sk.Unpack(&buf)
	return nil
}

// Sign signs the given message.
//
// opts.HashFunc() must return zero, which can be achieved by passing
// crypto.Hash(0) for opts.  rand is ignored.  Will only return an error
// if opts.HashFunc() is non-zero.
//
// This function is used to make PrivateKey implement the crypto.Signer
// interface.  The package-level SignTo function might be more convenient
// to use.
func (sk *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (
	signature []byte, err error) {
	var sig [SignatureSize]byte

	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("dilithium: cannot sign hashed message")
	}

	SignTo(sk, msg, sig[:])
	return sig[:], nil
}

// Computes the public key corresponding to this private key.
//
// Returns a *PublicKey.  The type crypto.PublicKey is used to make
// PrivateKey implement the crypto.Signer interface.
func (sk *PrivateKey) Public() sign.PublicKey {
	return (*PublicKey)((*internal.PrivateKey)(sk).Public())
}

// Equal returns whether the two private keys equal.
func (sk *PrivateKey) Equal(other sign.PrivateKey) bool {
	castOther, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	return (*internal.PrivateKey)(sk).Equal((*internal.PrivateKey)(castOther))
}

// Equal returns whether the two public keys equal.
func (pk *PublicKey) Equal(other sign.PublicKey) bool {
	castOther, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	return (*internal.PublicKey)(pk).Equal((*internal.PublicKey)(castOther))
}

func (sk *PrivateKey) Scheme() sign.Scheme {
	return Scheme
}

func (pk *PublicKey) Scheme() sign.Scheme {
	return Scheme
}

// implMode3AES implements the mode.Mode interface for Dilithium3-AES.
type implMode3AES struct{}

// Scheme is Dilithium in mode "Dilithium3-AES".
var Scheme sign.Scheme = &implMode3AES{}

func (m *implMode3AES) GenerateKey(rand io.Reader) (sign.PublicKey, sign.PrivateKey, error) {
	return GenerateKey(rand)
}

func (m *implMode3AES) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	if len(seed) != common.SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", common.SeedSize))
	}
	seedBuf := [common.SeedSize]byte{}
	copy(seedBuf[:], seed)
	return NewKeyFromSeed(&seedBuf)
}

func (m *implMode3AES) Sign(sk sign.PrivateKey, msg []byte) []byte {
	isk := sk.(*PrivateKey)
	ret := [SignatureSize]byte{}
	SignTo(isk, msg, ret[:])
	return ret[:]
}

func (m *implMode3AES) Verify(pk sign.PublicKey, msg []byte, signature []byte) bool {
	ipk := pk.(*PublicKey)
	return Verify(ipk, msg, signature)
}

func (m *implMode3AES) Signer(sk sign.PrivateKey) sign.Signer {
	return NewSigner(sk.(*PrivateKey))
}

func (m *implMode3AES) Verifier(pk sign.PublicKey) sign.Verifier {
	return NewVerifier(pk.(*PublicKey))
}

func (m *implMode3AES) UnmarshalBinaryPublicKey(data []byte) (sign.PublicKey, error) {
	var ret PublicKey
	if len(data) != PublicKeySize {
		return nil, sign.ErrPubKeySize
	}
	var buf [PublicKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret, nil
}

func (m *implMode3AES) UnmarshalBinaryPrivateKey(data []byte) (sign.PrivateKey, error) {
	var ret PrivateKey
	if len(data) != PrivateKeySize {
		return nil, sign.ErrPrivKeySize
	}
	var buf [PrivateKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret, nil
}

func (m *implMode3AES) SeedSize() int {
	return common.SeedSize
}

func (m *implMode3AES) PublicKeySize() int {
	return internal.PublicKeySize
}

func (m *implMode3AES) PrivateKeySize() int {
	return internal.PrivateKeySize
}

func (m *implMode3AES) SignatureSize() int {
	return internal.SignatureSize
}

func (m *implMode3AES) Name() string {
	return "Dilithium3-AES"
}
