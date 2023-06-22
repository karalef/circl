// Package schemes contains a register of KEM schemes.
//
// # Schemes Implemented
//
//	FrodoKEM-640-SHAKE
//	Kyber512, Kyber768, Kyber1024
package schemes

import (
	"strings"

	"github.com/karalef/circl/kem"
	"github.com/karalef/circl/kem/frodo/frodo640shake"
	"github.com/karalef/circl/kem/kyber/kyber1024"
	"github.com/karalef/circl/kem/kyber/kyber512"
	"github.com/karalef/circl/kem/kyber/kyber768"
)

var allSchemes = [...]kem.Scheme{
	frodo640shake.Scheme(),
	kyber512.Scheme(),
	kyber768.Scheme(),
	kyber1024.Scheme(),
}

var allSchemeNames map[string]kem.Scheme

func init() {
	allSchemeNames = make(map[string]kem.Scheme)
	for _, scheme := range allSchemes {
		allSchemeNames[strings.ToLower(scheme.Name())] = scheme
	}
}

// ByName returns the scheme with the given name and nil if it is not
// supported.
//
// Names are case insensitive.
func ByName(name string) kem.Scheme {
	return allSchemeNames[strings.ToLower(name)]
}

// All returns all KEM schemes supported.
func All() []kem.Scheme { a := allSchemes; return a[:] }
