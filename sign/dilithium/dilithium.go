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
// signature scheme.
package dilithium

import (
	"github.com/karalef/circl/sign"
	"github.com/karalef/circl/sign/dilithium/mode2"
	"github.com/karalef/circl/sign/dilithium/mode2aes"
	"github.com/karalef/circl/sign/dilithium/mode3"
	"github.com/karalef/circl/sign/dilithium/mode3aes"
	"github.com/karalef/circl/sign/dilithium/mode5"
	"github.com/karalef/circl/sign/dilithium/mode5aes"
)

// Dilithium modes.
var (
	Mode2    = mode2.Scheme
	Mode2AES = mode2aes.Scheme
	Mode3    = mode3.Scheme
	Mode3AES = mode3aes.Scheme
	Mode5    = mode5.Scheme
	Mode5AES = mode5aes.Scheme
)

var modes = map[string]sign.Scheme{
	"Dilithium2":     Mode2,
	"Dilithium2-AES": Mode2AES,
	"Dilithium3":     Mode3,
	"Dilithium3-AES": Mode3AES,
	"Dilithium5":     Mode5,
	"Dilithium5-AES": Mode5AES,
}

// ModeNames returns the list of supported modes.
func ModeNames() []string {
	names := []string{}
	for name := range modes {
		names = append(names, name)
	}
	return names
}

// ModeByName returns the mode with the given name or nil when not supported.
func ModeByName(name string) sign.Scheme {
	return modes[name]
}
