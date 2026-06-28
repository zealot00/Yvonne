//go:build !gmsm

// Package auth - SM2 JWT stub（默认编译时不可用）。
package auth

import (
	"errors"
)

// loadSM2PublicKey stub（默认编译时不可用）。
func loadSM2PublicKey(path string) (interface{}, error) {
	return nil, errors.New("auth: SM2 not compiled in (rebuild with -tags gmsm)")
}
