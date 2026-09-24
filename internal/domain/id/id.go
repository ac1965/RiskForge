// Package id generates the random identifiers used by domain entity IDs.
package id

import "github.com/google/uuid"

// New returns a new random identifier.
func New() string {
	return uuid.NewString()
}
