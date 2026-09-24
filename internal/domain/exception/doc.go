// Package exception holds the Exception entity (AGENTS.md §18): a
// formally tracked, time-bounded risk acceptance or false-positive
// suppression for a Finding.
//
// Exceptions are never permanent by default: New requires an expiry, and
// ExceptionPolicy exists to cap how far in the future that expiry may be
// set. An expired or revoked Exception implies its Finding should be
// reopened for re-evaluation (AGENTS.md §18).
package exception
