package application

import "errors"

// ErrNotFound wraps a Named API's existing "not found" error so callers
// can detect it with errors.Is without parsing message text. It was
// introduced for internal/api's write endpoints (ADR 0014), which need
// to map "the addressed resource does not exist" to 404 — something the
// read-only endpoints (ADR 0011) deliberately did not need, since they
// have no per-ID lookup. Existing error message text and CLI output are
// unchanged; only wrapping was added at each site.
var ErrNotFound = errors.New("application: not found")
