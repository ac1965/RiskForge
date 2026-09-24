package cli

import "errors"

// errNotImplemented marks commands whose application-layer API
// (AGENTS.md §26) has not been implemented yet (Phase 1, AGENTS.md §45).
var errNotImplemented = errors.New("not implemented yet")
