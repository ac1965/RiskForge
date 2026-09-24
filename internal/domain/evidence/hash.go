package evidence

import (
	"crypto/sha256"
	"encoding/hex"
)

// ComputeContentHash returns the hex-encoded SHA-256 digest of content, for
// use as an Evidence's ContentHash (AGENTS.md §17: "Evidenceは後から改変され
// たことが分からなくてはならない。可能ならHashを利用する。"). Computing the
// hash is pure computation, not storage — where the content itself lives
// is Location's concern, handled by infrastructure.
func ComputeContentHash(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// VerifyContent reports whether content still matches e's recorded
// ContentHash.
func (e *Evidence) VerifyContent(content []byte) bool {
	return ComputeContentHash(content) == e.ContentHash
}
