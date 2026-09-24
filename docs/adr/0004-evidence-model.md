# 0004. Evidence model

## Status

Accepted

## Context

AGENTS.md §17 requires Evidence to be a first-class entity that is
tamper-evident and never conflated with Finding (§44 Invariant 4). §22
and §47.10 additionally forbid deleting or overwriting Evidence, even for
false positives.

## Decision

- `evidence.Evidence` (`internal/domain/evidence`) has exactly the fields
  listed in §17 (`Type`, `Source`, `CollectedAt`, `AssetID`, `FindingID`,
  `ContentHash`, `Location`) plus an `ID`, and **no update method** —
  only `New`. There is no code path in this package that mutates an
  existing Evidence value's fields after construction; a correction is
  always a new Evidence record.
- `FindingID` is the only optional field. Evidence — e.g. a raw scan
  result — can be collected before it is correlated to a specific
  Finding; `AssetID`, by contrast, is required, since evidence is always
  collected in the context of some asset.
- `ContentHash` is required but its format is not enforced beyond being
  non-empty: §17 says "可能ならHashを利用する" (use hashing "if possible"),
  so the domain type stays usable even if a future source can only supply
  a different kind of integrity marker. `ComputeContentHash` (SHA-256,
  hex-encoded) and `Evidence.VerifyContent` are provided as the default
  mechanism and are what infrastructure code should use when it has the
  raw content available.
- `Location` is required and is a reference (e.g. a URI) to where the
  actual content lives — the Evidence entity itself does not carry the
  raw content or read/write it. Storing and retrieving the content by
  Location is infrastructure's job, keeping this package free of
  storage/network dependencies (§25).

## Consequences

- Since Evidence has no setters, any code that wants to "update" evidence
  must instead create a new Evidence and, if needed, link it from a new
  Finding/Verification/Plan reference — the type system makes overwriting
  impossible to do by accident.
- Verifying that stored content has not been tampered with requires
  fetching the bytes at `Location` and calling `VerifyContent`; this
  package intentionally does not do that fetch itself.
