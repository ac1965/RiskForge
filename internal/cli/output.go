package cli

import (
	"io"
	"text/tabwriter"
)

// newTabWriter returns a tabwriter configured for the `list` commands'
// column output.
func newTabWriter(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
}
