// Package catalog identifies the software installed in a rootfs. Catalogers
// read from an fs.FS, which is what every input handler produces, so they are
// testable against fstest.MapFS without any fixture files.
package catalog

import (
	"context"
	"io/fs"

	"github.com/mhmtkas/fwscan/internal/model"
)

// Cataloger finds components of one kind in a rootfs.
//
// A cataloger that finds nothing returns an empty slice and a nil error: an
// image with no dpkg database is not an error, it is an image with no dpkg
// database. Errors are reserved for a database that exists but cannot be read.
type Cataloger interface {
	// Name identifies the cataloger in error messages, e.g. "dpkg".
	Name() string
	// Catalog reads root and returns everything it recognises. A cancelled
	// context is an error, not an empty result: a scan that stops must say so
	// rather than report an image with nothing in it.
	Catalog(ctx context.Context, root fs.FS) ([]model.Component, error)
}

// All returns the catalogers a scan runs, in order.
func All() []Cataloger {
	return []Cataloger{NewDpkg(), NewApk(), NewHeuristic()}
}
