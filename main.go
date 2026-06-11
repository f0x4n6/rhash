// Reverse hash lookup.
//
// Usage:
//
//	rhash hashsum
//
// The arguments are:
//
//	hashsum
//	    Hash sum to find all possible sources for (required).
package main

import (
	"fmt"
	"os"
	"strings"

	"go.foxforensics.eu/rhash/database"
)

var Usage = `© 2026 Fox Forensics. Licensed under MIT License.
Usage: rhash HASHSUM

Report bugs at: foxforensics.eu/issues`

func main() {
	if len(os.Args) == 1 || os.Args[1] == "--help" {
		_, _ = fmt.Fprintln(os.Stderr, Usage)
		os.Exit(2)
	}

	s := strings.ToLower(os.Args[1])

	for v := range database.Lookup(s) {
		_, _ = fmt.Println(v)
	}
}
