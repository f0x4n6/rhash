// What The Hash!? is a simple hash reverse lookup.
//
// It searches a database of 270+ hash algorithms for the possible source of the given hash sum
// and outputs all found matches in hashcat notation to STDOUT.
//
// Usage:
//
//	wth hashsum
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

	"go.foxforensics.dev/wth/database"
)

func main() {
	if len(os.Args) == 1 || os.Args[1] == "--help" {
		_, _ = fmt.Fprintln(os.Stderr, "usage: wth hashsum")
		os.Exit(2)
	}

	s := strings.ToLower(os.Args[1])

	for v := range database.Lookup(s) {
		_, _ = fmt.Println(v)
	}
}
