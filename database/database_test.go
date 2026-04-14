package database

import (
	"fmt"
	"strings"
	"testing"
)

func Example() {
	for v := range Lookup("1234567890abcd") {
		fmt.Println(v)
	}

	// Output:
	// Cisco Type 7
	// BigCrypt
}

// Source: https://hashcat.net/wiki/doku.php?id=example_hashes
func TestLookup(t *testing.T) {
	for _, tt := range []struct {
		name string
		data string
	}{
		{
			name: "MD5",
			data: "8743b52063cd84097a65d1633f5c74f5",
		},
		{
			name: "SHA-1",
			data: "b89eaac7e61417341b710b727768294d0e6a277b",
		},
		{
			name: "SHA-256",
			data: "127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935",
		},
		{
			name: "SHA-512",
			data: "82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f",
		},
		{
			name: "SAM",
			data: "aad3b435b51404eeaad3b435b51404ee:b4b9b02e6f09a9bd760f388b67351e2b",
		},
		{
			name: "NetNTLMv1",
			data: "u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c",
		},
		{
			name: "NetNTLMv2",
			data: "admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030",
		},
	} {
		t.Run("Test Lookup "+tt.name, func(t *testing.T) {
			for a := range Lookup(tt.data) {
				if strings.Contains(a, tt.name) {
					return
				}
			}

			t.Fatalf("no entry found")
		})
	}
}

func BenchmarkLookup(b *testing.B) {
	b.Run("Benchmark Lookup", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			for range Lookup("") {
			}
		}
	})
}
