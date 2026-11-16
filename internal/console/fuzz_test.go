// SPDX-License-Identifier: AGPL-3.0-only

package console

import (
	"bufio"
	"strings"
	"testing"
)

func FuzzReadRaw(f *testing.F) {
	for _, s := range []string{"4.sync,1.1;", "0.,4.ping,3.123;", "5.mouse,1.1,1.2;", "3.é€x;", "9999999999.a;", "-1.a;", "1.a", "1.ab;", "2.a;b;"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		raw, elems, err := readRaw(bufio.NewReader(strings.NewReader(in)))
		if err != nil {
			return
		}
		if len(elems) == 0 || !strings.HasPrefix(in, raw) {
			t.Fatalf("%q → raw %q elems %q", in, raw, elems)
		}
		// What we would forward must be exactly one well-formed instruction.
		if again := encode(elems...); again != raw {
			// Lengths may be written differently ("01.a"), but never the content.
			_, e2, err := readRaw(bufio.NewReader(strings.NewReader(again)))
			if err != nil || strings.Join(e2, "\x00") != strings.Join(elems, "\x00") {
				t.Fatalf("%q doesn't round-trip: %q", in, again)
			}
		}
	})
}
