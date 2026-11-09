// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import "crypto/sha256"

func sha(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}
