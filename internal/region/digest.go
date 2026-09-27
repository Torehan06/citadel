package region

import (
	"crypto/sha256"
	"encoding/hex"
)

// Anti-entropy digests. A replicated collection (a bucket's versions, a
// table's items) is split into Leaves ranges of the hash of each entry's
// identity. A leaf's digest is the XOR of sha256(identity, version) over its
// entries, so it doesn't depend on the order entries are visited in and can be
// computed in one scan. Two regions first compare all leaf digests (a
// two-level Merkle tree: the root is implied by the leaves), then exchange the
// entry lists of only the leaves that differ.

// Leaves is the number of ranges a digest has.
const Leaves = 256

// Digest is the leaf digests of one collection.
type Digest [Leaves][sha256.Size]byte

// LeafOf returns the leaf an entry identity falls in.
func LeafOf(id string) int {
	h := sha256.Sum256([]byte(id))
	return int(h[0])
}

// Add folds one entry into the digest.
func (d *Digest) Add(id, version string) {
	leaf := LeafOf(id)
	h := sha256.Sum256([]byte(id + "\x00" + version))
	for i := range h {
		d[leaf][i] ^= h[i]
	}
}

// Hex returns the leaf digests as hex strings.
func (d *Digest) Hex() []string {
	out := make([]string, Leaves)
	for i := range d {
		out[i] = hex.EncodeToString(d[i][:])
	}
	return out
}

// DiffLeaves returns the leaves whose digests differ. A malformed remote
// digest (wrong length) differs everywhere.
func DiffLeaves(local *Digest, remote []string) []int {
	var out []int
	mine := local.Hex()
	for i := range mine {
		if len(remote) != Leaves || remote[i] != mine[i] {
			out = append(out, i)
		}
	}
	return out
}
