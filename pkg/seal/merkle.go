// Package seal provides the cryptographic chain of custody for captured
// evidence: a deterministic SHA-256 Merkle tree over the memory dump, ECDSA
// P-256 signatures over the tree root, and the serialisable receipt that ties
// them together.
//
// Why a Merkle tree rather than a single file hash? Two reasons that matter in
// court and in practice:
//
//   - Selective disclosure. A 512 MB memory dump routinely contains unrelated
//     third-party data. A Merkle proof lets an examiner prove that one 4 KB
//     chunk is authentic without handing over the entire dump.
//   - Localised tamper evidence. A flat hash tells you "something changed".
//     The tree tells you which chunk changed.
package seal

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// DefaultChunkSize is the leaf granularity of the tree.
//
// 4096 bytes matches the x86-64 and arm64 page size, so a leaf corresponds to
// exactly one page of the captured address space. That alignment is what makes
// a proof meaningful: "page 0x7f3a1000 is authentic" is a statement an examiner
// can act on.
const DefaultChunkSize = 4096

// OddLeafPolicyDuplicateLast documents how odd levels are handled.
//
// When a tree level has an odd number of nodes the final node is duplicated and
// hashed with itself. This is the Bitcoin convention. It is chosen here for one
// reason only: forensic reproducibility requires a single, documented,
// deterministic rule, and this is the one an independent implementer is most
// likely to already have. The known weakness of the convention (two distinct
// leaf sequences can produce the same root when one is a duplicate-extended
// form of the other) is neutralised because LeafCount is recorded in the
// receipt and verification rejects a mismatch.
const OddLeafPolicyDuplicateLast = "duplicate_last"

// ErrEmptyInput is returned when a tree is built over no data. An empty tree
// has no meaningful root and silently returning the hash of nothing would let
// an empty capture masquerade as a successful one.
var ErrEmptyInput = errors.New("seal: cannot build a Merkle tree over empty input")

// ErrLeafOutOfRange is returned by GenerateProof for an invalid leaf index.
var ErrLeafOutOfRange = errors.New("seal: leaf index out of range")

// Tree is an immutable Merkle tree over a fixed sequence of leaves.
//
// levels[0] holds the leaf hashes; levels[len-1] holds the single root hash.
// The structure is built once and never mutated, which makes concurrent reads
// (proof generation from many goroutines) safe without locking.
type Tree struct {
	levels    [][][32]byte
	chunkSize int
	leafCount int
}

// ProofNode is one sibling hash on the path from a leaf to the root.
type ProofNode struct {
	Hash     string `json:"hash"`
	Position string `json:"position"` // "left" or "right": which side the sibling sits on
}

// MerkleProof is the set of sibling hashes needed to recompute the root from a
// single leaf.
type MerkleProof struct {
	LeafIndex int         `json:"leaf_index"`
	LeafCount int         `json:"leaf_count"`
	Siblings  []ProofNode `json:"siblings"`
}

// BuildTree chunks data into chunkSize blocks and builds the tree.
//
// Pass 0 for chunkSize to use DefaultChunkSize. The final chunk is NOT padded:
// hashing a short tail as-is keeps the root a function of the exact bytes
// captured, which is what tamper detection requires.
func BuildTree(data []byte, chunkSize int) (*Tree, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if len(data) == 0 {
		return nil, ErrEmptyInput
	}

	leafCount := (len(data) + chunkSize - 1) / chunkSize
	leaves := make([][32]byte, 0, leafCount)
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		leaves = append(leaves, sha256.Sum256(data[off:end]))
	}

	return buildFromLeafHashes(leaves, chunkSize)
}

// BuildTreeFromChunks builds a tree over pre-split chunks.
//
// This is the entry point used by the capture pipeline, which already holds
// memory regions as separate byte slices and must not pay for concatenating
// hundreds of megabytes just to split them again.
func BuildTreeFromChunks(chunks [][]byte, chunkSize int) (*Tree, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if len(chunks) == 0 {
		return nil, ErrEmptyInput
	}

	total := 0
	for _, c := range chunks {
		total += len(c)
	}
	if total == 0 {
		return nil, ErrEmptyInput
	}

	leaves := make([][32]byte, 0, len(chunks))
	for _, c := range chunks {
		if len(c) == 0 {
			continue
		}
		leaves = append(leaves, sha256.Sum256(c))
	}
	return buildFromLeafHashes(leaves, chunkSize)
}

func buildFromLeafHashes(leaves [][32]byte, chunkSize int) (*Tree, error) {
	if len(leaves) == 0 {
		return nil, ErrEmptyInput
	}

	t := &Tree{
		levels:    [][][32]byte{leaves},
		chunkSize: chunkSize,
		leafCount: len(leaves),
	}

	current := leaves
	for len(current) > 1 {
		next := make([][32]byte, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			left := current[i]
			right := left // odd node: duplicate-last, see OddLeafPolicyDuplicateLast
			if i+1 < len(current) {
				right = current[i+1]
			}
			next = append(next, hashPair(left, right))
		}
		t.levels = append(t.levels, next)
		current = next
	}

	return t, nil
}

func hashPair(left, right [32]byte) [32]byte {
	var buf [64]byte
	copy(buf[:32], left[:])
	copy(buf[32:], right[:])
	return sha256.Sum256(buf[:])
}

// Root returns the hex-encoded root hash.
func (t *Tree) Root() string {
	top := t.levels[len(t.levels)-1]
	return hex.EncodeToString(top[0][:])
}

// RootBytes returns the raw 32-byte root hash, which is what gets signed.
func (t *Tree) RootBytes() [32]byte {
	top := t.levels[len(t.levels)-1]
	return top[0]
}

// LeafCount returns the number of leaves (chunks) in the tree.
func (t *Tree) LeafCount() int { return t.leafCount }

// Depth returns the number of levels, counting leaves and root.
// A single-leaf tree has depth 1.
func (t *Tree) Depth() int { return len(t.levels) }

// ChunkSize returns the leaf granularity used to build the tree.
func (t *Tree) ChunkSize() int { return t.chunkSize }

// LeafHash returns the hex-encoded hash of leaf i.
func (t *Tree) LeafHash(i int) (string, error) {
	if i < 0 || i >= t.leafCount {
		return "", fmt.Errorf("%w: %d (have %d leaves)", ErrLeafOutOfRange, i, t.leafCount)
	}
	h := t.levels[0][i]
	return hex.EncodeToString(h[:]), nil
}

// GenerateProof produces the sibling path proving that leaf leafIndex is part
// of this tree.
func (t *Tree) GenerateProof(leafIndex int) (MerkleProof, error) {
	if leafIndex < 0 || leafIndex >= t.leafCount {
		return MerkleProof{}, fmt.Errorf("%w: %d (have %d leaves)", ErrLeafOutOfRange, leafIndex, t.leafCount)
	}

	proof := MerkleProof{
		LeafIndex: leafIndex,
		LeafCount: t.leafCount,
		Siblings:  make([]ProofNode, 0, len(t.levels)-1),
	}

	idx := leafIndex
	for level := 0; level < len(t.levels)-1; level++ {
		nodes := t.levels[level]

		var sibling [32]byte
		var position string
		if idx%2 == 0 {
			// We are the left child; the sibling is to our right, or is a
			// duplicate of ourselves at an odd boundary.
			position = "right"
			if idx+1 < len(nodes) {
				sibling = nodes[idx+1]
			} else {
				sibling = nodes[idx]
			}
		} else {
			position = "left"
			sibling = nodes[idx-1]
		}

		proof.Siblings = append(proof.Siblings, ProofNode{
			Hash:     hex.EncodeToString(sibling[:]),
			Position: position,
		})
		idx /= 2
	}

	return proof, nil
}

// GenerateAllProofs returns proofs for every leaf, keyed by leaf index.
//
// Only used for small trees (receipts embed proofs for the first N leaves);
// for a 512 MB dump this would be 131,072 proofs and is intentionally not done
// by default.
func (t *Tree) GenerateAllProofs() (map[int]MerkleProof, error) {
	out := make(map[int]MerkleProof, t.leafCount)
	for i := 0; i < t.leafCount; i++ {
		p, err := t.GenerateProof(i)
		if err != nil {
			return nil, err
		}
		out[i] = p
	}
	return out, nil
}

// VerifyProof independently checks that leaf hashes into rootHash along proof.
//
// This function deliberately depends on nothing but the arguments: an examiner
// can lift it out of this repository and re-run it against evidence produced
// years earlier. That property is the entire point of publishing the algorithm.
func VerifyProof(rootHash string, leaf []byte, proof MerkleProof) bool {
	want, err := hex.DecodeString(rootHash)
	if err != nil || len(want) != sha256.Size {
		return false
	}
	if proof.LeafIndex < 0 {
		return false
	}
	if proof.LeafCount > 0 && proof.LeafIndex >= proof.LeafCount {
		return false
	}

	acc := sha256.Sum256(leaf)
	for _, node := range proof.Siblings {
		sibBytes, err := hex.DecodeString(node.Hash)
		if err != nil || len(sibBytes) != sha256.Size {
			return false
		}
		var sib [32]byte
		copy(sib[:], sibBytes)

		switch node.Position {
		case "left":
			acc = hashPair(sib, acc)
		case "right":
			acc = hashPair(acc, sib)
		default:
			return false
		}
	}

	return hex.EncodeToString(acc[:]) == rootHash
}

// VerifyData rebuilds a tree over data and reports whether it reproduces
// rootHash with the given chunk size and leaf count.
//
// leafCount is checked explicitly to close the duplicate-last ambiguity
// described on OddLeafPolicyDuplicateLast.
func VerifyData(data []byte, chunkSize, leafCount int, rootHash string) error {
	tree, err := BuildTree(data, chunkSize)
	if err != nil {
		return err
	}
	if leafCount > 0 && tree.LeafCount() != leafCount {
		return fmt.Errorf("seal: leaf count mismatch: recomputed %d, receipt claims %d", tree.LeafCount(), leafCount)
	}
	if got := tree.Root(); got != rootHash {
		return fmt.Errorf("seal: root hash mismatch: recomputed %s, receipt claims %s", got, rootHash)
	}
	return nil
}
