package seal

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"testing/quick"
)

// chunks builds n chunks of size bytes with distinguishable content.
func chunks(n, size int) []byte {
	data := make([]byte, n*size)
	for i := range data {
		data[i] = byte(i % 251)
	}
	return data
}

func hashOf(b []byte) [32]byte { return sha256.Sum256(b) }

func concatHash(a, b [32]byte) [32]byte {
	var buf [64]byte
	copy(buf[:32], a[:])
	copy(buf[32:], b[:])
	return sha256.Sum256(buf[:])
}

// 1. Empty input must error rather than panic or produce a root.
func TestEmptyInput(t *testing.T) {
	if _, err := BuildTree(nil, DefaultChunkSize); !errors.Is(err, ErrEmptyInput) {
		t.Fatalf("BuildTree(nil) error = %v, want ErrEmptyInput", err)
	}
	if _, err := BuildTree([]byte{}, DefaultChunkSize); !errors.Is(err, ErrEmptyInput) {
		t.Fatalf("BuildTree(empty) error = %v, want ErrEmptyInput", err)
	}
	if _, err := BuildTreeFromChunks(nil, DefaultChunkSize); !errors.Is(err, ErrEmptyInput) {
		t.Fatalf("BuildTreeFromChunks(nil) error = %v, want ErrEmptyInput", err)
	}
	if _, err := BuildTreeFromChunks([][]byte{{}, {}}, DefaultChunkSize); !errors.Is(err, ErrEmptyInput) {
		t.Fatalf("BuildTreeFromChunks(all empty) error = %v, want ErrEmptyInput", err)
	}
}

// 2. A one-leaf tree's root is the hash of that leaf.
func TestSingleLeaf(t *testing.T) {
	data := []byte("a single chunk of process memory")

	tree, err := BuildTree(data, DefaultChunkSize)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}

	want := hashOf(data)
	if got := tree.Root(); got != hex.EncodeToString(want[:]) {
		t.Errorf("root = %s, want %s", got, hex.EncodeToString(want[:]))
	}
	if tree.LeafCount() != 1 {
		t.Errorf("leaf count = %d, want 1", tree.LeafCount())
	}
	if tree.Depth() != 1 {
		t.Errorf("depth = %d, want 1", tree.Depth())
	}
}

// 3. A two-leaf tree's root is SHA256(SHA256(l0) || SHA256(l1)).
func TestTwoLeaves(t *testing.T) {
	const chunk = 8
	data := []byte("AAAAAAAABBBBBBBB")

	tree, err := BuildTree(data, chunk)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}

	want := concatHash(hashOf(data[:8]), hashOf(data[8:]))
	if got := tree.Root(); got != hex.EncodeToString(want[:]) {
		t.Errorf("root = %s, want %s", got, hex.EncodeToString(want[:]))
	}
	if tree.Depth() != 2 {
		t.Errorf("depth = %d, want 2", tree.Depth())
	}
}

// 4. Odd leaf counts duplicate the last node, and that is what the root shows.
func TestOddLeaves(t *testing.T) {
	const chunk = 4
	data := []byte("AAAABBBBCCCC") // three leaves

	tree, err := BuildTree(data, chunk)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}

	h0, h1, h2 := hashOf(data[0:4]), hashOf(data[4:8]), hashOf(data[8:12])
	left := concatHash(h0, h1)
	right := concatHash(h2, h2) // duplicate-last
	want := concatHash(left, right)

	if got := tree.Root(); got != hex.EncodeToString(want[:]) {
		t.Errorf("root = %s, want %s (duplicate-last policy)", got, hex.EncodeToString(want[:]))
	}
	if tree.LeafCount() != 3 {
		t.Errorf("leaf count = %d, want 3", tree.LeafCount())
	}
}

// 5. Power-of-two trees match hand-computed roots.
func TestPowerOfTwoLeaves(t *testing.T) {
	for _, leaves := range []int{4, 8, 16} {
		t.Run(fmt.Sprintf("%dleaves", leaves), func(t *testing.T) {
			const chunk = 16
			data := chunks(leaves, chunk)

			tree, err := BuildTree(data, chunk)
			if err != nil {
				t.Fatalf("BuildTree: %v", err)
			}

			// Recompute independently, level by level.
			level := make([][32]byte, leaves)
			for i := 0; i < leaves; i++ {
				level[i] = hashOf(data[i*chunk : (i+1)*chunk])
			}
			for len(level) > 1 {
				next := make([][32]byte, 0, len(level)/2)
				for i := 0; i < len(level); i += 2 {
					next = append(next, concatHash(level[i], level[i+1]))
				}
				level = next
			}

			if got, want := tree.Root(), hex.EncodeToString(level[0][:]); got != want {
				t.Errorf("root = %s, want %s", got, want)
			}

			wantDepth := 1
			for n := leaves; n > 1; n /= 2 {
				wantDepth++
			}
			if tree.Depth() != wantDepth {
				t.Errorf("depth = %d, want %d", tree.Depth(), wantDepth)
			}
		})
	}
}

// 6. A large tree produces the same root every time it is built.
func TestLargeTree(t *testing.T) {
	const leaves = 10000
	const chunk = 64
	data := chunks(leaves, chunk)

	first, err := BuildTree(data, chunk)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	if first.LeafCount() != leaves {
		t.Fatalf("leaf count = %d, want %d", first.LeafCount(), leaves)
	}

	root := first.Root()
	for i := 0; i < 100; i++ {
		again, err := BuildTree(data, chunk)
		if err != nil {
			t.Fatalf("BuildTree iteration %d: %v", i, err)
		}
		if again.Root() != root {
			t.Fatalf("iteration %d: root %s != %s (construction is not deterministic)", i, again.Root(), root)
		}
	}
}

// 7. A proof can be produced for any leaf.
func TestProofGeneration(t *testing.T) {
	const chunk = 32
	const leaves = 37 // deliberately odd at several levels
	data := chunks(leaves, chunk)

	tree, err := BuildTree(data, chunk)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}

	for i := 0; i < leaves; i++ {
		proof, err := tree.GenerateProof(i)
		if err != nil {
			t.Fatalf("GenerateProof(%d): %v", i, err)
		}
		if proof.LeafIndex != i {
			t.Errorf("proof.LeafIndex = %d, want %d", proof.LeafIndex, i)
		}
		if len(proof.Siblings) != tree.Depth()-1 {
			t.Errorf("leaf %d: %d siblings, want %d", i, len(proof.Siblings), tree.Depth()-1)
		}
		if !VerifyProof(tree.Root(), data[i*chunk:(i+1)*chunk], proof) {
			t.Errorf("leaf %d: generated proof does not verify", i)
		}
	}

	if _, err := tree.GenerateProof(-1); !errors.Is(err, ErrLeafOutOfRange) {
		t.Errorf("GenerateProof(-1) error = %v, want ErrLeafOutOfRange", err)
	}
	if _, err := tree.GenerateProof(leaves); !errors.Is(err, ErrLeafOutOfRange) {
		t.Errorf("GenerateProof(%d) error = %v, want ErrLeafOutOfRange", leaves, err)
	}
}

// 8. A known-good proof validates against the root.
func TestProofVerificationValid(t *testing.T) {
	const chunk = 4096
	data := chunks(9, chunk)

	tree, err := BuildTree(data, chunk)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}

	proof, err := tree.GenerateProof(5)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	if !VerifyProof(tree.Root(), data[5*chunk:6*chunk], proof) {
		t.Fatal("valid proof failed verification")
	}
}

// 9. Modifying a single byte invalidates the proof.
func TestProofVerificationTampered(t *testing.T) {
	const chunk = 512
	data := chunks(11, chunk)

	tree, err := BuildTree(data, chunk)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}

	proof, err := tree.GenerateProof(3)
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	leaf := append([]byte(nil), data[3*chunk:4*chunk]...)
	leaf[chunk/2] ^= 0x01

	if VerifyProof(tree.Root(), leaf, proof) {
		t.Fatal("proof verified for a tampered leaf")
	}

	// A tampered sibling must also fail.
	badProof := MerkleProof{LeafIndex: proof.LeafIndex, LeafCount: proof.LeafCount}
	badProof.Siblings = append(badProof.Siblings, proof.Siblings...)
	badProof.Siblings[0].Hash = hex.EncodeToString(bytes.Repeat([]byte{0xAA}, 32))
	if VerifyProof(tree.Root(), data[3*chunk:4*chunk], badProof) {
		t.Fatal("proof verified with a forged sibling hash")
	}

	// Malformed proofs must be rejected, not panic.
	for name, bad := range map[string]MerkleProof{
		"bad position": {LeafIndex: 0, Siblings: []ProofNode{{Hash: hex.EncodeToString(make([]byte, 32)), Position: "middle"}}},
		"bad hex":      {LeafIndex: 0, Siblings: []ProofNode{{Hash: "zzzz", Position: "left"}}},
		"short hash":   {LeafIndex: 0, Siblings: []ProofNode{{Hash: "aabb", Position: "left"}}},
		"neg index":    {LeafIndex: -1},
	} {
		if VerifyProof(tree.Root(), data[:chunk], bad) {
			t.Errorf("%s: malformed proof verified", name)
		}
	}
}

// 10. Distinct inputs produce distinct roots.
func TestDifferentInputsDifferentRoots(t *testing.T) {
	roots := make(map[string]string)

	for i := 0; i < 256; i++ {
		data := chunks(4, 128)
		data[i] ^= 0xFF

		tree, err := BuildTree(data, 128)
		if err != nil {
			t.Fatalf("BuildTree: %v", err)
		}
		root := tree.Root()
		if prev, dup := roots[root]; dup {
			t.Fatalf("collision: mutation at byte %d produced the same root as %s", i, prev)
		}
		roots[root] = fmt.Sprintf("mutation at byte %d", i)
	}
}

// 11. A receipt survives a JSON round trip with every field intact.
func TestRoundTripSerialization(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}

	data := chunks(20, 4096)
	receipt, _, err := Seal(data, signer, SealOptions{
		CaseID:       "11111111-2222-3333-4444-555555555555",
		ToolName:     "flight-recorder",
		ToolVersion:  "1.2.3",
		SampleProofs: 4,
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded SealReceipt
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.RootHash != receipt.RootHash {
		t.Errorf("root hash changed: %s != %s", decoded.RootHash, receipt.RootHash)
	}
	if decoded.LeafCount != receipt.LeafCount || decoded.TreeDepth != receipt.TreeDepth {
		t.Errorf("tree parameters changed: %+v", decoded)
	}
	if decoded.ChunkSizeBytes != receipt.ChunkSizeBytes {
		t.Errorf("chunk size changed: %d != %d", decoded.ChunkSizeBytes, receipt.ChunkSizeBytes)
	}
	if decoded.OddLeafPolicy != OddLeafPolicyDuplicateLast {
		t.Errorf("odd leaf policy = %q", decoded.OddLeafPolicy)
	}
	if decoded.Signature != receipt.Signature || decoded.SignerKeyID != receipt.SignerKeyID {
		t.Error("signature fields changed across serialisation")
	}
	if !decoded.CaptureStartTime.Equal(receipt.CaptureStartTime) {
		t.Error("capture start time changed across serialisation")
	}
	if decoded.DumpSHA256 != receipt.DumpSHA256 || decoded.DumpSizeBytes != receipt.DumpSizeBytes {
		t.Error("payload digest fields changed across serialisation")
	}

	// The decoded receipt must still verify the original data.
	res, err := decoded.Verify(data, signer.Public())
	if err != nil {
		t.Fatalf("Verify after round trip: %v", err)
	}
	if !res.OK() {
		t.Errorf("round-tripped receipt failed verification: %+v", res)
	}
}

// 12. Concurrent construction of the same tree yields the same root.
func TestConcurrentTreeConstruction(t *testing.T) {
	const goroutines = 10
	data := chunks(500, 1024)

	var wg sync.WaitGroup
	roots := make([]string, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tree, err := BuildTree(data, 1024)
			if err != nil {
				t.Errorf("goroutine %d: %v", i, err)
				return
			}
			roots[i] = tree.Root()
		}(i)
	}
	wg.Wait()

	for i := 1; i < goroutines; i++ {
		if roots[i] != roots[0] {
			t.Fatalf("goroutine %d root %s != goroutine 0 root %s", i, roots[i], roots[0])
		}
	}
}

// Concurrent proof generation from one tree must also be safe: the pipeline
// generates proofs from multiple workers against a shared tree.
func TestConcurrentProofGeneration(t *testing.T) {
	const chunk = 256
	const leaves = 64
	data := chunks(leaves, chunk)

	tree, err := BuildTree(data, chunk)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, leaves)

	for i := 0; i < leaves; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			proof, err := tree.GenerateProof(i)
			if err != nil {
				errs <- err
				return
			}
			if !VerifyProof(tree.Root(), data[i*chunk:(i+1)*chunk], proof) {
				errs <- fmt.Errorf("leaf %d proof did not verify", i)
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// -----------------------------------------------------------------------------
// Property-based tests
// -----------------------------------------------------------------------------

// Property: every leaf of every tree has a proof that verifies.
func TestPropertyAllProofsVerify(t *testing.T) {
	property := func(payload []byte, chunkSeed uint8) bool {
		if len(payload) == 0 {
			return true
		}
		chunkSize := int(chunkSeed)%64 + 1

		tree, err := BuildTree(payload, chunkSize)
		if err != nil {
			return false
		}

		for i := 0; i < tree.LeafCount(); i++ {
			proof, err := tree.GenerateProof(i)
			if err != nil {
				return false
			}
			start := i * chunkSize
			end := start + chunkSize
			if end > len(payload) {
				end = len(payload)
			}
			if !VerifyProof(tree.Root(), payload[start:end], proof) {
				return false
			}
		}
		return true
	}

	if err := quick.Check(property, &quick.Config{MaxCount: 1000}); err != nil {
		t.Error(err)
	}
}

// Property: mutating any byte changes the root.
func TestPropertyMutationChangesRoot(t *testing.T) {
	property := func(payload []byte, pos uint16) bool {
		if len(payload) == 0 {
			return true
		}

		before, err := BuildTree(payload, 16)
		if err != nil {
			return false
		}

		mutated := append([]byte(nil), payload...)
		idx := int(pos) % len(mutated)
		mutated[idx] ^= 0xFF

		after, err := BuildTree(mutated, 16)
		if err != nil {
			return false
		}

		return before.Root() != after.Root()
	}

	if err := quick.Check(property, &quick.Config{MaxCount: 1000}); err != nil {
		t.Error(err)
	}
}

// Property: the root is a pure function of the input and the chunk size.
func TestPropertyRootIsDeterministic(t *testing.T) {
	property := func(payload []byte) bool {
		if len(payload) == 0 {
			return true
		}
		a, err := BuildTree(payload, 4096)
		if err != nil {
			return false
		}
		b, err := BuildTree(payload, 4096)
		if err != nil {
			return false
		}
		return a.Root() == b.Root() && a.LeafCount() == b.LeafCount() && a.Depth() == b.Depth()
	}

	if err := quick.Check(property, &quick.Config{MaxCount: 1000}); err != nil {
		t.Error(err)
	}
}

// VerifyData is the path an examiner uses; it must reject a leaf-count lie as
// well as a content change.
func TestVerifyDataDetectsLeafCountMismatch(t *testing.T) {
	data := chunks(5, 100)
	tree, err := BuildTree(data, 100)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}

	if err := VerifyData(data, 100, tree.LeafCount(), tree.Root()); err != nil {
		t.Fatalf("VerifyData on good data: %v", err)
	}
	if err := VerifyData(data, 100, tree.LeafCount()+1, tree.Root()); err == nil {
		t.Error("VerifyData accepted a mismatched leaf count")
	}

	mutated := append([]byte(nil), data...)
	mutated[0] ^= 0xFF
	if err := VerifyData(mutated, 100, tree.LeafCount(), tree.Root()); err == nil {
		t.Error("VerifyData accepted mutated data")
	}
}

// -----------------------------------------------------------------------------
// Benchmarks
// -----------------------------------------------------------------------------

// BenchmarkSeal100MB is the performance gate from the build plan: sealing a
// 100 MB dump must stay under 2 seconds, otherwise the seal, not the
// acquisition, becomes the bottleneck in the capture window.
func BenchmarkSeal100MB(b *testing.B) {
	data := make([]byte, 100<<20)
	if _, err := rand.Read(data); err != nil {
		b.Fatalf("rand: %v", err)
	}

	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := BuildTree(data, DefaultChunkSize); err != nil {
			b.Fatalf("BuildTree: %v", err)
		}
	}
}

func BenchmarkGenerateProof(b *testing.B) {
	data := chunks(4096, 4096)
	tree, err := BuildTree(data, 4096)
	if err != nil {
		b.Fatalf("BuildTree: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := tree.GenerateProof(i % tree.LeafCount()); err != nil {
			b.Fatalf("GenerateProof: %v", err)
		}
	}
}
