// Package evidence writes, reads, verifies and ages out evidence bundles.
//
// A bundle is a directory, not an archive, so that the metadata a responder
// needs first (what was captured, when, from where, and whether it verifies)
// can be read without decrypting or unpacking the payload:
//
//	evidence/<case-id>/
//	  manifest.json        file inventory with digests
//	  metadata.jsonld      CASE/UCO bundle (plaintext: metadata and hashes only)
//	  receipt.json         signed Merkle receipt (plaintext)
//	  regions.json         memory map and per-region acquisition outcome
//	  dump.bin.zst.enc     the payload: zstd compressed, then AES-256-GCM
//	  dump.bin.sha256      digest of the PLAINTEXT payload
package evidence

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Payload container format identifiers.
const (
	// EncMagic prefixes every encrypted payload so a stray file can be
	// identified years later without external context.
	EncMagic = "FRENC001"
	// DefaultFrameSize is the plaintext size of one AEAD frame.
	//
	// The payload is encrypted in frames rather than as one AEAD message for
	// two reasons: a single-shot seal of a 512 MB dump would require the whole
	// ciphertext in memory (on a DaemonSet capped at 256 MiB), and a framed
	// layout allows a damaged bundle to be partially recovered - everything up
	// to the corrupted frame still decrypts and still verifies against its
	// Merkle leaves.
	DefaultFrameSize = 1 << 20 // 1 MiB
	// noncePrefixLen is the random per-file portion of each frame nonce.
	noncePrefixLen = 8
	// maxFrameCiphertext bounds a frame read from an untrusted file.
	maxFrameCiphertext = DefaultFrameSize * 4
)

// ErrCorruptPayload indicates the encrypted payload is malformed or truncated.
var ErrCorruptPayload = errors.New("evidence: encrypted payload is corrupt or truncated")

// ErrAuthenticationFailed indicates a frame failed its GCM authentication tag.
// This means the ciphertext was modified or the wrong key was supplied - both
// are evidence-integrity events, not routine errors.
var ErrAuthenticationFailed = errors.New("evidence: payload authentication failed (wrong key or tampered ciphertext)")

// frameWriter encrypts a stream into authenticated frames.
//
// Layout:
//
//	"FRENC001" | uint8 version | uint8 noncePrefixLen | noncePrefix
//	then, repeated: uint32be ciphertextLen | ciphertext(+16 byte tag)
//	terminated by: uint32be 0
//
// The nonce for frame N is noncePrefix || uint32be(N), which is unique per
// frame within a file and unique across files because noncePrefix is random.
// Frame counters are rejected past 2^32-2, well beyond any plausible dump.
type frameWriter struct {
	w           io.Writer
	aead        cipher.AEAD
	noncePrefix []byte
	counter     uint32
	buf         []byte
	frameSize   int
	closed      bool
}

func newFrameWriter(w io.Writer, key []byte, frameSize int) (*frameWriter, []byte, error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("evidence: AES-256 key must be 32 bytes, got %d", len(key))
	}
	if frameSize <= 0 {
		frameSize = DefaultFrameSize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("evidence: create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("evidence: create GCM: %w", err)
	}
	if aead.NonceSize() != noncePrefixLen+4 {
		return nil, nil, fmt.Errorf("evidence: unexpected GCM nonce size %d", aead.NonceSize())
	}

	prefix := make([]byte, noncePrefixLen)
	if _, err := rand.Read(prefix); err != nil {
		return nil, nil, fmt.Errorf("evidence: generate nonce prefix: %w", err)
	}

	header := make([]byte, 0, len(EncMagic)+2+noncePrefixLen)
	header = append(header, EncMagic...)
	header = append(header, 1, noncePrefixLen)
	header = append(header, prefix...)
	if _, err := w.Write(header); err != nil {
		return nil, nil, fmt.Errorf("evidence: write payload header: %w", err)
	}

	return &frameWriter{
		w:           w,
		aead:        aead,
		noncePrefix: prefix,
		buf:         make([]byte, 0, frameSize),
		frameSize:   frameSize,
	}, prefix, nil
}

func (f *frameWriter) Write(p []byte) (int, error) {
	if f.closed {
		return 0, errors.New("evidence: write to closed payload writer")
	}

	written := 0
	for len(p) > 0 {
		space := f.frameSize - len(f.buf)
		n := len(p)
		if n > space {
			n = space
		}
		f.buf = append(f.buf, p[:n]...)
		p = p[n:]
		written += n

		if len(f.buf) == f.frameSize {
			if err := f.flushFrame(); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

func (f *frameWriter) flushFrame() error {
	if len(f.buf) == 0 {
		return nil
	}
	if f.counter == ^uint32(0)-1 {
		return errors.New("evidence: frame counter exhausted")
	}

	nonce := make([]byte, f.aead.NonceSize())
	copy(nonce, f.noncePrefix)
	binary.BigEndian.PutUint32(nonce[noncePrefixLen:], f.counter)

	ciphertext := f.aead.Seal(nil, nonce, f.buf, nil)

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ciphertext)))
	if _, err := f.w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("evidence: write frame length: %w", err)
	}
	if _, err := f.w.Write(ciphertext); err != nil {
		return fmt.Errorf("evidence: write frame: %w", err)
	}

	f.counter++
	f.buf = f.buf[:0]
	return nil
}

func (f *frameWriter) Close() error {
	if f.closed {
		return nil
	}
	if err := f.flushFrame(); err != nil {
		return err
	}
	var terminator [4]byte
	if _, err := f.w.Write(terminator[:]); err != nil {
		return fmt.Errorf("evidence: write payload terminator: %w", err)
	}
	f.closed = true
	return nil
}

// frameReader decrypts a stream produced by frameWriter.
type frameReader struct {
	r       io.Reader
	aead    cipher.AEAD
	prefix  []byte
	counter uint32
	buf     []byte
	eof     bool
}

func newFrameReader(r io.Reader, key []byte) (*frameReader, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("evidence: AES-256 key must be 32 bytes, got %d", len(key))
	}

	header := make([]byte, len(EncMagic)+2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("%w: reading header: %v", ErrCorruptPayload, err)
	}
	if string(header[:len(EncMagic)]) != EncMagic {
		return nil, fmt.Errorf("%w: bad magic %q", ErrCorruptPayload, header[:len(EncMagic)])
	}
	if header[len(EncMagic)] != 1 {
		return nil, fmt.Errorf("evidence: unsupported payload format version %d", header[len(EncMagic)])
	}
	prefixLen := int(header[len(EncMagic)+1])
	if prefixLen != noncePrefixLen {
		return nil, fmt.Errorf("%w: nonce prefix length %d", ErrCorruptPayload, prefixLen)
	}

	prefix := make([]byte, prefixLen)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return nil, fmt.Errorf("%w: reading nonce prefix: %v", ErrCorruptPayload, err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("evidence: create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("evidence: create GCM: %w", err)
	}

	return &frameReader{r: r, aead: aead, prefix: prefix}, nil
}

func (f *frameReader) Read(p []byte) (int, error) {
	for len(f.buf) == 0 {
		if f.eof {
			return 0, io.EOF
		}
		if err := f.readFrame(); err != nil {
			return 0, err
		}
	}
	n := copy(p, f.buf)
	f.buf = f.buf[n:]
	return n, nil
}

func (f *frameReader) readFrame() error {
	var lenBuf [4]byte
	if _, err := io.ReadFull(f.r, lenBuf[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: payload ended without a terminator", ErrCorruptPayload)
		}
		return fmt.Errorf("%w: reading frame length: %v", ErrCorruptPayload, err)
	}

	length := binary.BigEndian.Uint32(lenBuf[:])
	if length == 0 {
		f.eof = true
		return io.EOF
	}
	if length > maxFrameCiphertext {
		return fmt.Errorf("%w: frame length %d exceeds maximum", ErrCorruptPayload, length)
	}

	ciphertext := make([]byte, length)
	if _, err := io.ReadFull(f.r, ciphertext); err != nil {
		return fmt.Errorf("%w: reading frame body: %v", ErrCorruptPayload, err)
	}

	nonce := make([]byte, f.aead.NonceSize())
	copy(nonce, f.prefix)
	binary.BigEndian.PutUint32(nonce[noncePrefixLen:], f.counter)

	plaintext, err := f.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("%w (frame %d)", ErrAuthenticationFailed, f.counter)
	}

	f.counter++
	f.buf = plaintext
	return nil
}
