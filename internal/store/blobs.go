package store

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Blobs is the content-addressed byte store: blobs/sha256/ab/cd/<hex>.
// Uploads stream to blobs/tmp first and are renamed into place only after the
// caller has checked the digests (see Pending), so a half-written or rejected
// upload is never visible under its address.
type Blobs struct {
	root string
	// mu orders Commit against the sweeper's check-and-remove, so a blob
	// being reused by a new upload is never deleted underneath it (gc.go).
	mu sync.Mutex
}

// OpenBlobs creates the directory layout under root if needed.
func OpenBlobs(root string) (*Blobs, error) {
	for _, d := range []string{"tmp", "sha256"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			return nil, err
		}
	}
	return &Blobs{root: root}, nil
}

// Path returns where the blob with this SHA-256 hex digest lives.
func (b *Blobs) Path(sha string) string {
	if len(sha) < 4 {
		return filepath.Join(b.root, "sha256", "invalid", sha)
	}
	return filepath.Join(b.root, "sha256", sha[:2], sha[2:4], sha)
}

// Open opens a committed blob for reading.
func (b *Blobs) Open(sha string) (*os.File, error) { return os.Open(b.Path(sha)) }

// Pending is an upload that has been written and fsynced to a temp file but
// not yet given its address. Call Commit or Abort exactly once.
type Pending struct {
	b      *Blobs
	tmp    string
	Size   int64
	SHA256 string // hex; the blob's address
	MD5    []byte // raw digest; S3's ETag for single-part objects
	done   bool
}

// Write streams r to a temp file while computing SHA-256, MD5, and any extra
// hashes the caller passes (for example a requested CRC32 checksum). It never
// holds the whole body in memory. On a read error the temp file is removed and
// the error returned unchanged, so callers can map it to a protocol error.
func (b *Blobs) Write(r io.Reader, extra ...hash.Hash) (*Pending, error) {
	name, err := randomName()
	if err != nil {
		return nil, err
	}
	tmp := filepath.Join(b.root, "tmp", name)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	sh, mh := sha256.New(), md5.New()
	writers := []io.Writer{f, sh, mh}
	for _, h := range extra {
		writers = append(writers, h)
	}
	n, err := io.CopyBuffer(io.MultiWriter(writers...), r, make([]byte, 256<<10))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	return &Pending{
		b: b, tmp: tmp, Size: n,
		SHA256: hex.EncodeToString(sh.Sum(nil)),
		MD5:    mh.Sum(nil),
	}, nil
}

// Commit moves the upload to its content address. If identical content is
// already stored, the temp copy is simply dropped.
func (p *Pending) Commit() error {
	if p.done {
		return errors.New("blob: pending upload already finished")
	}
	p.done = true
	dst := p.b.Path(p.SHA256)
	p.b.mu.Lock()
	defer p.b.mu.Unlock()
	if _, err := os.Stat(dst); err == nil {
		// Identical content is already stored. Refresh its mtime so the
		// sweeper's grace period protects it until our metadata commits.
		now := time.Now()
		_ = os.Chtimes(dst, now, now)
		return os.Remove(p.tmp)
	}
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		_ = os.Remove(p.tmp)
		return err
	}
	if err := os.Rename(p.tmp, dst); err != nil {
		_ = os.Remove(p.tmp)
		return fmt.Errorf("blob commit: %w", err)
	}
	return syncDir(dir)
}

// Abort discards the upload. Safe to call after Commit (it does nothing then),
// so callers can `defer p.Abort()`.
func (p *Pending) Abort() {
	if p.done {
		return
	}
	p.done = true
	_ = os.Remove(p.tmp)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	// Some platforms can't fsync a directory; the rename is still atomic.
	_ = d.Sync()
	return nil
}

func randomName() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
