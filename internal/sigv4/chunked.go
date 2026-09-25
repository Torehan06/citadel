package sigv4

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// aws-chunked body layout (https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html):
//
//	<hex-size>;chunk-signature=<sig>\r\n<data>\r\n      signed chunks
//	...
//	0;chunk-signature=<sig>\r\n                          final chunk
//	x-amz-checksum-crc32:<b64>\r\n                       trailers (TRAILER variants)
//	x-amz-trailer-signature:<sig>\r\n                    (signed trailer variant only)
//	\r\n
//
// Unsigned trailer bodies (STREAMING-UNSIGNED-PAYLOAD-TRAILER) are the same
// without the ;chunk-signature extensions and without a trailer signature.
//
// Each chunk signature signs:
//
//	AWS4-HMAC-SHA256-PAYLOAD \n date \n scope \n previous-signature \n sha256("") \n sha256(chunk)
//
// chained from the seed signature in the Authorization header, so chunks can
// neither be altered nor reordered.

const maxChunkHeader = 4096

func newLineReader(r io.Reader) *bufio.Reader { return bufio.NewReaderSize(r, 64<<10) }

type chunkedReader struct {
	r    *bufio.Reader
	body io.Closer

	signed, trailer bool
	key             []byte
	amzDate, scope  string
	prevSig         string

	remaining        int64  // bytes left in the current chunk
	chunkSig         string // signature claimed for the current chunk
	chunkHash        hash.Hash
	remainingDecoded int64 // X-Amz-Decoded-Content-Length minus bytes delivered
	trailers         http.Header
	err              error
}

func (c *chunkedReader) Close() error { return c.body.Close() }

func incomplete() *Error {
	return errorf(400, "IncompleteBody", "The request body terminated unexpectedly")
}

func badChunkSig() *Error {
	return errorf(403, "SignatureDoesNotMatch",
		"The request signature we calculated does not match the signature you provided. Check your key and signing method.")
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	for c.remaining == 0 {
		if err := c.nextChunk(); err != nil {
			c.err = err
			return 0, err
		}
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.r.Read(p)
	c.remaining -= int64(n)
	c.remainingDecoded -= int64(n)
	if c.chunkHash != nil {
		c.chunkHash.Write(p[:n])
	}
	if c.remainingDecoded < 0 {
		c.err = errorf(400, "IncompleteBody", "The decoded body is longer than X-Amz-Decoded-Content-Length")
		return n, c.err
	}
	if err == io.EOF {
		err = incomplete()
	}
	if err != nil {
		c.err = err
		return n, err
	}
	if c.remaining == 0 {
		if err := c.finishChunk(); err != nil {
			c.err = err
			return n, err
		}
	}
	return n, nil
}

func (c *chunkedReader) readLine() (string, error) {
	line, err := c.r.ReadSlice('\n')
	if err == bufio.ErrBufferFull || len(line) > maxChunkHeader {
		return "", errorf(400, "InvalidChunkSizeError", "Chunk header too long")
	}
	if err != nil {
		return "", incomplete()
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

// nextChunk reads a chunk header. On the final (zero-size) chunk it also reads
// the trailers and returns io.EOF.
func (c *chunkedReader) nextChunk() error {
	line, err := c.readLine()
	if err != nil {
		return err
	}
	sizeStr, ext, _ := strings.Cut(line, ";")
	size, perr := strconv.ParseInt(strings.TrimSpace(sizeStr), 16, 64)
	if perr != nil || size < 0 {
		return errorf(400, "InvalidChunkSizeError", "Only the last chunk is allowed to have a size less than 8192 bytes")
	}
	c.chunkSig = ""
	if sig, ok := strings.CutPrefix(ext, "chunk-signature="); ok {
		c.chunkSig = strings.ToLower(strings.TrimSpace(sig))
	}
	if c.signed && c.chunkSig == "" {
		return errorf(400, "InvalidChunkSizeError", "chunk-signature missing")
	}
	c.chunkHash = nil
	if c.signed {
		c.chunkHash = sha256.New()
	}
	if size > 0 {
		c.remaining = size
		return nil
	}
	// Final chunk.
	if c.signed {
		if err := c.verifyChunk(hexSHA256(nil)); err != nil {
			return err
		}
	}
	if err := c.readTrailers(); err != nil {
		return err
	}
	if c.remainingDecoded != 0 {
		return incomplete()
	}
	return io.EOF
}

// finishChunk consumes the CRLF after a chunk's data and checks its signature.
func (c *chunkedReader) finishChunk() error {
	var crlf [2]byte
	if _, err := io.ReadFull(c.r, crlf[:]); err != nil || crlf != [2]byte{'\r', '\n'} {
		return incomplete()
	}
	if c.signed {
		return c.verifyChunk(hex.EncodeToString(c.chunkHash.Sum(nil)))
	}
	return nil
}

func (c *chunkedReader) verifyChunk(dataHash string) error {
	sts := "AWS4-HMAC-SHA256-PAYLOAD\n" + c.amzDate + "\n" + c.scope + "\n" + c.prevSig + "\n" + emptySHA256 + "\n" + dataHash
	want := hex.EncodeToString(hmacSHA256(c.key, sts))
	if !hmac.Equal([]byte(want), []byte(c.chunkSig)) {
		return badChunkSig()
	}
	c.prevSig = want
	return nil
}

func (c *chunkedReader) readTrailers() error {
	var canonical strings.Builder
	var trailerSig string
	for {
		line, err := c.readLine()
		if err != nil {
			if !c.trailer {
				// Some encoders end right after "0;chunk-signature=...\r\n".
				return nil
			}
			return err
		}
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return errorf(400, "MalformedTrailerError", "The request contained trailing data that was not well-formed or did not conform to our published schema.")
		}
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		if name == "x-amz-trailer-signature" {
			trailerSig = strings.ToLower(value)
			continue
		}
		canonical.WriteString(name + ":" + value + "\n")
		c.trailers.Add(name, value)
	}
	if c.signed && c.trailer {
		sts := "AWS4-HMAC-SHA256-TRAILER\n" + c.amzDate + "\n" + c.scope + "\n" + c.prevSig + "\n" + hexSHA256([]byte(canonical.String()))
		want := hex.EncodeToString(hmacSHA256(c.key, sts))
		if !hmac.Equal([]byte(want), []byte(trailerSig)) {
			return badChunkSig()
		}
	}
	return nil
}
