package s3

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"net/http"
	"strings"
)

// Flexible checksums: https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html
// A client names one algorithm, either with an x-amz-checksum-<algo> header
// carrying the value up front, or with x-amz-trailer when the value follows
// an aws-chunked body. S3 verifies it, stores it, and returns it on GET/HEAD
// when asked (x-amz-checksum-mode: ENABLED). Objects uploaded without one
// get a CRC64NVME, as S3 has done by default since 2025.

var crc64NVMETable = crc64.MakeTable(0x9a6c9329ac4bc9b5) // reflected CRC-64/NVME polynomial

var checksumAlgorithms = []string{"CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256"}

func newChecksum(algo string) hash.Hash {
	switch algo {
	case "CRC32":
		return crc32.NewIEEE()
	case "CRC32C":
		return crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case "CRC64NVME":
		return crc64.New(crc64NVMETable)
	case "SHA1":
		return sha1.New()
	case "SHA256":
		return sha256.New()
	}
	return nil
}

// checksumHeader is the header name carrying an algorithm's value.
func checksumHeader(algo string) string { return "x-amz-checksum-" + strings.ToLower(algo) }

func encodeChecksum(h hash.Hash) string { return base64.StdEncoding.EncodeToString(h.Sum(nil)) }

// requestedChecksum works out which checksum the client is sending and, when
// it is in a header, its value. For trailers the value arrives after the body.
type requestedChecksum struct {
	Algo    string // "" when none
	Value   string // from the header; empty for trailers until the body is read
	Trailer bool
}

func parseRequestedChecksum(r *http.Request) (requestedChecksum, *Error) {
	var rc requestedChecksum
	for _, a := range checksumAlgorithms {
		if v := r.Header.Get(checksumHeader(a)); v != "" {
			if rc.Algo != "" {
				return rc, errInvalidArgument("Expecting a single x-amz-checksum- header. Multiple checksum Types are not allowed.")
			}
			rc.Algo, rc.Value = a, v
		}
	}
	if t := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Amz-Trailer"))); t != "" {
		algo := ""
		for _, a := range checksumAlgorithms {
			if t == checksumHeader(a) {
				algo = a
			}
		}
		if algo == "" {
			return rc, errInvalidArgument("The value specified in the x-amz-trailer header is not supported")
		}
		if rc.Algo != "" && rc.Algo != algo {
			return rc, errInvalidArgument("Expecting a single x-amz-checksum- header. Multiple checksum Types are not allowed.")
		}
		rc.Algo, rc.Trailer = algo, true
	}
	if rc.Algo == "" {
		if a := strings.ToUpper(r.Header.Get("X-Amz-Sdk-Checksum-Algorithm")); a != "" {
			if newChecksum(a) == nil {
				return rc, errInvalidArgument("Checksum algorithm provided is unsupported. Please try again with any of the valid types: [CRC32, CRC32C, CRC64NVME, SHA1, SHA256]")
			}
			// Algorithm named but no value sent: S3 computes and stores it.
			rc.Algo = a
		}
	}
	if rc.Value != "" {
		// A value that isn't a well-formed digest can never match the body.
		raw, err := base64.StdEncoding.DecodeString(rc.Value)
		if err != nil || len(raw) != newChecksum(rc.Algo).Size() {
			return rc, checksumMismatch(rc.Algo)
		}
	}
	return rc, nil
}

func checksumMismatch(algo string) *Error {
	return errf(400, "BadDigest", "The %s you specified did not match the calculated checksum.", algo)
}
