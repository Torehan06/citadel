package s3

import (
	"encoding/base64"
	"hash/crc64"
	"testing"
)

func TestValidBucketName(t *testing.T) {
	cases := map[string]bool{
		"abc": true, "my-bucket.logs": true, "0bucket9": true, "a23456789012345678901234567890123456789012345678901234567890123": true,
		"ab": false, "a234567890123456789012345678901234567890123456789012345678901234": false,
		"Bucket": false, "foo_bar": false, "-foo": false, "foo-": false, "foo..bar": false,
		"foo.-bar": false, "foo-.bar": false, "192.168.5.123": false, "xn--foo": false,
		"foo-s3alias": false, "foo--ol-s3": false, ".foo": false,
	}
	for name, want := range cases {
		if got := validBucketName(name); got != want {
			t.Errorf("validBucketName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestParseRange(t *testing.T) {
	cases := []struct {
		h                    string
		size                 int64
		start, length        int64
		partial, unsatisfied bool
	}{
		{"", 10, 0, 10, false, false},
		{"bytes=0-4", 10, 0, 5, true, false},
		{"bytes=4-", 10, 4, 6, true, false},
		{"bytes=-3", 10, 7, 3, true, false},
		{"bytes=-30", 10, 0, 10, true, false},
		{"bytes=5-100", 10, 5, 5, true, false},
		{"bytes=10-", 10, 0, 0, false, true},
		{"bytes=0-", 0, 0, 0, false, true},
		{"bytes=-0", 10, 0, 0, false, true},
		{"bytes=5-2", 10, 0, 10, false, false},     // invalid: ignored, whole object
		{"bytes=0-1,3-4", 10, 0, 10, false, false}, // multiple ranges: whole object
		{"items=0-1", 10, 0, 10, false, false},
	}
	for _, c := range cases {
		start, length, partial, err := parseRange(c.h, c.size)
		if (err != nil) != c.unsatisfied {
			t.Errorf("%q/%d: err = %v", c.h, c.size, err)
			continue
		}
		if err == nil && (start != c.start || length != c.length || partial != c.partial) {
			t.Errorf("%q/%d: got %d+%d partial=%v, want %d+%d partial=%v", c.h, c.size, start, length, partial, c.start, c.length, c.partial)
		}
	}
}

func TestSuccessor(t *testing.T) {
	cases := map[string]string{"": "", "a/": "a0", "ab": "ac", "a\xff": "b", "\xff\xff": ""}
	for in, want := range cases {
		if got := successor(in); got != want {
			t.Errorf("successor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCRC64NVME(t *testing.T) {
	// Check value for CRC-64/NVME ("123456789" -> 0xae8b14860a799888).
	if got := crc64.Checksum([]byte("123456789"), crc64NVMETable); got != 0xae8b14860a799888 {
		t.Fatalf("crc64nvme = %#x", got)
	}
	h := newChecksum("CRC32")
	h.Write([]byte("hello"))
	// base64 of big-endian CRC32 IEEE("hello") = 0x3610a686
	if got, want := encodeChecksum(h), base64.StdEncoding.EncodeToString([]byte{0x36, 0x10, 0xa6, 0x86}); got != want {
		t.Fatalf("crc32 = %s, want %s", got, want)
	}
}
