package sigv4

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Values from the AWS documentation examples:
// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
// https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
const (
	docAK     = "AKIAIOSFODNN7EXAMPLE"
	docSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

var docTime = time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

func docVerifier(now time.Time) *Verifier {
	return &Verifier{
		Now: func() time.Time { return now },
		Lookup: func(_ context.Context, ak string) (string, error) {
			if ak == docAK {
				return docSecret, nil
			}
			return "", ErrUnknownKey
		},
	}
}

func authHeader(signed, sig string) string {
	return "AWS4-HMAC-SHA256 Credential=" + docAK + "/20130524/us-east-1/s3/aws4_request,SignedHeaders=" +
		signed + ",Signature=" + sig
}

func TestSigningKeyDocExample(t *testing.T) {
	// https://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
	k := SigningKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20120215", "us-east-1", "iam")
	if got := hex.EncodeToString(k); got != "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d" {
		t.Fatalf("signing key = %s", got)
	}
}

func TestHeaderAuthDocExamples(t *testing.T) {
	cases := []struct {
		name, method, url, body string
		headers                 map[string]string
		signed, sig             string
	}{
		{
			name: "GET object", method: "GET", url: "http://examplebucket.s3.amazonaws.com/test.txt",
			headers: map[string]string{"Range": "bytes=0-9", "X-Amz-Content-Sha256": emptySHA256, "X-Amz-Date": "20130524T000000Z"},
			signed:  "host;range;x-amz-content-sha256;x-amz-date",
			sig:     "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
		},
		{
			name: "PUT object", method: "PUT", url: "http://examplebucket.s3.amazonaws.com/test$file.text",
			body: "Welcome to Amazon S3.",
			headers: map[string]string{
				"Date": "Fri, 24 May 2013 00:00:00 GMT", "X-Amz-Date": "20130524T000000Z",
				"X-Amz-Storage-Class":  "REDUCED_REDUNDANCY",
				"X-Amz-Content-Sha256": "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072",
			},
			signed: "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class",
			sig:    "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
		},
		{
			name: "GET bucket lifecycle", method: "GET", url: "http://examplebucket.s3.amazonaws.com/?lifecycle",
			headers: map[string]string{"X-Amz-Content-Sha256": emptySHA256, "X-Amz-Date": "20130524T000000Z"},
			signed:  "host;x-amz-content-sha256;x-amz-date",
			sig:     "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543",
		},
		{
			name: "list objects", method: "GET", url: "http://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J",
			headers: map[string]string{"X-Amz-Content-Sha256": emptySHA256, "X-Amz-Date": "20130524T000000Z"},
			signed:  "host;x-amz-content-sha256;x-amz-date",
			sig:     "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			newReq := func(sig string) *http.Request {
				r := httptest.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
				for k, v := range tc.headers {
					r.Header.Set(k, v)
				}
				r.Header.Set("Authorization", authHeader(tc.signed, sig))
				return r
			}
			r := newReq(tc.sig)
			a, err := docVerifier(docTime).Verify(r)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if a.AccessKey != docAK || a.Region != "us-east-1" || a.Service != "s3" {
				t.Fatalf("auth = %+v", a)
			}
			if got, err := io.ReadAll(r.Body); err != nil || string(got) != tc.body {
				t.Fatalf("body = %q, %v", got, err)
			}

			bad := strings.Repeat("0", 64)
			if _, err := docVerifier(docTime).Verify(newReq(bad)); errCode(err) != "SignatureDoesNotMatch" {
				t.Fatalf("wrong signature: got %v", err)
			}
		})
	}
}

func errCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return "non-sigv4: " + err.Error()
}

func TestPayloadHashMismatch(t *testing.T) {
	r := httptest.NewRequest("PUT", "http://examplebucket.s3.amazonaws.com/test$file.text", strings.NewReader("Welcome to Amazon S3!"))
	r.Header.Set("Date", "Fri, 24 May 2013 00:00:00 GMT")
	r.Header.Set("X-Amz-Date", "20130524T000000Z")
	r.Header.Set("X-Amz-Storage-Class", "REDUCED_REDUNDANCY")
	r.Header.Set("X-Amz-Content-Sha256", "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072")
	r.Header.Set("Authorization", authHeader("date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class",
		"98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"))
	if _, err := docVerifier(docTime).Verify(r); err != nil {
		t.Fatal(err) // the signature is over the declared hash, which is fine
	}
	if _, err := io.ReadAll(r.Body); errCode(err) != "XAmzContentSHA256Mismatch" {
		t.Fatalf("body with other content: got %v", err)
	}
}

func TestClockSkewAndErrors(t *testing.T) {
	mk := func() *http.Request {
		r := httptest.NewRequest("GET", "http://examplebucket.s3.amazonaws.com/test.txt", nil)
		r.Header.Set("Range", "bytes=0-9")
		r.Header.Set("X-Amz-Content-Sha256", emptySHA256)
		r.Header.Set("X-Amz-Date", "20130524T000000Z")
		r.Header.Set("Authorization", authHeader("host;range;x-amz-content-sha256;x-amz-date",
			"f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"))
		return r
	}
	cases := []struct {
		name  string
		now   time.Time
		tweak func(*http.Request)
		code  string
	}{
		{"14 minutes ahead ok", docTime.Add(14 * time.Minute), nil, ""},
		{"14 minutes behind ok", docTime.Add(-14 * time.Minute), nil, ""},
		{"16 minutes skew", docTime.Add(16 * time.Minute), nil, "RequestTimeTooSkewed"},
		{"future request", docTime.Add(-16 * time.Minute), nil, "RequestTimeTooSkewed"},
		{"unknown key", docTime, func(r *http.Request) {
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), docAK, "NOSUCHKEY", 1))
		}, "InvalidAccessKeyId"},
		{"no content sha", docTime, func(r *http.Request) { r.Header.Del("X-Amz-Content-Sha256") }, "InvalidRequest"},
		{"garbage content sha", docTime, func(r *http.Request) { r.Header.Set("X-Amz-Content-Sha256", "nope") }, "InvalidArgument"},
		{"malformed credential", docTime, func(r *http.Request) {
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AK/2013/us-east-1, SignedHeaders=host, Signature=00")
		}, "AuthorizationHeaderMalformed"},
		{"sigv2", docTime, func(r *http.Request) { r.Header.Set("Authorization", "AWS AK:sig") }, "InvalidRequest"},
		{"no date", docTime, func(r *http.Request) { r.Header.Del("X-Amz-Date") }, "AccessDenied"},
		{"tampered header", docTime, func(r *http.Request) { r.Header.Set("Range", "bytes=0-10") }, "SignatureDoesNotMatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := mk()
			if tc.tweak != nil {
				tc.tweak(r)
			}
			_, err := docVerifier(tc.now).Verify(r)
			if got := errCode(err); got != tc.code {
				t.Fatalf("got %q (%v), want %q", got, err, tc.code)
			}
		})
	}
}

func TestPresignedDocExample(t *testing.T) {
	const u = "http://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request" +
		"&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host" +
		"&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
	cases := []struct {
		name string
		now  time.Time
		url  string
		code string
	}{
		{"valid", docTime.Add(time.Hour), u, ""},
		{"expired", docTime.Add(86401 * time.Second), u, "AccessDenied"},
		{"tampered", docTime, strings.Replace(u, "test.txt", "test2.txt", 1), "SignatureDoesNotMatch"},
		{"too long", docTime, strings.Replace(u, "X-Amz-Expires=86400", "X-Amz-Expires=604801", 1), "AuthorizationQueryParametersError"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := docVerifier(tc.now).Verify(httptest.NewRequest("GET", tc.url, nil))
			if got := errCode(err); got != tc.code {
				t.Fatalf("got %q (%v), want %q", got, err, tc.code)
			}
			if err == nil && (!a.Presigned || a.PayloadHash != UnsignedPayload) {
				t.Fatalf("auth = %+v", a)
			}
		})
	}
}

func TestAnonymous(t *testing.T) {
	a, err := docVerifier(docTime).Verify(httptest.NewRequest("GET", "http://x/bucket/key", nil))
	if err != nil || !a.Anonymous {
		t.Fatalf("got %+v, %v", a, err)
	}
}

// docChunkedRequest reproduces the streaming PUT example from the AWS docs:
// 65 KiB of 'a' in a 64 KiB chunk and a 1 KiB chunk.
func docChunkedRequest(chunkSigs [3]string) *http.Request {
	data := bytes.Repeat([]byte{'a'}, 65*1024)
	var body bytes.Buffer
	fmt.Fprintf(&body, "10000;chunk-signature=%s\r\n", chunkSigs[0])
	body.Write(data[:65536])
	fmt.Fprintf(&body, "\r\n400;chunk-signature=%s\r\n", chunkSigs[1])
	body.Write(data[65536:])
	fmt.Fprintf(&body, "\r\n0;chunk-signature=%s\r\n\r\n", chunkSigs[2])

	r := httptest.NewRequest("PUT", "http://s3.amazonaws.com/examplebucket/chunkObject.txt", bytes.NewReader(body.Bytes()))
	r.Header.Set("X-Amz-Date", "20130524T000000Z")
	r.Header.Set("X-Amz-Storage-Class", "REDUCED_REDUNDANCY")
	r.Header.Set("X-Amz-Content-Sha256", StreamingSigned)
	r.Header.Set("Content-Encoding", "aws-chunked")
	r.Header.Set("X-Amz-Decoded-Content-Length", "66560")
	r.Header.Set("Content-Length", "66824")
	r.Header.Set("Authorization", authHeader(
		"content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class",
		"4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"))
	return r
}

var docChunkSigs = [3]string{
	"ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
	"0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
	"b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
}

func TestChunkedDocExample(t *testing.T) {
	r := docChunkedRequest(docChunkSigs)
	if r.ContentLength != 66824 {
		t.Fatalf("encoded length = %d, doc says 66824", r.ContentLength)
	}
	a, err := docVerifier(docTime).Verify(r)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Streaming || a.DecodedLength != 66560 {
		t.Fatalf("auth = %+v", a)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{'a'}, 66560)) {
		t.Fatalf("decoded %d bytes", len(got))
	}
}

func TestChunkedBadChunkSignature(t *testing.T) {
	for i := range docChunkSigs {
		sigs := docChunkSigs
		sigs[i] = strings.Repeat("1", 64)
		r := docChunkedRequest(sigs)
		if _, err := docVerifier(docTime).Verify(r); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(r.Body); errCode(err) != "SignatureDoesNotMatch" {
			t.Fatalf("chunk %d tampered: got %v", i, err)
		}
	}
}

// signedTrailerBody is an independent encoder (client side) for the
// STREAMING-*-TRAILER formats, used to round-trip the decoder.
func trailerBody(key []byte, seed, amzDate, scope string, chunks [][]byte, trailerName, trailerValue string, signed bool) []byte {
	var b bytes.Buffer
	prev := seed
	sign := func(data []byte) string {
		sts := "AWS4-HMAC-SHA256-PAYLOAD\n" + amzDate + "\n" + scope + "\n" + prev + "\n" + emptySHA256 + "\n" + hexSHA256(data)
		prev = hex.EncodeToString(hmacSHA256(key, sts))
		return prev
	}
	for _, c := range append(chunks, nil) {
		if signed {
			fmt.Fprintf(&b, "%x;chunk-signature=%s\r\n", len(c), sign(c))
		} else {
			fmt.Fprintf(&b, "%x\r\n", len(c))
		}
		if len(c) > 0 {
			b.Write(c)
			b.WriteString("\r\n")
		}
	}
	fmt.Fprintf(&b, "%s:%s\r\n", trailerName, trailerValue)
	if signed {
		canon := trailerName + ":" + trailerValue + "\n"
		sts := "AWS4-HMAC-SHA256-TRAILER\n" + amzDate + "\n" + scope + "\n" + prev + "\n" + hexSHA256([]byte(canon))
		fmt.Fprintf(&b, "x-amz-trailer-signature:%s\r\n", hex.EncodeToString(hmacSHA256(key, sts)))
	}
	b.WriteString("\r\n")
	return b.Bytes()
}

// signHeaders signs r (client side) with the doc credentials.
func signHeaders(r *http.Request, signed []string, payload string) string {
	amzDate := "20130524T000000Z"
	scope := "20130524/us-east-1/s3/aws4_request"
	creq := CanonicalRequest(r, "s3", signed, r.URL.RawQuery, "", payload)
	key := SigningKey(docSecret, "20130524", "us-east-1", "s3")
	sig := hex.EncodeToString(hmacSHA256(key, StringToSign(amzDate, scope, creq)))
	r.Header.Set("Authorization", authHeader(strings.Join(signed, ";"), sig))
	return sig
}

func TestChunkedTrailers(t *testing.T) {
	chunks := [][]byte{bytes.Repeat([]byte("x"), 8192), []byte("tail")}
	key := SigningKey(docSecret, "20130524", "us-east-1", "s3")
	for _, tc := range []struct {
		name    string
		payload string
		signed  bool
		corrupt bool
		code    string
	}{
		{"unsigned trailer", StreamingUnsigned, false, false, ""},
		{"signed trailer", StreamingSignedTrailer, true, false, ""},
		{"signed trailer tampered", StreamingSignedTrailer, true, true, "SignatureDoesNotMatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("PUT", "http://127.0.0.1/bucket/key", nil)
			r.Header.Set("X-Amz-Date", "20130524T000000Z")
			r.Header.Set("X-Amz-Content-Sha256", tc.payload)
			r.Header.Set("X-Amz-Trailer", "x-amz-checksum-crc32")
			r.Header.Set("X-Amz-Decoded-Content-Length", "8196")
			seed := signHeaders(r, []string{"host", "x-amz-content-sha256", "x-amz-date", "x-amz-decoded-content-length", "x-amz-trailer"}, tc.payload)
			value := "AAAAAA=="
			body := trailerBody(key, seed, "20130524T000000Z", "20130524/us-east-1/s3/aws4_request", chunks, "x-amz-checksum-crc32", value, tc.signed)
			if tc.corrupt {
				body = bytes.Replace(body, []byte(value), []byte("BBBBBB=="), 1)
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			if _, err := docVerifier(docTime).Verify(r); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(r.Body)
			if code := errCode(err); code != tc.code {
				t.Fatalf("read: got %q (%v), want %q", code, err, tc.code)
			}
			if tc.code == "" {
				if len(got) != 8196 || r.Trailer.Get("x-amz-checksum-crc32") != value {
					t.Fatalf("decoded %d bytes, trailer %q", len(got), r.Trailer.Get("x-amz-checksum-crc32"))
				}
			}
		})
	}
}

func TestChunkedTruncated(t *testing.T) {
	r := docChunkedRequest(docChunkSigs)
	full, _ := io.ReadAll(r.Body)
	r = docChunkedRequest(docChunkSigs)
	r.Body = io.NopCloser(bytes.NewReader(full[:40000]))
	if _, err := docVerifier(docTime).Verify(r); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r.Body); errCode(err) != "IncompleteBody" {
		t.Fatalf("got %v", err)
	}
}

func TestURIEncode(t *testing.T) {
	cases := []struct{ in, path, query string }{
		{"abc-._~XYZ09", "abc-._~XYZ09", "abc-._~XYZ09"},
		{"a b/c", "a%20b/c", "a%20b%2Fc"},
		{"é+=&$", "%C3%A9%2B%3D%26%24", "%C3%A9%2B%3D%26%24"},
	}
	for _, c := range cases {
		if got := uriEncode(c.in, true); got != c.path {
			t.Errorf("path %q: got %q want %q", c.in, got, c.path)
		}
		if got := uriEncode(c.in, false); got != c.query {
			t.Errorf("query %q: got %q want %q", c.in, got, c.query)
		}
	}
	if got := canonicalQuery("prefix=J&max-keys=2&acl&X-Amz-Signature=x", "X-Amz-Signature"); got != "acl=&max-keys=2&prefix=J" {
		t.Errorf("canonical query = %q", got)
	}
}
