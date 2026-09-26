package s3

import (
	"context"
	"io"
)

// Access for other services running inside the region (Lambda reading a
// deployment package from a bucket).

// S3Error reports the S3 error code and message, for services that wrap an
// S3 failure in their own error.
func (e *Error) S3Error() (string, string) { return e.Code, e.Message }

// OpenObject opens an object (the current version, or versionID) in a bucket
// that account owns. Buckets of other accounts answer AccessDenied.
func (h *Handler) OpenObject(ctx context.Context, account, bucket, key, versionID string) (io.ReadCloser, int64, error) {
	b, err := h.loadBucket(ctx, bucket)
	if err != nil {
		return nil, 0, err
	}
	if b.Account != account {
		return nil, 0, errAccessDenied()
	}
	req := &request{ctx: ctx, bucket: bucket, key: key, hasKey: true}
	o, err := h.loadObject(req, versionID)
	if err != nil {
		return nil, 0, err
	}
	body, err := h.openRange(o, 0, o.Size)
	if err != nil {
		return nil, 0, err
	}
	return body, o.Size, nil
}
