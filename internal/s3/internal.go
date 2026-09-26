package s3

import (
	"context"
	"io"
)

// S3Code reports the S3 error code and message, so services that read
// objects on a caller's behalf (Lambda fetching a deployment package) can
// quote them the way AWS does.
func (e *Error) S3Code() (string, string) { return e.Code, e.Message }

// OpenObject opens the current version of an object for another service in
// the region acting for account. The bucket must belong to that account:
// cross-account reads would need the bucket policy and ACL checks that a
// signed S3 request goes through.
func (h *Handler) OpenObject(ctx context.Context, account, bucket, key string) (io.ReadCloser, int64, error) {
	b, err := h.loadBucket(ctx, bucket)
	if err != nil {
		return nil, 0, err
	}
	if b.Account != account {
		return nil, 0, &Error{Status: 403, Code: "AccessDenied", Message: "Access Denied", Bucket: bucket, Key: key}
	}
	o, err := h.loadObject(&request{ctx: ctx, bucket: bucket, key: key, hasKey: true}, "")
	if err != nil {
		return nil, 0, err
	}
	rc, err := h.openRange(o, 0, o.Size)
	return rc, o.Size, err
}
