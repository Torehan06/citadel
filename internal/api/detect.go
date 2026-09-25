package api

import (
	"net/http"
	"strings"
)

// Service names match the SigV4 credential-scope service names that AWS SDKs
// sign with, so a signed request tells us which API it is for without guessing.
const (
	SvcS3       = "s3"
	SvcDynamoDB = "dynamodb"
	SvcSQS      = "sqs"
	SvcLambda   = "lambda"
	SvcIAM      = "iam"
	SvcSTS      = "sts"
	SvcRoute53  = "route53"
	SvcUnknown  = ""
)

// DetectService decides which AWS API a request targets.
//
// Order of evidence (see ARCHITECTURE.md, D4):
//  1. SigV4 credential scope in the Authorization header or presigned query.
//  2. X-Amz-Target header (JSON 1.0 protocols: DynamoDB, SQS).
//  3. REST path prefixes (Lambda, Route 53).
//  4. Everything else is S3, which is also the only API that accepts
//     anonymous requests.
func DetectService(r *http.Request) string {
	if svc := scopeService(r.Header.Get("Authorization")); svc != "" {
		return svc
	}
	if cred := r.URL.Query().Get("X-Amz-Credential"); cred != "" {
		if svc := serviceFromCredential(cred); svc != "" {
			return svc
		}
	}
	if t := r.Header.Get("X-Amz-Target"); t != "" {
		switch {
		case strings.HasPrefix(t, "DynamoDB_"):
			return SvcDynamoDB
		case strings.HasPrefix(t, "AmazonSQS"):
			return SvcSQS
		}
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/2015-03-31/"):
		return SvcLambda
	case strings.HasPrefix(r.URL.Path, "/2013-04-01/"):
		return SvcRoute53
	}
	return SvcS3
}

// scopeService extracts the service from
// "AWS4-HMAC-SHA256 Credential=AKID/20260925/us-east-1/s3/aws4_request, ...".
func scopeService(auth string) string {
	const marker = "Credential="
	i := strings.Index(auth, marker)
	if i < 0 {
		return ""
	}
	rest := auth[i+len(marker):]
	if j := strings.IndexAny(rest, ", "); j >= 0 {
		rest = rest[:j]
	}
	return serviceFromCredential(rest)
}

// serviceFromCredential parses "AKID/date/region/service/aws4_request".
func serviceFromCredential(cred string) string {
	parts := strings.Split(cred, "/")
	if len(parts) != 5 || parts[4] != "aws4_request" {
		return ""
	}
	return parts[3]
}
