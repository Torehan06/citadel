package iam

import (
	"errors"
	"testing"
)

func TestValidatePolicy(t *testing.T) {
	const ok = ""
	cases := []struct {
		name, doc, want string
	}{
		{"valid", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}}`, ok},
		{"statement list", `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","NotAction":["s3:*"],"NotResource":"*"}]}`, ok},
		{"not json", `some policy`, "Syntax errors in policy."},
		{"unknown top element", `{"Version":"2012-10-17","Foo":1,"Statement":[]}`, "Syntax errors in policy."},
		{"empty statements", `{"Version":"2012-10-17","Statement":[]}`, "Syntax errors in policy."},
		{"effect case-insensitive in grammar", `{"Version":"2012-10-17","Statement":{"Effect":"allow","Action":"s3:*","Resource":"*"}}`, errLegacyParse},
		{"bad effect", `{"Version":"2012-10-17","Statement":{"Effect":"Maybe","Action":"s3:*","Resource":"*"}}`, "Syntax errors in policy."},
		{"action and notaction", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","NotAction":"s3:*","Resource":"*"}}`, "Syntax errors in policy."},
		{"old version", `{"Version":"2008-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`, "Policy document must be version 2012-10-17 or greater."},
		{"no version", `{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`, "Policy document must be version 2012-10-17 or greater."},
		{"no action", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Resource":"*"}}`, "Policy statement must contain actions."},
		{"empty action list", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":[],"Resource":"*"}}`, "Policy statement must contain actions."},
		{"no resource", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*"}}`, "Policy statement must contain resources."},
		{"no vendor", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"GetObject","Resource":"*"}}`, "Actions/Conditions must be prefaced by a vendor, e.g., iam, sdb, ec2, etc."},
		{"two colons", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:a:b","Resource":"*"}}`, "Actions/Condition can contain only one colon."},
		{"bad vendor", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"a a:b","Resource":"*"}}`, "Vendor a a is not valid"},
		{"duplicate sid", `{"Version":"2012-10-17","Statement":[{"Sid":"x","Effect":"Allow","Action":"s3:*","Resource":"*"},{"Sid":"x","Effect":"Allow","Action":"s3:*","Resource":"*"}]}`, "Statement IDs (SID) in a single policy must be unique."},
		{"resource not arn", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"bucket"}}`, `Resource bucket must be in ARN format or "*".`},
		{"bad partition", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:red:s3:::b"}}`, `Partition "red" is not valid for resource "arn:red:s3:::b".`},
		{"s3 region", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:us-east-1::example_bucket"}}`, "Resource arn:aws:s3:us-east-1::example_bucket can not contain region information."},
		{"s3 access point region ok", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:us-west-2:123456789012:accesspoint/ap"}}`, ok},
		{"iam region", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:*","Resource":"arn:aws:iam:us-east-1::example_bucket"}}`, "IAM resource arn:aws:iam:us-east-1::example_bucket cannot contain region information."},
		{"legacy: short arn with ::", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws::b"}}`, errLegacyParse},
		{"date condition", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"DateGreaterThan":{"aws:CurrentTime":"2019-07-01T00:00:00Z"}}}}`, ok},
		{"bad date condition", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"DateGreaterThan":{"aws:CurrentTime":"2019-13-01"}}}}`, errLegacyParse},
		{"numeric condition value", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"NumericLessThan":{"s3:max-keys":10}}}}`, "Syntax errors in policy."},
		{"unknown condition operator", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"Bogus":{"a":"b"}}}}`, "Syntax errors in policy."},
		{"unknown empty condition", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"Bogus":{}}}}`, ok},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePolicy(tc.doc)
			got := ""
			var e *apiError
			if errors.As(err, &e) {
				got = e.Message
			} else if err != nil {
				t.Fatalf("unexpected error type %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidateTrustPolicy(t *testing.T) {
	good := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}}`
	if err := ValidateTrustPolicy(good); err != nil {
		t.Fatal(err)
	}
	bad := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject"}}`
	if err := ValidateTrustPolicy(bad); err == nil {
		t.Fatal("non-STS action accepted")
	}
	withResource := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Resource":"*"}}`
	if err := ValidateTrustPolicy(withResource); err == nil || err.(*apiError).Message != "Has prohibited field Resource." {
		t.Fatalf("got %v", err)
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		p, s string
		fold bool
		want bool
	}{
		{"*", "", false, true},
		{"s3:Get*", "s3:GetObject", false, true},
		{"s3:get*", "s3:GetObject", true, true},
		{"s3:get*", "s3:GetObject", false, false},
		{"arn:aws:s3:::b/*", "arn:aws:s3:::b/k/x", false, true},
		{"arn:aws:s3:::b/?", "arn:aws:s3:::b/k", false, true},
		{"arn:aws:s3:::b/?", "arn:aws:s3:::b/kk", false, false},
		{"a*b*c", "aXXbYYc", false, true},
		{"a*b*c", "aXXbYY", false, false},
	}
	for _, tc := range cases {
		if got := Glob(tc.p, tc.s, tc.fold); got != tc.want {
			t.Errorf("Glob(%q, %q, %v) = %v", tc.p, tc.s, tc.fold, got)
		}
	}
}

func TestEvaluate(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::bucket/*"},
		{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"},
		{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::bucket","Condition":{"StringLike":{"s3:prefix":["home/${aws:username}/*"]}}},
		{"Effect":"Allow","Action":"dynamodb:GetItem","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}},
		{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"*","Condition":{"StringNotEquals":{"aws:username":"mallory"}}},
		{"Effect":"Allow","Action":"sqs:ReceiveMessage","Resource":"*","Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["a","b"]}}},
		{"Effect":"Allow","Action":"sqs:DeleteMessage","Resource":"*","Condition":{"Null":{"aws:MultiFactorAuthAge":"true"}}}
	]}`
	d, err := ParseDocument(doc)
	if err != nil {
		t.Fatal(err)
	}
	ctx := func(kv ...string) map[string][]string {
		m := map[string][]string{"aws:username": {"alice"}}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = append(m[kv[i]], kv[i+1])
		}
		return m
	}
	cases := []struct {
		name, action, resource string
		ctx                    map[string][]string
		want                   Decision
	}{
		{"allow object", "s3:GetObject", "arn:aws:s3:::bucket/k", ctx(), Allow},
		{"other bucket", "s3:GetObject", "arn:aws:s3:::other/k", ctx(), NoMatch},
		{"explicit deny wins", "s3:DeleteObject", "arn:aws:s3:::bucket/k", ctx(), Deny},
		{"policy variable", "s3:ListBucket", "arn:aws:s3:::bucket", ctx("s3:prefix", "home/alice/docs"), Allow},
		{"policy variable other user", "s3:ListBucket", "arn:aws:s3:::bucket", ctx("s3:prefix", "home/bob/docs"), NoMatch},
		{"missing condition key", "s3:ListBucket", "arn:aws:s3:::bucket", ctx(), NoMatch},
		{"ip in range", "dynamodb:GetItem", "t", ctx("aws:sourceip", "10.1.2.3"), Allow},
		{"ip out of range", "dynamodb:GetItem", "t", ctx("aws:sourceip", "192.168.0.1"), NoMatch},
		{"negated operator", "sqs:SendMessage", "q", ctx(), Allow},
		{"for all values subset", "sqs:ReceiveMessage", "q", ctx("aws:tagkeys", "a"), Allow},
		{"for all values extra", "sqs:ReceiveMessage", "q", ctx("aws:tagkeys", "a", "aws:tagkeys", "c"), NoMatch},
		{"for all values empty", "sqs:ReceiveMessage", "q", ctx(), Allow},
		{"null true", "sqs:DeleteMessage", "q", ctx(), Allow},
		{"null false", "sqs:DeleteMessage", "q", ctx("aws:multifactorauthage", "5"), NoMatch},
		{"action case-insensitive", "S3:getobject", "arn:aws:s3:::bucket/k", ctx(), Allow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := d.Evaluate(&Request{Action: tc.action, Resource: tc.resource, Context: tc.ctx})
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPrincipalMatching(t *testing.T) {
	trust, err := ParseDocument(`{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"sts:AssumeRole"},
		{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::222222222222:user/alice"]},"Action":"sts:AssumeRole"},
		{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		acct string
		arns []string
		want Decision
	}{
		{"111111111111", []string{"arn:aws:iam::111111111111:user/bob"}, Allow},
		{"", []string{"arn:aws:iam::111111111111:user/bob"}, NoMatch}, // account match disabled
		{"222222222222", []string{"arn:aws:iam::222222222222:user/alice"}, Allow},
		{"222222222222", []string{"arn:aws:iam::222222222222:user/eve"}, NoMatch},
		{"333333333333", []string{"arn:aws:iam::333333333333:root"}, NoMatch},
	}
	for _, tc := range cases {
		got := trust.Evaluate(&Request{Action: "sts:AssumeRole", Account: tc.acct, Principals: tc.arns})
		if got != tc.want {
			t.Errorf("%s %v: got %v, want %v", tc.acct, tc.arns, got, tc.want)
		}
	}
}

func TestEncodeDocument(t *testing.T) {
	got := encodeDocument(`{"a": "b c+d/é"}`)
	want := `%7B%22a%22%3A%20%22b%20c%2Bd%2F%C3%A9%22%7D`
	if got != want {
		t.Fatalf("got %s", got)
	}
}
