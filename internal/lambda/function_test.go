package lambda

import "testing"

func TestParseRef(t *testing.T) {
	tests := []struct {
		in                               string
		name, qualifier, account, region string
		bad                              bool
	}{
		{in: "fn", name: "fn"},
		{in: "fn:1", name: "fn", qualifier: "1"},
		{in: "fn:$LATEST", name: "fn", qualifier: "$LATEST"},
		{in: "fn:live", name: "fn", qualifier: "live"},
		{in: "123456789012:function:fn", name: "fn", account: "123456789012"},
		{in: "arn:aws:lambda:us-east-1:123456789012:function:fn", name: "fn", account: "123456789012", region: "us-east-1"},
		{in: "arn:aws:lambda:us-east-1:123456789012:function:fn:9", name: "fn", qualifier: "9", account: "123456789012", region: "us-east-1"},
		{in: "arn:aws-cn:lambda:cn-northwest-1:123456789012:function:my_fn-2:prod", name: "my_fn-2", qualifier: "prod", account: "123456789012", region: "cn-northwest-1"},
		{in: "arn:aws:lambda:us-gov-west-1:123456789012:function:fn", name: "fn", account: "123456789012", region: "us-gov-west-1"},
		{in: "", bad: true},
		{in: "bad name", bad: true},
		{in: "fn:a:b", bad: true},
	}
	for _, tc := range tests {
		got, err := parseRef(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("parseRef(%q) = %+v, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseRef(%q): %v", tc.in, err)
			continue
		}
		if got.name != tc.name || got.qualifier != tc.qualifier || got.account != tc.account || got.region != tc.region {
			t.Errorf("parseRef(%q) = %+v", tc.in, got)
		}
	}
}

func TestPartition(t *testing.T) {
	for region, want := range map[string]string{
		"us-west-2": "aws", "cn-northwest-1": "aws-cn", "us-gov-east-1": "aws-us-gov",
		"us-iso-east-1": "aws-iso", "us-isob-east-1": "aws-iso-b", "tuchanka-1": "aws",
	} {
		if got := partition(region); got != want {
			t.Errorf("partition(%s) = %s, want %s", region, got, want)
		}
	}
}

func TestAliasName(t *testing.T) {
	for name, ok := range map[string]bool{"live": true, "v1": true, "1": false, "123": false, "a-b_c": true, "": false, "x:y": false} {
		if got := aliasNameRE.MatchString(name) && name != ""; got != ok {
			t.Errorf("alias name %q valid = %v, want %v", name, got, ok)
		}
	}
}
