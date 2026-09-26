package lambda

import (
	"net/http/httptest"
	"testing"
)

func TestParseName(t *testing.T) {
	c := &call{account: "123456789012", region: "us-west-2"}
	tests := []struct {
		raw, qualifier          string
		wantRegion, wantName    string
		wantQualifier           string
		wantErr, wantAccessDeny bool
	}{
		{raw: "fn", wantRegion: "us-west-2", wantName: "fn"},
		{raw: "fn:live", wantRegion: "us-west-2", wantName: "fn", wantQualifier: "live"},
		{raw: "fn", qualifier: "$LATEST", wantRegion: "us-west-2", wantName: "fn", wantQualifier: "$LATEST"},
		{raw: "fn:1", qualifier: "1", wantRegion: "us-west-2", wantName: "fn", wantQualifier: "1"},
		{raw: "fn:1", qualifier: "2", wantErr: true},
		{raw: "123456789012:function:fn", wantRegion: "us-west-2", wantName: "fn"},
		{raw: "arn:aws:lambda:eu-west-1:123456789012:function:fn", wantRegion: "eu-west-1", wantName: "fn"},
		{raw: "arn:aws:lambda:eu-west-1:123456789012:function:fn:7", wantRegion: "eu-west-1", wantName: "fn", wantQualifier: "7"},
		{raw: "arn:aws-iso-b:lambda:us-isob-east-1:123456789012:function:fn", wantRegion: "us-isob-east-1", wantName: "fn"},
		{raw: "arn:aws:lambda:eu-west-1:000000000000:function:fn", wantAccessDeny: true},
		{raw: "arn:aws:lambda:tuchanka-1:123456789012:function:fn:live", wantRegion: "tuchanka-1", wantName: "fn", wantQualifier: "live"},
		{raw: "my-func-1:live", wantRegion: "us-west-2", wantName: "my-func-1", wantQualifier: "live"},
		{raw: "fn:", wantErr: true},
		{raw: "arn:aws:lambda:us-west-2:123456789012:layer:x", wantErr: true},
		{raw: "bad name", wantErr: true},
		{raw: "a.b", wantErr: true},
		{raw: "", wantErr: true},
	}
	for _, tt := range tests {
		ref, err := c.parseName(tt.raw, tt.qualifier)
		if tt.wantErr || tt.wantAccessDeny {
			e, ok := err.(*apiError)
			if !ok {
				t.Errorf("parseName(%q, %q): want error, got %+v", tt.raw, tt.qualifier, ref)
				continue
			}
			if tt.wantAccessDeny != (e.Code == "AccessDeniedException") {
				t.Errorf("parseName(%q): error %s", tt.raw, e.Code)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseName(%q, %q): %v", tt.raw, tt.qualifier, err)
			continue
		}
		if ref.region != tt.wantRegion || ref.name != tt.wantName || ref.qualifier != tt.wantQualifier {
			t.Errorf("parseName(%q, %q) = %+v", tt.raw, tt.qualifier, ref)
		}
	}
}

func TestARNs(t *testing.T) {
	ref := fnRef{account: "123456789012", region: "cn-north-1", name: "fn"}
	if got := ref.arn(); got != "arn:aws-cn:lambda:cn-north-1:123456789012:function:fn" {
		t.Errorf("arn = %s", got)
	}
	if got := ref.qualifiedARN("$LATEST"); got != "arn:aws-cn:lambda:cn-north-1:123456789012:function:fn:$LATEST" {
		t.Errorf("qualified = %s", got)
	}
	back, err := parseFunctionARN(ref.qualifiedARN("3"))
	if err != nil || back.name != "fn" || back.qualifier != "3" || back.region != "cn-north-1" {
		t.Errorf("parseFunctionARN = %+v, %v", back, err)
	}
}

func TestVersionNumber(t *testing.T) {
	tests := []struct {
		in   string
		n    int
		isOK bool
	}{
		{"$LATEST", 0, true}, {"1", 1, true}, {"42", 42, true},
		{"0", 0, false}, {"01", 0, false}, {"-1", 0, false}, {"live", 0, false}, {"", 0, false},
	}
	for _, tt := range tests {
		n, ok := versionNumber(tt.in)
		if n != tt.n || ok != tt.isOK {
			t.Errorf("versionNumber(%q) = %d, %v", tt.in, n, ok)
		}
	}
}

func TestMarker(t *testing.T) {
	m := encodeMarker("my-fn", 12)
	name, num, ok := decodeMarker(m)
	if !ok || name != "my-fn" || num != 12 {
		t.Errorf("round trip = %q %d %v", name, num, ok)
	}
	if _, _, ok := decodeMarker("not base64!"); ok {
		t.Error("garbage marker accepted")
	}
}

func TestValidAliasName(t *testing.T) {
	for in, want := range map[string]bool{"live": true, "v1": true, "a-b_c": true, "1": false, "$LATEST": false, "": false, "a:b": false} {
		if got := validAliasName(in); got != want {
			t.Errorf("validAliasName(%q) = %v", in, got)
		}
	}
}

func TestPickVersion(t *testing.T) {
	a := &alias{FunctionVersion: "1", RoutingConfig: map[string]any{"AdditionalVersionWeights": map[string]any{"2": 1.0}}}
	if v := pickVersion(a); v != "2" {
		t.Errorf("weight 1.0 routes to %s", v)
	}
	a.RoutingConfig = nil
	if v := pickVersion(a); v != "1" {
		t.Errorf("no routing picks %s", v)
	}
}

func TestMemoryPages(t *testing.T) {
	for mb, want := range map[int]uint32{128: 2048, 1024: 16384, 10240: 65536} {
		if got := memoryPages(mb); got != want {
			t.Errorf("memoryPages(%d) = %d", mb, got)
		}
	}
}

func TestFilterPattern(t *testing.T) {
	tests := []struct {
		pattern, msg string
		want         bool
	}{
		{"", "anything", true},
		{"ERROR", "an ERROR here", true},
		{"ERROR", "all good", false},
		{"ERROR timeout", "ERROR: timeout", true},
		{"ERROR timeout", "ERROR only", false},
		{`"Task timed out"`, "x Task timed out after 3.00 seconds", true},
		{`"Task timed out"`, "Task was timed", false},
		{"ERROR -retry", "ERROR retry", false},
		{"?ERROR ?WARN", "WARN disk", true},
		{"?ERROR ?WARN", "INFO", false},
		{`{ $.level = "x" }`, "anything", true},
	}
	for _, tt := range tests {
		if got := compileFilter(tt.pattern)(tt.msg); got != tt.want {
			t.Errorf("filter %q on %q = %v", tt.pattern, tt.msg, got)
		}
	}
}

func TestRoutes(t *testing.T) {
	tests := []struct{ method, path, op string }{
		{"GET", "/2015-03-31/functions/", "ListFunctions"},
		{"GET", "/2015-03-31/functions/fn", "GetFunction"},
		{"GET", "/2015-03-31/functions/arn%3Aaws%3Alambda%3Aus-east-1%3A123456789012%3Afunction%3Afn/configuration", "GetFunctionConfiguration"},
		{"POST", "/2015-03-31/functions/fn/invocations", "Invoke"},
		{"DELETE", "/2015-03-31/functions/fn/aliases/live", "DeleteAlias"},
		{"GET", "/2019-09-25/functions/fn/event-invoke-config/list", "ListFunctionEventInvokeConfigs"},
		{"DELETE", "/2017-03-31/tags/arn%3Aaws%3Alambda%3Aus-east-1%3A123456789012%3Afunction%3Afn", "UntagResource"},
		{"GET", "/2015-03-31/event-source-mappings/", "ListEventSourceMappings"},
		{"GET", "/2018-10-31/layers", ""},
	}
	for _, tt := range tests {
		rt, params := match(httptest.NewRequest(tt.method, tt.path, nil))
		op := ""
		if rt != nil {
			op = rt.op
		}
		if op != tt.op {
			t.Errorf("%s %s routed to %q, want %q", tt.method, tt.path, op, tt.op)
		}
		if tt.op == "GetFunctionConfiguration" && params["FunctionName"] != "arn:aws:lambda:us-east-1:123456789012:function:fn" {
			t.Errorf("FunctionName param = %q", params["FunctionName"])
		}
	}
}
