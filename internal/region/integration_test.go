//go:build unix

package region_test

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"citadel/internal/bootstrap"
	"citadel/internal/region"
	"citadel/internal/sigv4"
)

// These tests start real citadel processes: a home region and two followers
// on loopback ports, each with its own data directory, as
// examples/multiregion-local does. They cover M8's exit criteria.

const bootstrapPath = "../../harness/bootstrap.json"

type proc struct {
	name, addr, dir, log string
	cmd                  *exec.Cmd
}

type cloud struct {
	t       *testing.T
	bin     string
	regPath string
	key     string
	regions map[string]*proc
	extra   []string // more serve flags
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func newCloud(t *testing.T, extra ...string) *cloud {
	if testing.Short() {
		t.Skip("starts real processes")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "citadel")
	if out, err := exec.Command("go", "build", "-o", bin, "citadel/cmd/citadel").CombinedOutput(); err != nil {
		t.Fatalf("build citadel: %v\n%s", err, out)
	}
	c := &cloud{t: t, bin: bin, key: "integration-test-region-key-0123456789", regions: map[string]*proc{}, extra: extra}
	reg := region.Registry{Home: "home-1"}
	for _, n := range []string{"home-1", "follow-1", "follow-2"} {
		p := &proc{name: n, addr: freePort(t), dir: filepath.Join(dir, n)}
		p.log = p.dir + ".log"
		c.regions[n] = p
		reg.Regions = append(reg.Regions, region.Region{Name: n, Endpoint: "http://" + p.addr})
	}
	b, _ := json.Marshal(reg)
	c.regPath = filepath.Join(dir, "regions.json")
	if err := os.WriteFile(c.regPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, p := range c.regions {
			c.stop(p.name)
		}
		if t.Failed() {
			for _, p := range c.regions {
				b, _ := os.ReadFile(p.log)
				lines := strings.Split(strings.TrimSpace(string(b)), "\n")
				t.Logf("---- %s log (tail) ----\n%s", p.name, strings.Join(lines[max(0, len(lines)-15):], "\n"))
			}
		}
	})
	for _, n := range []string{"home-1", "follow-1", "follow-2"} {
		c.start(n)
	}
	return c
}

func (c *cloud) start(name string) {
	c.t.Helper()
	p := c.regions[name]
	logf, err := os.OpenFile(p.log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		c.t.Fatal(err)
	}
	args := append([]string{"serve", "--region", name, "--listen", p.addr, "--data", p.dir,
		"--bootstrap", bootstrapPath, "--regions", c.regPath, "--log", "text", "--gc-interval", "0"}, c.extra...)
	p.cmd = exec.Command(c.bin, args...)
	p.cmd.Env = append(os.Environ(), region.KeyEnv+"="+c.key)
	p.cmd.Stdout, p.cmd.Stderr = logf, logf
	if err := p.cmd.Start(); err != nil {
		c.t.Fatal(err)
	}
	logf.Close()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get("http://" + p.addr + "/_citadel/healthz"); err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	c.t.Fatalf("%s did not become healthy", name)
}

func (c *cloud) stop(name string) {
	p := c.regions[name]
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGCONT)
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _, _ = p.cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		_ = p.cmd.Process.Kill()
		<-done
	}
	p.cmd = nil
}

func (c *cloud) signal(name string, sig syscall.Signal) {
	c.t.Helper()
	if err := c.regions[name].cmd.Process.Signal(sig); err != nil {
		c.t.Fatal(err)
	}
}

func (c *cloud) health(name string) map[string]any {
	resp, err := (&http.Client{Timeout: time.Second}).Get("http://" + c.regions[name].addr + "/_citadel/healthz")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var h map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&h)
	return h
}

// call sends a signed request and returns the status and body.
func (c *cloud) call(name string, cred sigv4.Credentials, service, method, path string, hdr map[string]string, body []byte) (int, string) {
	c.t.Helper()
	r, err := http.NewRequest(method, "http://"+c.regions[name].addr+path, bytes.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	sigv4.Sign(r, cred, "us-east-1", service, body, time.Now())
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(r)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (c *cloud) query(name string, cred sigv4.Credentials, service string, params url.Values) (int, string) {
	return c.call(name, cred, service, "POST", "/", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(params.Encode()))
}

func (c *cloud) mustQuery(name string, cred sigv4.Credentials, service string, params url.Values) string {
	c.t.Helper()
	code, body := c.query(name, cred, service, params)
	if code != 200 {
		c.t.Fatalf("%s %s at %s: %d %s", service, params.Get("Action"), name, code, body)
	}
	return body
}

func iamParams(action string, kv ...string) url.Values {
	v := url.Values{"Action": {action}, "Version": {"2010-05-08"}}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

// newUserKey creates an IAM user with full access and an access key for it.
func (c *cloud) newUserKey(at string, admin sigv4.Credentials, user string) sigv4.Credentials {
	c.t.Helper()
	c.mustQuery(at, admin, "iam", iamParams("CreateUser", "UserName", user))
	c.mustQuery(at, admin, "iam", iamParams("PutUserPolicy", "UserName", user, "PolicyName", "all",
		"PolicyDocument", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`))
	var out struct {
		Key struct {
			ID     string `xml:"AccessKeyId"`
			Secret string `xml:"SecretAccessKey"`
		} `xml:"CreateAccessKeyResult>AccessKey"`
	}
	body := c.mustQuery(at, admin, "iam", iamParams("CreateAccessKey", "UserName", user))
	if err := xml.Unmarshal([]byte(body), &out); err != nil || out.Key.ID == "" {
		c.t.Fatalf("CreateAccessKey response %q: %v", body, err)
	}
	return sigv4.Credentials{AccessKey: out.Key.ID, SecretKey: out.Key.Secret}
}

// waitAuth polls until cred authenticates in region name, and returns how long that took.
func (c *cloud) waitAuth(name string, cred sigv4.Credentials, within time.Duration) time.Duration {
	c.t.Helper()
	start := time.Now()
	for {
		code, body := c.query(name, cred, "sts", url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}})
		if code == 200 {
			return time.Since(start)
		}
		if time.Since(start) > within {
			c.t.Fatalf("key %s not accepted by %s after %v: %d %s", cred.AccessKey, name, within, code, body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func adminCredentials(t *testing.T) sigv4.Credentials {
	f, err := bootstrap.Load(bootstrapPath)
	if err != nil || len(f.Accounts) == 0 || len(f.Accounts[0].Users) == 0 {
		t.Fatalf("bootstrap: %v", err)
	}
	u := f.Accounts[0].Users[0]
	return sigv4.Credentials{AccessKey: u.AccessKey, SecretKey: u.SecretKey}
}

func TestMultiRegionControlPlane(t *testing.T) {
	c := newCloud(t)
	admin := adminCredentials(t)
	followers := []string{"follow-1", "follow-2"}

	// A key created in the home region authenticates in both followers within 5 s.
	alice := c.newUserKey("home-1", admin, "alice")
	for _, f := range followers {
		d := c.waitAuth(f, alice, 5*time.Second)
		t.Logf("alice's key accepted by %s after %v", f, d.Round(time.Millisecond))
	}

	// IAM calls made in a follower go to the home region.
	bob := c.newUserKey("follow-1", admin, "bob")
	c.waitAuth("follow-2", bob, 5*time.Second)
	if body := c.mustQuery("home-1", admin, "iam", iamParams("GetUser", "UserName", "bob")); !strings.Contains(body, "<UserName>bob</UserName>") {
		t.Fatalf("home does not know bob: %s", body)
	}

	// Followers survive restarts: changes made while one is down arrive after it returns.
	c.stop("follow-2")
	carol := c.newUserKey("home-1", admin, "carol")
	c.mustQuery("home-1", admin, "iam", iamParams("UpdateAccessKey", "UserName", "bob", "AccessKeyId", bob.AccessKey, "Status", "Inactive"))
	c.start("follow-2")
	c.waitAuth("follow-2", alice, time.Second)
	c.waitAuth("follow-2", carol, 5*time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for {
		code, _ := c.query("follow-2", bob, "sts", url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}})
		if code == 403 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("bob's deactivated key still answers %d in follow-2", code)
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Static stability: stop the home region; followers keep serving the
	// data plane with existing (already replicated) credentials.
	c.waitAuth("follow-1", carol, 5*time.Second)
	c.signal("home-1", syscall.SIGSTOP)
	for _, f := range followers {
		deadline := time.Now().Add(10 * time.Second)
		for c.health(f)["home_reachable"] != false {
			if time.Now().After(deadline) {
				t.Fatalf("%s did not notice the home region stopped: %v", f, c.health(f))
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	for _, f := range followers {
		start := time.Now()
		bucket := "static-" + f
		for _, step := range []struct {
			what, method, path string
			body               []byte
			want               string
		}{
			{"create bucket", "PUT", "/" + bucket, nil, ""},
			{"put object", "PUT", "/" + bucket + "/k", []byte("still here"), ""},
			{"get object", "GET", "/" + bucket + "/k", nil, "still here"},
		} {
			code, body := c.call(f, alice, "s3", step.method, step.path, nil, step.body)
			if code != 200 || !strings.Contains(body, step.want) {
				t.Fatalf("%s in %s with home stopped: %d %s", step.what, f, code, body)
			}
		}
		code, body := c.call(f, carol, "dynamodb", "POST", "/", map[string]string{
			"Content-Type": "application/x-amz-json-1.0", "X-Amz-Target": "DynamoDB_20120810.ListTables"}, []byte(`{}`))
		if code != 200 || !strings.Contains(body, "TableNames") {
			t.Fatalf("dynamodb ListTables in %s with home stopped: %d %s", f, code, body)
		}
		t.Logf("%s served S3 and DynamoDB with the home region stopped in %v", f, time.Since(start).Round(time.Millisecond))

		// IAM reads come from the replica; writes wait for the home region.
		if body := c.mustQuery(f, alice, "iam", iamParams("ListUsers")); !strings.Contains(body, "<UserName>carol</UserName>") {
			t.Fatalf("ListUsers in %s from the replica: %s", f, body)
		}
		code, body = c.query(f, alice, "iam", iamParams("CreateUser", "UserName", "dave-"+f))
		if code != 503 || !strings.Contains(body, "ServiceUnavailable") {
			t.Fatalf("CreateUser in %s with home stopped: %d %s", f, code, body)
		}
	}

	// The home region returns; control-plane writes work again everywhere.
	c.signal("home-1", syscall.SIGCONT)
	deadline = time.Now().Add(15 * time.Second)
	for {
		code, body := c.query("follow-2", alice, "iam", iamParams("CreateUser", "UserName", "erin"))
		if code == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("CreateUser after the home region resumed: %d %s", code, body)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
