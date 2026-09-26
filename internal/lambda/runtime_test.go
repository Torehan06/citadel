package lambda

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// buildHello compiles examples/functions/hello-go for wasip1.
func buildHello(t *testing.T) []byte {
	t.Helper()
	if testing.Short() {
		t.Skip("builds a wasm module")
	}
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(goBin); err != nil {
		t.Skip("go toolchain not available")
	}
	out := filepath.Join(t.TempDir(), "bootstrap.wasm")
	cmd := exec.Command(goBin, "build", "-o", out, ".")
	cmd.Dir = filepath.Join("..", "..", "examples", "functions", "hello-go")
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build hello-go: %v\n%s", err, b)
	}
	bin, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestRuntime(t *testing.T) {
	wasm := buildHello(t)
	rt := newRuntime(t.TempDir(), slog.Default())
	defer rt.close()
	run := func(event string, timeout time.Duration) (runOutcome, string, string) {
		var stdout, stderr bytes.Buffer
		oc, err := rt.run(context.Background(), runSpec{
			codeKey: "hello", wasm: func() ([]byte, error) { return wasm, nil },
			pages: memoryPages(128), timeout: timeout,
			env:   map[string]string{"AWS_LAMBDA_FUNCTION_NAME": "hello", "AWS_LAMBDA_FUNCTION_VERSION": "$LATEST"},
			stdin: []byte(event), stdout: &stdout, stderr: &stderr,
		})
		if err != nil {
			t.Fatalf("run %s: %v", event, err)
		}
		return oc, stdout.String(), stderr.String()
	}

	oc, out, logs := run(`{"name":"Ada"}`, 10*time.Second)
	if oc.exitCode != 0 || oc.timedOut || oc.trap != nil || !oc.cold {
		t.Fatalf("hello outcome = %+v", oc)
	}
	var resp map[string]string
	if err := json.Unmarshal([]byte(out), &resp); err != nil || resp["message"] != "Hello, Ada!" {
		t.Errorf("hello stdout = %q", out)
	}
	if !strings.Contains(logs, "hello-go: hello version $LATEST") {
		t.Errorf("stderr = %q (environment not passed?)", logs)
	}

	oc, out, _ = run(`{"fail":"boom"}`, 10*time.Second)
	if oc.exitCode != 1 || oc.cold || !strings.Contains(out, `"errorMessage":"boom"`) {
		t.Errorf("fail outcome = %+v, stdout %q (second run should reuse the compiled module)", oc, out)
	}

	oc, _, _ = run(`{"sleep_ms":5000}`, 300*time.Millisecond)
	if !oc.timedOut {
		t.Errorf("sleep outcome = %+v, want a timeout", oc)
	}

	oc, _, _ = run(`not json`, 10*time.Second)
	if oc.exitCode == 0 {
		t.Errorf("bad event exited 0")
	}
}

func TestRuntimeRejectsGarbage(t *testing.T) {
	rt := newRuntime("", slog.Default())
	defer rt.close()
	_, err := rt.run(context.Background(), runSpec{
		codeKey: "junk", wasm: func() ([]byte, error) { return []byte("not wasm"), nil },
		pages: memoryPages(128), timeout: time.Second, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{},
	})
	if _, ok := err.(*invalidModule); !ok {
		t.Errorf("err = %v, want invalidModule", err)
	}
}
