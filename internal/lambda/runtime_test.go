package lambda

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildWasm compiles a Go program for wasip1 and zips it as bootstrap.wasm.
func buildWasm(t *testing.T, src string) []byte {
	t.Helper()
	if testing.Short() {
		t.Skip("builds a wasm module")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fn\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", "bootstrap.wasm", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0", "GOFLAGS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build wasip1 module: %v\n%s", err, out)
	}
	wasm, err := os.ReadFile(filepath.Join(dir, "bootstrap.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("bootstrap.wasm")
	_, _ = w.Write(wasm)
	_ = zw.Close()
	return buf.Bytes()
}

const echoProgram = `package main

import (
	"fmt"
	"io"
	"os"
	"time"
)

func main() {
	in, _ := io.ReadAll(os.Stdin)
	fmt.Fprintln(os.Stderr, "log line for", os.Getenv("GREETING"))
	switch string(in) {
	case "\"sleep\"":
		time.Sleep(10 * time.Second)
	case "\"fail\"":
		fmt.Print("{\"errorMessage\":\"boom\",\"errorType\":\"Oops\"}")
		os.Exit(3)
	case "\"crash\"":
		os.Exit(2)
	case "\"alloc\"":
		b := make([]byte, 256<<20)
		b[len(b)-1] = 1
		fmt.Print(len(b))
	}
	fmt.Printf("{\"got\":%s}\n", in)
}
`

func TestRuntimeRun(t *testing.T) {
	zipped := buildWasm(t, echoProgram)
	rt, err := NewRuntime(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	load := func() (io.ReaderAt, int64, error) { return bytes.NewReader(zipped), int64(len(zipped)), nil }
	ctx := context.Background()
	run := func(event string, timeout time.Duration, mem int) *Outcome {
		t.Helper()
		out, err := rt.Run(ctx, "code1", load, Execution{MemoryMB: mem, Timeout: timeout, Env: map[string]string{"GREETING": "tests"}, Event: []byte(event)})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	tests := []struct {
		name, event string
		timeout     time.Duration
		mem         int
		check       func(*Outcome) string
	}{
		{"echo", `{"a":1}`, 10 * time.Second, 128, func(o *Outcome) string {
			if o.ExitCode != 0 || strings.TrimSpace(string(o.Payload)) != `{"got":{"a":1}}` {
				return "payload " + string(o.Payload)
			}
			if !strings.Contains(string(o.Log), "log line for tests") {
				return "log " + string(o.Log)
			}
			return ""
		}},
		{"timeout", `"sleep"`, 500 * time.Millisecond, 128, func(o *Outcome) string {
			if !o.TimedOut {
				return "not timed out"
			}
			return ""
		}},
		{"reported error", `"fail"`, 10 * time.Second, 128, func(o *Outcome) string {
			if o.ExitCode != 3 || !strings.Contains(string(o.Payload), "boom") {
				return "outcome " + string(o.Payload)
			}
			return ""
		}},
		{"crash", `"crash"`, 10 * time.Second, 128, func(o *Outcome) string {
			if o.ExitCode != 2 {
				return "exit code"
			}
			return ""
		}},
		{"memory limit", `"alloc"`, 10 * time.Second, 128, func(o *Outcome) string {
			if o.ExitCode == 0 {
				return "allocated past MemorySize: " + string(o.Payload)
			}
			return ""
		}},
		{"memory fits", `"alloc"`, 10 * time.Second, 1024, func(o *Outcome) string {
			if o.ExitCode != 0 {
				return "failed: " + string(o.Log)
			}
			return ""
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if msg := tc.check(run(tc.event, tc.timeout, tc.mem)); msg != "" {
				t.Error(msg)
			}
		})
	}
}

func TestBootstrapMissing(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("lambda_function.py")
	_, _ = w.Write([]byte("def handler(e, c): return e"))
	_ = zw.Close()
	if _, err := bootstrapFromZip(bytes.NewReader(buf.Bytes()), int64(buf.Len())); err != ErrNoBootstrap {
		t.Fatalf("got %v, want ErrNoBootstrap", err)
	}
	if _, err := bootstrapFromZip(bytes.NewReader([]byte("not a zip")), 9); err == nil {
		t.Fatal("expected an error for a non-zip")
	}
}
