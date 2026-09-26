package lambda

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

// The WebAssembly runtime (ARCHITECTURE.md §9). A function's zip holds
// bootstrap.wasm, a WASI preview 1 command module. Each invocation gets a
// fresh instance: the event arrives on stdin, the response is read from
// stdout, and stderr becomes the function's log. Timeout is enforced by
// closing the module when its context ends; MemorySize caps linear memory.

const (
	bootstrapName   = "bootstrap.wasm"
	maxWasmSize     = 250 << 20 // AWS's unzipped deployment package limit
	maxResponseSize = 6 << 20   // synchronous invocation payload limit
	maxLogCapture   = 256 << 10 // per invocation, as a CloudWatch event would be
	moduleCacheSize = 16        // compiled modules kept in memory
)

// ErrNoBootstrap means the package has no bootstrap.wasm to run.
var ErrNoBootstrap = errors.New("no " + bootstrapName + " in the deployment package")

// Runtime compiles and runs function modules. It keeps one wazero runtime per
// memory size (the page limit is a runtime setting), a shared on-disk
// compilation cache, and a small in-memory cache of compiled modules.
type Runtime struct {
	cache wazero.CompilationCache

	mu       sync.Mutex
	runtimes map[int]wazero.Runtime // MemorySize (MB) -> runtime
	modules  map[moduleKey]*compiled
	tick     int64
}

type moduleKey struct {
	memory int
	code   string // blob address of the zip
}

type compiled struct {
	mod  wazero.CompiledModule
	used int64
	err  error
	done chan struct{} // closed when compilation finished
}

// NewRuntime keeps compiled code under cacheDir (empty: memory only).
func NewRuntime(cacheDir string) (*Runtime, error) {
	rt := &Runtime{runtimes: map[int]wazero.Runtime{}, modules: map[moduleKey]*compiled{}}
	if cacheDir != "" {
		if err := os.MkdirAll(cacheDir, 0o755); err != nil {
			return nil, err
		}
		c, err := wazero.NewCompilationCacheWithDir(cacheDir)
		if err != nil {
			return nil, err
		}
		rt.cache = c
	}
	return rt, nil
}

// Close releases every runtime and compiled module.
func (rt *Runtime) Close() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	ctx := context.Background()
	for _, r := range rt.runtimes {
		_ = r.Close(ctx)
	}
	rt.runtimes = map[int]wazero.Runtime{}
	rt.modules = map[moduleKey]*compiled{}
	if rt.cache != nil {
		_ = rt.cache.Close(ctx)
	}
}

func (rt *Runtime) runtimeFor(ctx context.Context, memoryMB int) (wazero.Runtime, error) {
	if r, ok := rt.runtimes[memoryMB]; ok {
		return r, nil
	}
	cfg := wazero.NewRuntimeConfig().
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(uint32(memoryMB) * 16) // 64 KiB pages
	if rt.cache != nil {
		cfg = cfg.WithCompilationCache(rt.cache)
	}
	r := wazero.NewRuntimeWithConfig(ctx, cfg)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, r); err != nil {
		_ = r.Close(ctx)
		return nil, err
	}
	rt.runtimes[memoryMB] = r
	return r, nil
}

// module returns the compiled bootstrap.wasm for a package, compiling it
// once. load opens the zip only when it is not cached.
func (rt *Runtime) module(ctx context.Context, memoryMB int, code string, load func() (io.ReaderAt, int64, error)) (wazero.Runtime, wazero.CompiledModule, error) {
	key := moduleKey{memoryMB, code}
	rt.mu.Lock()
	r, err := rt.runtimeFor(ctx, memoryMB)
	if err != nil {
		rt.mu.Unlock()
		return nil, nil, err
	}
	rt.tick++
	c, ok := rt.modules[key]
	if ok {
		c.used = rt.tick
		rt.mu.Unlock()
		<-c.done
		return r, c.mod, c.err
	}
	c = &compiled{used: rt.tick, done: make(chan struct{})}
	rt.modules[key] = c
	rt.evictLocked(ctx)
	rt.mu.Unlock()

	c.mod, c.err = compile(ctx, r, load)
	close(c.done)
	if c.err != nil {
		rt.mu.Lock()
		if rt.modules[key] == c {
			delete(rt.modules, key) // let a fixed package (same address never changes, but a transient error) retry
		}
		rt.mu.Unlock()
	}
	return r, c.mod, c.err
}

// evictLocked drops the least recently used modules beyond the cache size.
// A module still running keeps working: closing a CompiledModule only frees
// it for new instances.
func (rt *Runtime) evictLocked(ctx context.Context) {
	if len(rt.modules) <= moduleCacheSize {
		return
	}
	keys := make([]moduleKey, 0, len(rt.modules))
	for k := range rt.modules {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return rt.modules[keys[i]].used < rt.modules[keys[j]].used })
	for _, k := range keys[:len(keys)-moduleCacheSize] {
		c := rt.modules[k]
		select {
		case <-c.done:
			if c.mod != nil {
				_ = c.mod.Close(ctx)
			}
			delete(rt.modules, k)
		default: // still compiling
		}
	}
}

func compile(ctx context.Context, r wazero.Runtime, load func() (io.ReaderAt, int64, error)) (wazero.CompiledModule, error) {
	ra, size, err := load()
	if err != nil {
		return nil, err
	}
	if c, ok := ra.(io.Closer); ok {
		defer c.Close()
	}
	wasm, err := bootstrapFromZip(ra, size)
	if err != nil {
		return nil, err
	}
	return r.CompileModule(ctx, wasm)
}

// bootstrapFromZip extracts bootstrap.wasm from a deployment package.
func bootstrapFromZip(ra io.ReaderAt, size int64) ([]byte, error) {
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return nil, fmt.Errorf("could not unzip the deployment package: %w", err)
	}
	for _, f := range zr.File {
		if f.Name != bootstrapName {
			continue
		}
		if f.UncompressedSize64 > maxWasmSize {
			return nil, fmt.Errorf("%s is larger than %d bytes", bootstrapName, maxWasmSize)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(io.LimitReader(rc, maxWasmSize))
	}
	return nil, ErrNoBootstrap
}

// Execution is one run of a function module.
type Execution struct {
	MemoryMB int
	Timeout  time.Duration
	Env      map[string]string
	Event    []byte
}

// Outcome is what a run produced.
type Outcome struct {
	Payload   []byte // stdout, at most maxResponseSize bytes
	Overflow  bool   // stdout exceeded maxResponseSize
	Log       []byte // stderr, the first maxLogCapture bytes
	ExitCode  uint32
	TimedOut  bool
	Duration  time.Duration
	MaxMemory uint32 // bytes of linear memory at the end of the run
}

// Run instantiates the module once and runs it to completion (its _start).
// A non-nil error means the module could not be started at all (bad
// package, compile failure); everything the module itself does, including
// traps, non-zero exits and timeouts, is reported in the Outcome.
func (rt *Runtime) Run(ctx context.Context, code string, load func() (io.ReaderAt, int64, error), x Execution) (*Outcome, error) {
	r, mod, err := rt.module(ctx, x.MemoryMB, code, load)
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithTimeout(ctx, x.Timeout)
	defer cancel()
	stdout := &capped{max: maxResponseSize}
	stderr := &capped{max: maxLogCapture}
	cfg := wazero.NewModuleConfig().
		WithName(""). // anonymous: any number of concurrent instances
		WithArgs("bootstrap").
		WithStdin(bytes.NewReader(x.Event)).
		WithStdout(stdout).
		WithStderr(stderr).
		WithSysWalltime().
		WithSysNanotime().
		// A sleeping module is inside a host call, where closing on context
		// done cannot reach it: wake it so the timeout can end the run.
		WithNanosleep(func(ns int64) {
			t := time.NewTimer(time.Duration(ns))
			defer t.Stop()
			select {
			case <-t.C:
			case <-runCtx.Done():
			}
		}).
		WithRandSource(rand.Reader)
	keys := make([]string, 0, len(x.Env))
	for k := range x.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		cfg = cfg.WithEnv(k, x.Env[k])
	}
	start := time.Now()
	inst, err := r.InstantiateModule(runCtx, mod, cfg)
	out := &Outcome{Duration: time.Since(start), Payload: stdout.buf.Bytes(), Overflow: stdout.over, Log: stderr.buf.Bytes()}
	if inst != nil {
		if m := inst.Memory(); m != nil {
			out.MaxMemory = m.Size()
		}
		_ = inst.Close(ctx)
	}
	if err != nil {
		var exit *sys.ExitError
		if !errors.As(err, &exit) {
			// A trap (unreachable, out-of-bounds access, stack overflow).
			out.ExitCode = 1
			out.Log = append(out.Log, []byte("\n"+err.Error()+"\n")...)
			return out, nil
		}
		out.ExitCode = exit.ExitCode()
		if out.ExitCode == sys.ExitCodeDeadlineExceeded || runCtx.Err() == context.DeadlineExceeded {
			out.TimedOut = true
		}
	}
	return out, nil
}

// capped keeps the first max bytes written and remembers whether more came.
type capped struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room < len(p) {
		c.over = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}

// Prepare compiles a package ahead of its first invocation, so a new or
// updated function does not pay for compilation on its first request.
func (rt *Runtime) Prepare(ctx context.Context, memoryMB int, code string, load func() (io.ReaderAt, int64, error)) {
	_, _, _ = rt.module(ctx, memoryMB, code, load)
}
