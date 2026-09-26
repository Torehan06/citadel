package lambda

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

// wasmRuntime runs WASI preview 1 command modules. Compiled modules are cached on
// disk (wazero's compilation cache under <data>/wasm-cache) and in memory,
// keyed by code hash and memory limit, under a size cap. Every invocation
// gets a fresh module instance.
type wasmRuntime struct {
	log      *slog.Logger
	cache    wazero.CompilationCache
	mu       sync.Mutex
	runtimes map[uint32]wazero.Runtime // one per memory limit (pages)
	modules  map[string]*compiled
	size     int64 // wasm bytes held by modules
}

type compiled struct {
	mod  wazero.CompiledModule
	size int64
	used time.Time
}

// maxCompiled caps the wasm bytes whose compiled forms stay in memory.
const maxCompiled = 64 << 20

func newRuntime(dataDir string, log *slog.Logger) *wasmRuntime {
	r := &wasmRuntime{log: log, runtimes: map[uint32]wazero.Runtime{}, modules: map[string]*compiled{}}
	if dataDir != "" {
		dir := filepath.Join(dataDir, "wasm-cache")
		if err := os.MkdirAll(dir, 0o755); err == nil {
			if c, err := wazero.NewCompilationCacheWithDir(dir); err == nil {
				r.cache = c
			} else {
				log.Warn("wasm compilation cache disabled", "err", err)
			}
		}
	}
	if r.cache == nil {
		r.cache = wazero.NewCompilationCache()
	}
	return r
}

func (r *wasmRuntime) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rt := range r.runtimes {
		_ = rt.Close(context.Background())
	}
	r.runtimes = map[uint32]wazero.Runtime{}
	r.modules = map[string]*compiled{}
	_ = r.cache.Close(context.Background())
}

// runtimeFor returns the wazero runtime enforcing a memory limit. WASI is
// instantiated in it once.
func (r *wasmRuntime) runtimeFor(ctx context.Context, pages uint32) (wazero.Runtime, error) {
	if rt := r.runtimes[pages]; rt != nil {
		return rt, nil
	}
	cfg := wazero.NewRuntimeConfig().
		WithCompilationCache(r.cache).
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(pages)
	rt := wazero.NewRuntimeWithConfig(ctx, cfg)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		_ = rt.Close(ctx)
		return nil, err
	}
	r.runtimes[pages] = rt
	return rt, nil
}

// compile returns the compiled module for code, compiling it on a miss. It
// reports whether it compiled (a cold start).
func (r *wasmRuntime) compile(ctx context.Context, codeKey string, pages uint32, wasm func() ([]byte, error)) (wazero.Runtime, wazero.CompiledModule, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rt, err := r.runtimeFor(ctx, pages)
	if err != nil {
		return nil, nil, false, err
	}
	key := fmt.Sprintf("%d/%s", pages, codeKey)
	if c := r.modules[key]; c != nil {
		c.used = time.Now()
		return rt, c.mod, false, nil
	}
	bin, err := wasm()
	if err != nil {
		return nil, nil, false, err
	}
	mod, err := rt.CompileModule(ctx, bin)
	if err != nil {
		return nil, nil, false, &invalidModule{err}
	}
	r.modules[key] = &compiled{mod: mod, size: int64(len(bin)), used: time.Now()}
	r.size += int64(len(bin))
	r.evict()
	return rt, mod, true, nil
}

// evict drops least recently used modules until the cache is under its cap.
// Closing a compiled module is safe while instances made from it still run.
func (r *wasmRuntime) evict() {
	for r.size > maxCompiled && len(r.modules) > 1 {
		var oldest string
		for k, c := range r.modules {
			if oldest == "" || c.used.Before(r.modules[oldest].used) {
				oldest = k
			}
		}
		c := r.modules[oldest]
		_ = c.mod.Close(context.Background())
		r.size -= c.size
		delete(r.modules, oldest)
	}
}

type invalidModule struct{ err error }

func (e *invalidModule) Error() string { return "invalid WebAssembly module: " + e.err.Error() }

// runSpec is one invocation of a module.
type runSpec struct {
	codeKey string
	wasm    func() ([]byte, error)
	task    fs.FS // the deployment package, mounted read-only at /var/task
	pages   uint32
	timeout time.Duration
	env     map[string]string
	stdin   []byte
	stdout  io.Writer
	stderr  io.Writer
}

// runOutcome says how the module ended.
type runOutcome struct {
	exitCode   uint32
	timedOut   bool
	trap       error // a trap or other runtime failure
	cold       bool
	initTime   time.Duration
	memoryUsed uint32 // bytes, when known
}

func (r *wasmRuntime) run(ctx context.Context, s runSpec) (runOutcome, error) {
	var out runOutcome
	start := time.Now()
	rt, mod, cold, err := r.compile(ctx, s.codeKey, s.pages, s.wasm)
	if err != nil {
		return out, err
	}
	out.cold = cold
	if cold {
		out.initTime = time.Since(start)
	}
	cfg := wazero.NewModuleConfig().
		WithName("").
		WithArgs("bootstrap").
		WithStdin(bytes.NewReader(s.stdin)).
		WithStdout(s.stdout).
		WithStderr(s.stderr).
		WithSysWalltime().
		WithSysNanotime().
		WithSysNanosleep().
		WithRandSource(rand.Reader)
	if s.task != nil {
		cfg = cfg.WithFSConfig(wazero.NewFSConfig().WithFSMount(s.task, "/var/task"))
	}
	for _, k := range sortedKeys(s.env) {
		cfg = cfg.WithEnv(k, s.env[k])
	}
	runCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	inst, err := rt.InstantiateModule(runCtx, mod, cfg)
	if inst != nil {
		if m := inst.Memory(); m != nil {
			out.memoryUsed = m.Size()
		}
		_ = inst.Close(context.Background())
	}
	if err == nil {
		return out, nil
	}
	var exit *sys.ExitError
	if errors.As(err, &exit) {
		switch exit.ExitCode() {
		case sys.ExitCodeDeadlineExceeded:
			out.timedOut = true
			return out, nil
		case sys.ExitCodeContextCanceled:
			if runCtx.Err() == context.DeadlineExceeded {
				out.timedOut = true
				return out, nil
			}
			return out, ctx.Err()
		}
		out.exitCode = exit.ExitCode()
		return out, nil
	}
	if runCtx.Err() == context.DeadlineExceeded {
		out.timedOut = true
		return out, nil
	}
	out.trap = err
	return out, nil
}

// memoryPages converts MemorySize (MB) to 64 KiB wasm pages, capped at the
// 4 GiB a 32-bit module can address.
func memoryPages(mb int) uint32 {
	pages := uint64(mb) * 16
	if pages > 65536 {
		pages = 65536
	}
	return uint32(pages)
}
