# passcheck WebAssembly

This directory contains the WebAssembly build of passcheck for client-side password strength checking in the browser.

## Modern TypeScript/Vite Web App

See [web/README.md](web/README.md) for the full-featured web application with:

- Dark mode interface with real-time feedback
- TypeScript type-safe client code
- Web Workers for non-blocking password checks
- Configurable rules with preset support
- Optional HIBP breach database checks

## Building

```bash
# From the project root:
make wasm          # build WASM binary and copy to wasm/web/public/
make serve-wasm    # start the Vite dev server
```

The WASM binary is output to `bin/passcheck.wasm` and automatically copied to `wasm/web/public/` for the web app.

## How It Works

The Go code is compiled to WebAssembly using `GOOS=js GOARCH=wasm`. A JavaScript wrapper (`wasm_exec.js`) bootstraps the Go runtime in the browser. The password is checked entirely client-side — it is never sent to a server.

For HIBP breach checks, the browser makes a direct k-anonymity request (only a 5-character SHA-1 hash prefix is sent). CORS restrictions may apply in some environments.

## Bundle Sizes

Approximate sizes (may vary by Go version and build flags):

| Format   | Size      |
| -------- | --------- |
| Raw      | ~3.0 MB   |
| gzip -9  | ~1.1 MB   |

Use `make wasm` to build locally and see exact sizes. The CI [WASM workflow](../.github/workflows/wasm.yml) reports current sizes on every push to `main`.

For mobile or bandwidth-constrained users, serve the binary with gzip/Brotli compression from your CDN — most modern browsers support `Content-Encoding: br` (Brotli), reducing the transfer to ~950 KB.

## Lazy-Loading Guide

Loading the full WASM binary on page load blocks the main thread and delays
time-to-interactive. The recommended pattern is to initialise the runtime
inside a **Web Worker** and load the binary only when the user first interacts
with a password field.

### How the built-in worker works

[`wasm/web/src/worker/worker.ts`](web/src/worker/worker.ts) implements this
pattern already:

1. The worker imports `wasm_exec.js` once via `importScripts`.
2. `initWasm(wasmUrl)` fetches and instantiates the binary the first time a
   `CHECK` or `CHECK_INCREMENTAL` message arrives — not at script load time.
3. Once loaded, subsequent checks run synchronously inside the worker (no
   re-init penalty).
4. The main thread never blocks: it sends a message and awaits a `postMessage`
   reply.

### Minimal TypeScript snippet

If you are building a custom integration rather than using the full Vite app,
here is the minimal pattern to replicate:

```typescript
// password-worker.ts  (runs inside a Web Worker)
/// <reference lib="webworker" />
importScripts('/wasm_exec.js');

declare var Go: any;
declare var passcheckCheck: (pw: string) => string;

const go = new Go();
let ready = false;

async function load() {
  if (ready) return;
  const result = await WebAssembly.instantiateStreaming(
    fetch('/passcheck.wasm'),
    go.importObject,
  );
  go.run(result.instance);
  ready = true;
}

self.onmessage = async (e: MessageEvent) => {
  const { id, password } = e.data;
  await load(); // no-op after the first call
  const json = passcheckCheck(password);
  self.postMessage({ id, result: JSON.parse(json) });
};
```

```typescript
// main.ts  (runs on the main thread)
const worker = new Worker(new URL('./password-worker.ts', import.meta.url), {
  type: 'module',
});

let nextId = 0;
const pending = new Map<number, (r: unknown) => void>();

worker.onmessage = (e) => {
  const { id, result } = e.data;
  pending.get(id)?.(result);
  pending.delete(id);
};

export function checkPassword(password: string): Promise<unknown> {
  return new Promise((resolve) => {
    const id = nextId++;
    pending.set(id, resolve);
    worker.postMessage({ id, password });
  });
}
```

Key points:
- **No main-thread block**: the Go runtime initialises entirely inside the worker.
- **Lazy fetch**: the ~3 MB binary is only downloaded when `checkPassword` is
  first called — not on page load.
- **Incremental checks**: replace `passcheckCheck` with
  `passcheckCheckIncremental` and thread the previous result JSON through the
  message channel for live strength meters.
- **Bundle budget**: serve `passcheck.wasm` compressed (gzip ≈ 1.1 MB, Brotli ≈
  950 KB). Cache aggressively — the binary changes only when the Go library
  version changes.
