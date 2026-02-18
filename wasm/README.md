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
