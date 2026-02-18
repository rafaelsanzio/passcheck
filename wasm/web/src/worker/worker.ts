/// <reference lib="webworker" />

declare var self: DedicatedWorkerGlobalScope;

// Types from the Go implementation
declare global {
  var Go: any;
  // Go functions exposed to JS
  var passcheckCheck: (password: string) => string;
  var passcheckCheckWithConfig: (password: string, config: string) => string;
  var passcheckCheckIncremental: (password: string, previousResultJSON: string) => string;
  var passcheckCheckIncrementalWithConfig: (password: string, previousResultJSON: string, config: string) => string;
}

// Load the Go WASM runtime
// This assumes /wasm_exec.js is available at the root (public folder)
importScripts('/wasm_exec.js');

const go = new Go();
let inst: WebAssembly.Instance;
let loaded = false;

async function initWasm(wasmUrl: string) {
  if (loaded) return;

  try {
    if ('instantiateStreaming' in WebAssembly) {
      const result = await WebAssembly.instantiateStreaming(
        fetch(wasmUrl),
        go.importObject
      );
      inst = result.instance;
    } else {
      const resp = await fetch(wasmUrl);
      const bytes = await resp.arrayBuffer();
      const result = await WebAssembly.instantiate(bytes, go.importObject);
      inst = result.instance;
    }

    go.run(inst);
    loaded = true;
    console.log('[PassCheck Worker] WASM loaded');
  } catch (err) {
    console.error('[PassCheck Worker] Failed to load WASM:', err);
    throw err;
  }
}

async function checkHibp(password: string) {
  if (!password) return { breached: false, count: 0 };

  // Create SHA-1 hash
  const msgBuffer = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-1', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  // Hex string (uppercase)
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();

  const prefix = hashHex.substring(0, 5);
  const suffix = hashHex.substring(5);

  try {
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    if (!response.ok) throw new Error('HIBP API error');

    const text = await response.text();
    const lines = text.split('\n');

    for (const line of lines) {
      // line is SUFFIX:COUNT
      const parts = line.split(':');
      if (parts.length >= 2) {
        const lineSuffix = parts[0].trim().toUpperCase();
        if (lineSuffix === suffix) {
          return { breached: true, count: parseInt(parts[1], 10) };
        }
      }
    }
  } catch (err) {
    console.warn('HIBP check failed:', err);
  }

  return { breached: false, count: 0 };
}

self.onmessage = async (e) => {
  const { id, type, payload } = e.data;

  try {
    switch (type) {
      case 'INIT':
        await initWasm(payload.wasmUrl || '/passcheck.wasm');
        self.postMessage({ id, type: 'INIT_SUCCESS' });
        break;

      case 'CHECK': {
        if (!loaded) throw new Error('WASM not loaded');
        // Legacy CHECK is disabled in favor of CHECK_INCREMENTAL
        throw new Error("Use CHECK_INCREMENTAL");
      }

      case 'CHECK_INCREMENTAL': {
        if (!loaded) throw new Error('WASM not loaded');
        const { password, config, previousResult } = payload;

        // Restore HIBP Check (if enabled)
        if (config && config.useHibp) {
          try {
            const hibpRes = await checkHibp(password);
            config.hibpResult = hibpRes;
          } catch (e) {
            console.warn('HIBP check failed:', e);
          }
        }

        // Go function expects: password, previousResultJSON, configJSON
        const prevJson = previousResult ? JSON.stringify(previousResult) : "null";
        const configJson = config ? JSON.stringify(config) : "null";

        // Call WASM
        // @ts-ignore - injected by WASM
        const resultJson = self.passcheckCheckIncrementalWithConfig(password, prevJson, configJson);
        const result = JSON.parse(resultJson);

        if (result.error) throw new Error(result.error);

        // result structure from Go: { result: Result, delta: IncrementalDelta }
        // We inject HIBP count into the Result part
        const hibpCount = config && config.hibpResult ? config.hibpResult.count : 0;
        const resWithHibp = { ...result.result, hibpCount };

        self.postMessage({ id, type: 'check_result', payload: { result: resWithHibp, delta: result.delta } });
        break;
      }

      default:
        console.warn('Unknown message type:', type);
    }
  } catch (err: any) {
    self.postMessage({ id, type: 'ERROR', error: err.message });
  }
};
