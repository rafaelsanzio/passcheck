
export interface PenaltyWeights {
    ruleViolation?: number;
    patternMatch?: number;
    dictionaryMatch?: number;
    contextMatch?: number;
    hibpBreach?: number;
    entropyWeight?: number;
}

export interface PassCheckConfig {
    preset?: 'nist' | 'pci' | 'owasp' | 'enterprise' | 'userfriendly';
    minLength?: number;
    requireUpper?: boolean;
    requireLower?: boolean;
    requireDigit?: boolean;
    requireSymbol?: boolean;
    maxRepeats?: number;
    patternMinLength?: number;
    maxIssues?: number;
    customPasswords?: string[];
    customWords?: string[];
    contextWords?: string[];
    disableLeet?: boolean;
    useHibp?: boolean;
    hibpResult?: { breached: boolean; count: number };
    passphraseMode?: boolean;
    minWords?: number;
    wordDictSize?: number;
    entropyMode?: 'simple' | 'advanced' | 'pattern-aware';
    penaltyWeights?: PenaltyWeights;
}

export interface Issue {
    code: string;
    message: string;
    category: string;
    severity: number;
}

export interface PassCheckResult {
    score: number;
    verdict: string;
    issues: Issue[];
    suggestions: string[];
    entropy: number;
    hibpCount?: number;
}

class PassCheckClient {
    private worker: Worker;
    private messageMap: Map<number, { resolve: (val: any) => void; reject: (err: any) => void }>;
    private msgIdCounter: number;
    private readyPromise: Promise<void>;

    constructor(wasmUrl: string = '/passcheck.wasm') {
        // Initialize the worker. Note the { type: 'classic' } to support importScripts within the worker
        this.worker = new Worker(new URL('./worker/worker.ts', import.meta.url), {
            type: 'classic',
        });
        this.messageMap = new Map();
        this.msgIdCounter = 0;

        this.worker.onmessage = (e) => {
            const { id, type, payload, error } = e.data;
            const handler = this.messageMap.get(id);
            if (handler) {
                if (type === 'ERROR') {
                    handler.reject(new Error(error));
                } else {
                    handler.resolve(payload);
                }
                this.messageMap.delete(id);
            }
        };

        this.readyPromise = this.send('INIT', { wasmUrl }) as Promise<void>;
    }

    private send(type: string, payload: any): Promise<any> {
        const id = ++this.msgIdCounter;
        return new Promise((resolve, reject) => {
            this.messageMap.set(id, { resolve, reject });
            this.worker.postMessage({ id, type, payload });
        });
    }

    async ready(): Promise<void> {
        return this.readyPromise;
    }

    async check(password: string, config?: PassCheckConfig): Promise<PassCheckResult> {
        await this.ready();

        // We'll maintain the previous result in the main app or here?
        // Ideally here to abstract it? 
        // But the check method signature implies a stateless check if we just return Result.
        // Let's change the signature or just handle it internally if I store state?
        // Storing state in the client class for the "last check" seems appropriate for a single-user client.

        // Actually, to correctly implement incremental, we need to pass the *previous* result to the worker.
        // The worker is stateless regarding the Go WASM side (Go doesn't persist state between calls unless we do).
        // Since `passcheckCheckIncremental` takes `previousResultJSON`, we need to hold it.

        const response = await this.send('CHECK_INCREMENTAL', {
            password,
            config,
            previousResult: this.lastResult
        });

        this.lastResult = response.result;
        return response.result;
    }

    private lastResult: PassCheckResult | null = null;
}

export const passCheck = new PassCheckClient();
