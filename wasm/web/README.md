# PassCheck Web (WASM)

A modern, secure, and privacy-focused password strength checker powered by WebAssembly and Go.

## Features

- **Local Processing**: All password checks happen in your browser via WebAssembly. No passwords are sent to a server (except for hashed prefixes for HIBP checks).
- **Advanced Rules**: Configurable requirements for length, complexity, patterns, and dictionaries.
- **HIBP Integration**: Securely checks against the Have I Been Pwned database using k-Anonymity (only the first 5 characters of the SHA-1 hash are sent).
- **Presets**: Built-in compliance templates for NIST, PCI-DSS, OWASP, and more.
- **Premium UI**: Dark mode interface with real-time feedback and dynamic requirements.

## Installation

1. Navigate to the project directory:
   ```bash
   cd wasm/web
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

## Development

Start the development server:

```bash
npm run dev
```

Open your browser at the URL shown in the terminal (usually `http://localhost:5173`).

## Build

Build for production:

```bash
npm run build
```

The output will be in the `dist` directory.

## Usage

The application centers around the `PassCheckClient` which communicates with a Web Worker running the Go WASM module.

- **Configuration**: Use the UI panel to toggle rules or choose a preset.
- **Feedback**: The strength meter and issue list update in real-time as you type.

### Project Structure

- `src/client.ts`: TypeScript wrapper for the WASM worker.
- `src/worker/worker.ts`: Web Worker that loads and interacts with the WASM module.
- `src/components/`: UI components (ConfigPanel, PasswordInput, etc.).
- `public/`: Static assets including `passcheck.wasm` and `wasm_exec.js`.
