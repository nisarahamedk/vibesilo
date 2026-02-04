# vibesilo

> ⚠️ **VibeSlopped MVP**: This is a "workable" sandbox prototype for local experimentation.
> It is **not** a hardened security boundary. Use at your own risk.

A local sandbox for LLM agents: run arbitrary CLIs in Docker with outbound allow‑lists and on‑wire secret injection (MITM), so secrets never live in the container and agents can’t exfiltrate them.

## Architecture

- **Sandbox container** runs arbitrary CLIs with **placeholder secrets** only.
- **Sidecar MITM proxy** (mitmproxy) intercepts HTTPS, enforces `allowNet`, and swaps placeholders with real secrets.
- **Docker internal network** prevents the sandbox from reaching the Internet directly.

```
Host (SDK/CLI)
  ├─ Sandbox container (placeholders only)
  └─ Mitmproxy sidecar (real secrets + allowNet)
```

## Requirements

- Docker Desktop (Mac)
- Node.js 18+

## Quick start

```bash
npm install
npm run build

node dist/cli.js run \
  --image curlimages/curl:8.6.0 \
  --allow example.com \
  -- curl -s https://example.com
```

## CLI usage

```bash
vibesilo run \
  --image node:20-bookworm \
  --allow api.github.com \
  --secret GH_TOKEN=ghp_xxx@api.github.com \
  -- gh repo list
```

## SDK usage

```ts
import { Sandbox } from "vibesilo";

const sandbox = await Sandbox.create({
  image: "node:20-bookworm",
  allowNet: ["api.github.com"],
  secrets: {
    GH_TOKEN: {
      hosts: ["api.github.com"],
      value: process.env.GH_TOKEN!,
    },
  },
});

const result = await sandbox.exec("gh repo list");
console.log(result.stdout);
await sandbox.close();
```

## Notes

- `debugInjectHeader` adds a response header to prove injection during tests.
  Leave it off in normal runs.

- The sandbox only ever sees **placeholder** values. The proxy replaces them on the wire.
- MITM requires a custom CA. The CA is installed inside the sandbox container only.
- Some CLIs with **cert pinning** may break under MITM.

## Self-validate

```bash
npm run self-validate
```
